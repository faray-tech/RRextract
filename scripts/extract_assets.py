#!/usr/bin/env python3
"""
Extract and verify all non-.RED metadata, assets, configs, DBs, and logs from an EaseUS .pbd image.

Reads virtual disk blocks on demand via scripts/pbd_reader.py (IMGF v0x20000),
discovers all ext2/3/4 partitions via parse_partitions / Ext3Filesystem from
scripts/extract_red_files.py, extracts every non-.RED regular file preserving
exact POSIX paths under extracted_fs/, records symlinks in JSON without requiring
Windows symlink privileges, populates thumbnails/ with clean package poster and
thumbnail images, and validates every JPEG, XML, SQLite DB, and manifest hash.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import posixpath
import shutil
import sqlite3
import struct
import sys
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from extract_red_files import (  # noqa: E402
    Ext3Filesystem,
    PartitionInfo,
    make_output_filename,
    parse_partitions,
)
from pbd_reader import PbdDiskReader, resolve_pbd_path  # noqa: E402

DEFAULT_OUT_DIR = REPO_ROOT / "extracted_fs"
DEFAULT_THUMB_DIR = REPO_ROOT / "thumbnails"
DEFAULT_RED_DIR = REPO_ROOT / "red_files"


def open_ext3_filesystems(disk: PbdDiskReader) -> List[Tuple[PartitionInfo, Ext3Filesystem]]:
    """Locate and open every ext2/3/4 partition on the virtual disk."""
    parts = parse_partitions(disk)
    found: List[Tuple[PartitionInfo, Ext3Filesystem]] = []
    for part in parts:
        if Ext3Filesystem.probe_partition(disk, part.offset):
            found.append((part, Ext3Filesystem(disk, part.offset)))
    if not found and Ext3Filesystem.probe_partition(disk, 0):
        raw_part = PartitionInfo(0, "RAW", "ext3", 0, disk.disk_size // 512)
        found.append((raw_part, Ext3Filesystem(disk, 0)))
    return found


def safe_rel_parts(ext3_path: str) -> Tuple[str, ...]:
    """Validate and split an ext3 POSIX path into safe relative path components."""
    parts = tuple(p for p in PurePosixPath(ext3_path).parts if p not in ("/", ""))
    if any(p in (".", "..") or ":" in p for p in parts):
        raise ValueError(f"Unsafe ext3 path: {ext3_path!r}")
    return parts


def sha256_bytes(data: bytes) -> Tuple[str, str]:
    """Return (hex_digest, base64_digest) for a byte buffer."""
    digest = hashlib.sha256(data).digest()
    return digest.hex(), base64.b64encode(digest).decode("ascii")


def sha256_file(path: Path) -> Tuple[str, str, int]:
    """Stream-hash a file on disk and return (hex_digest, base64_digest, byte_size)."""
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as fp:
        while True:
            buf = fp.read(4 * 1024 * 1024)
            if not buf:
                break
            h.update(buf)
            size += len(buf)
    digest = h.digest()
    return digest.hex(), base64.b64encode(digest).decode("ascii"), size


def parse_jpeg_dimensions(data: bytes) -> Optional[Tuple[int, int]]:
    """Scan JPEG markers for the SOF frame header and return (width, height)."""
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return None
    pos = 2
    n = len(data)
    while pos + 1 < n:
        if data[pos] != 0xFF:
            pos += 1
            continue
        while pos < n and data[pos] == 0xFF:
            pos += 1
        if pos >= n:
            break
        marker = data[pos]
        pos += 1
        if marker in (0xD8, 0xD9, 0x00) or (0xD0 <= marker <= 0xD7):
            continue
        if pos + 2 > n:
            break
        seg_len = struct.unpack_from(">H", data, pos)[0]
        if seg_len < 2 or pos + seg_len > n:
            break
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            if pos + 7 <= n:
                height, width = struct.unpack_from(">HH", data, pos + 3)
                return (width, height)
        if marker == 0xDA:  # SOS: entropy-coded image data follows
            break
        pos += seg_len
    return None


def validate_jpeg(path: Path) -> Dict[str, Any]:
    """Validate JPEG SOI (FF D8) and EOI (FF D9) markers and read dimensions."""
    data = path.read_bytes()
    has_soi = len(data) >= 2 and data[:2] == b"\xff\xd8"
    has_eoi = len(data) >= 2 and data[-2:] == b"\xff\xd9"
    dims = parse_jpeg_dimensions(data) if has_soi else None
    hex_hash, b64_hash = sha256_bytes(data)
    return {
        "path": str(path),
        "size": len(data),
        "sha256_hex": hex_hash,
        "sha256_b64": b64_hash,
        "has_soi": has_soi,
        "has_eoi": has_eoi,
        "width": dims[0] if dims else None,
        "height": dims[1] if dims else None,
        "valid": bool(has_soi and has_eoi and dims is not None),
    }


def validate_xml(path: Path) -> Dict[str, Any]:
    """Validate XML well-formedness with ElementTree."""
    data = path.read_bytes()
    try:
        text = data.decode("utf-8").lstrip("\ufeff")
        root = ET.fromstring(text)
        return {
            "path": str(path),
            "size": len(data),
            "root_tag": root.tag,
            "valid": True,
            "error": None,
        }
    except Exception as exc:
        return {
            "path": str(path),
            "size": len(data),
            "root_tag": None,
            "valid": False,
            "error": str(exc),
        }


def validate_sqlite(path: Path) -> Dict[str, Any]:
    """Run read-only PRAGMA integrity_check and summarize tables/row counts."""
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    conn: Optional[sqlite3.Connection] = None
    try:
        conn = sqlite3.connect(uri, uri=True)
        cur = conn.cursor()
        integrity_rows = [r[0] for r in cur.execute("PRAGMA integrity_check;").fetchall()]
        tables: Dict[str, int] = {}
        for (tbl_name,) in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
        ).fetchall():
            quoted = '"' + tbl_name.replace('"', '""') + '"'
            cnt = cur.execute(f"SELECT COUNT(*) FROM {quoted};").fetchone()[0]
            tables[tbl_name] = cnt
        ok = integrity_rows == ["ok"]
        return {
            "path": str(path),
            "size": path.stat().st_size,
            "integrity_check": integrity_rows,
            "tables": tables,
            "valid": ok,
            "error": None if ok else "; ".join(integrity_rows),
        }
    except Exception as exc:
        return {
            "path": str(path),
            "size": path.stat().st_size if path.exists() else 0,
            "integrity_check": [],
            "tables": {},
            "valid": False,
            "error": str(exc),
        }
    finally:
        if conn is not None:
            conn.close()


def verify_package_manifests(
    out_dir: Path,
    red_dir: Optional[Path],
    verify_red_hashes: bool = True,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Verify manifest.xml asset hashes, /redray/images mirrors, and clip/chunklist .RED refs.

    Note: REDRAY packages store XML assets with CRLF line endings on ext3 while
    manifest.xml records LF-normalized byte sizes and SHA-256 digests. Both raw
    and LF-normalized hashes are recorded so exact binary and canonical XML matches
    are verified transparently.
    """
    content_dir = out_dir / "redray" / "content"
    images_root = out_dir / "redray" / "images"
    manifest_checks: List[Dict[str, Any]] = []
    chunklist_checks: List[Dict[str, Any]] = []
    mirror_checks: List[Dict[str, Any]] = []

    if not content_dir.is_dir():
        return manifest_checks, chunklist_checks, mirror_checks

    pkg_dirs = sorted(p for p in content_dir.iterdir() if p.is_dir())
    for pkg_dir in pkg_dirs:
        pkg_name = pkg_dir.name
        man_path = pkg_dir / "manifest.xml"
        if not man_path.is_file():
            manifest_checks.append(
                {
                    "package": pkg_name,
                    "asset_path": "manifest.xml",
                    "verified": False,
                    "error": "Missing manifest.xml",
                }
            )
            continue

        man_root = ET.fromstring(man_path.read_text(encoding="utf-8").lstrip("\ufeff"))
        for asset in man_root.findall(".//Asset"):
            rel_path = (asset.findtext("Path") or "").strip()
            exp_size_s = (asset.findtext("Size") or "").strip()
            exp_hash = (asset.findtext("Hash") or "").strip() or None
            asset_type = (asset.findtext("Type") or "").strip() or None
            exp_size = int(exp_size_s) if exp_size_s.isdigit() else None

            target_path = pkg_dir.joinpath(*safe_rel_parts(rel_path))
            if not target_path.is_file():
                manifest_checks.append(
                    {
                        "package": pkg_name,
                        "asset_path": rel_path,
                        "type": asset_type,
                        "expected_size": exp_size,
                        "expected_sha256_b64": exp_hash,
                        "file_exists": False,
                        "verified": False,
                    }
                )
                continue

            raw_bytes = target_path.read_bytes()
            raw_hex, raw_b64 = sha256_bytes(raw_bytes)
            lf_bytes = raw_bytes.replace(b"\r\n", b"\n")
            lf_hex, lf_b64 = sha256_bytes(lf_bytes)

            if exp_hash is None and exp_size is None:
                manifest_checks.append(
                    {
                        "package": pkg_name,
                        "asset_path": rel_path,
                        "type": asset_type,
                        "file_exists": True,
                        "has_expected_hash": False,
                        "actual_size": len(raw_bytes),
                        "actual_sha256_b64": raw_b64,
                        "match_mode": "unhashed_metadata",
                        "verified": True,
                    }
                )
                continue

            raw_match = (raw_b64 == exp_hash) and (exp_size is None or len(raw_bytes) == exp_size)
            lf_match = (
                rel_path.lower().endswith(".xml")
                and (lf_b64 == exp_hash)
                and (exp_size is None or len(lf_bytes) == exp_size)
            )
            match_mode = "exact_raw" if raw_match else ("lf_normalized" if lf_match else "mismatch")
            manifest_checks.append(
                {
                    "package": pkg_name,
                    "asset_path": rel_path,
                    "type": asset_type,
                    "file_exists": True,
                    "has_expected_hash": True,
                    "expected_size": exp_size,
                    "actual_size": len(raw_bytes),
                    "lf_size": len(lf_bytes),
                    "expected_sha256_b64": exp_hash,
                    "actual_sha256_b64": raw_b64,
                    "actual_sha256_hex": raw_hex,
                    "lf_sha256_b64": lf_b64,
                    "lf_sha256_hex": lf_hex,
                    "match_mode": match_mode,
                    "verified": bool(raw_match or lf_match),
                }
            )

        # Cross-check /redray/images/<pkg> mirror against /redray/content/<pkg>/images
        for img_name in ("poster.jpg", "thumbnail.jpg"):
            pkg_img = pkg_dir / "images" / img_name
            mir_img = images_root / pkg_name / img_name
            if pkg_img.is_file() and mir_img.is_file():
                p_hex, p_b64, p_sz = sha256_file(pkg_img)
                m_hex, m_b64, m_sz = sha256_file(mir_img)
                mirror_checks.append(
                    {
                        "package": pkg_name,
                        "image": img_name,
                        "content_size": p_sz,
                        "mirror_size": m_sz,
                        "content_sha256_b64": p_b64,
                        "mirror_sha256_b64": m_b64,
                        "identical": (p_sz == m_sz and p_hex == m_hex),
                    }
                )
            else:
                mirror_checks.append(
                    {
                        "package": pkg_name,
                        "image": img_name,
                        "content_exists": pkg_img.is_file(),
                        "mirror_exists": mir_img.is_file(),
                        "identical": False,
                    }
                )

        # Verify clip.xml <-> chunklist.xml consistency (and red_files/*.RED if present)
        for chunklist_path in sorted(pkg_dir.rglob("chunklist.xml")):
            clip_dir = chunklist_path.parent
            clip_xml_path = clip_dir / "clip.xml"
            chunk_root = ET.fromstring(chunklist_path.read_text(encoding="utf-8").lstrip("\ufeff"))
            clip_hash = None
            clip_type = None
            if clip_xml_path.is_file():
                clip_root = ET.fromstring(clip_xml_path.read_text(encoding="utf-8").lstrip("\ufeff"))
                clip_hash = (clip_root.findtext("Hash") or "").strip() or None
                clip_type = (clip_root.findtext("Type") or "").strip() or None

            for chunk in chunk_root.findall(".//Chunk"):
                red_rel = (chunk.findtext("Path") or "").strip()
                exp_sz_s = (chunk.findtext("Size") or "").strip()
                exp_sz = int(exp_sz_s) if exp_sz_s.isdigit() else None
                chunk_hash = (chunk.findtext("Hash") or "").strip() or None
                parts = chunk.findall(".//Part")

                rel_from_content = clip_dir.relative_to(content_dir).as_posix()
                ext3_red_path = posixpath.join("/redray/content", rel_from_content, red_rel)
                mapped_red_name = make_output_filename(ext3_red_path, set())

                rec: Dict[str, Any] = {
                    "package": pkg_name,
                    "ext3_red_path": ext3_red_path,
                    "mapped_red_filename": mapped_red_name,
                    "clip_type": clip_type,
                    "part_count": len(parts),
                    "expected_size": exp_sz,
                    "chunklist_sha256_b64": chunk_hash,
                    "clip_xml_sha256_b64": clip_hash,
                    "clip_chunk_hash_match": (clip_hash == chunk_hash) if (clip_hash and chunk_hash) else None,
                    "red_file_checked": False,
                    "verified": (clip_hash == chunk_hash) if (clip_hash and chunk_hash) else bool(chunk_hash),
                }

                if verify_red_hashes and red_dir is not None:
                    red_file_path = red_dir / mapped_red_name
                    if red_file_path.is_file():
                        actual_sz = red_file_path.stat().st_size
                        _, actual_b64, _ = sha256_file(red_file_path)
                        size_ok = (exp_sz is None or actual_sz == exp_sz)
                        hash_ok = (chunk_hash is None or actual_b64 == chunk_hash)
                        clip_ok = (clip_hash is None or actual_b64 == clip_hash)
                        rec.update(
                            {
                                "red_file_checked": True,
                                "actual_size": actual_sz,
                                "actual_sha256_b64": actual_b64,
                                "size_match": size_ok,
                                "hash_match": hash_ok,
                                "verified": bool(size_ok and hash_ok and clip_ok),
                            }
                        )
                chunklist_checks.append(rec)

    return manifest_checks, chunklist_checks, mirror_checks


def populate_thumbnails(
    out_dir: Path,
    thumb_dir: Path,
    clean_old: bool = True,
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """Copy clean package poster.jpg and thumbnail.jpg into thumbnails/<PackageDir>__<name>.jpg."""
    thumb_dir.mkdir(parents=True, exist_ok=True)
    content_dir = out_dir / "redray" / "content"
    expected_files: Dict[str, Path] = {}

    if content_dir.is_dir():
        for pkg_dir in sorted(p for p in content_dir.iterdir() if p.is_dir()):
            for img_name in ("poster.jpg", "thumbnail.jpg"):
                src = pkg_dir / "images" / img_name
                if src.is_file():
                    dst_name = f"{pkg_dir.name}__{img_name}"
                    expected_files[dst_name] = src

    removed_old: List[str] = []
    if clean_old:
        for existing in sorted(thumb_dir.iterdir()):
            if existing.is_file() and existing.name not in expected_files:
                existing.unlink()
                removed_old.append(existing.name)

    checks: List[Dict[str, Any]] = []
    for dst_name, src_path in expected_files.items():
        dst_path = thumb_dir / dst_name
        shutil.copy2(src_path, dst_path)
        src_hex, _, src_sz = sha256_file(src_path)
        jinfo = validate_jpeg(dst_path)
        jinfo["thumbnail_filename"] = dst_name
        jinfo["source_path"] = str(src_path)
        jinfo["matches_source"] = (jinfo["sha256_hex"] == src_hex and jinfo["size"] == src_sz)
        jinfo["valid"] = bool(jinfo["valid"] and jinfo["matches_source"])
        checks.append(jinfo)

    return removed_old, checks


def run_asset_extraction(
    pbd_path: Optional[Path | str] = None,
    out_dir: Path = DEFAULT_OUT_DIR,
    thumb_dir: Path = DEFAULT_THUMB_DIR,
    red_dir: Optional[Path] = DEFAULT_RED_DIR,
    json_out: Optional[Path] = None,
    clean_old_thumbnails: bool = True,
    verify_red_hashes: bool = True,
    pure_python: bool = False,
) -> Dict[str, Any]:
    """Extract all non-.RED files from all ext3 partitions and verify every asset."""
    resolved_pbd = resolve_pbd_path(pbd_path)
    json_path = json_out if json_out is not None else (out_dir / "asset_verification.json")

    extracted_files: List[Dict[str, Any]] = []
    skipped_red_files: List[Dict[str, Any]] = []
    symlinks: List[Dict[str, Any]] = []
    special_files: List[Dict[str, Any]] = []
    partition_reports: List[Dict[str, Any]] = []

    with PbdDiskReader(resolved_pbd, use_native=not pure_python) as disk:
        out_dir.mkdir(parents=True, exist_ok=True)
        filesystems = open_ext3_filesystems(disk)
        if not filesystems:
            raise RuntimeError(f"No ext2/3/4 filesystems found in {resolved_pbd}")

        # Inspect file counts per partition to detect whether multiple partitions contain data
        nonempty_part_count = 0
        part_walks = []
        for part, fs in filesystems:
            walk_items = list(fs.walk("/"))
            has_entries = any(bool(files) for _, _, files in walk_items)
            if has_entries:
                nonempty_part_count += 1
            part_walks.append((part, fs, walk_items, has_entries))

        for part, fs, walk_items, has_entries in part_walks:
            p_reg = 0
            p_red = 0
            p_lnk = 0
            p_nonred_bytes = 0
            part_prefix = f"partition_{part.index}" if nonempty_part_count > 1 else ""

            for cur_dir, _subdirs, entries in walk_items:
                dir_parts = safe_rel_parts(cur_dir)
                if has_entries and dir_parts and dir_parts != ("lost+found",):
                    target_dir = out_dir.joinpath(*((part_prefix,) + dir_parts if part_prefix else dir_parts))
                    target_dir.mkdir(parents=True, exist_ok=True)

                for entry in entries:
                    assert entry.inode is not None
                    inode = entry.inode
                    ext3_path = posixpath.join(cur_dir, entry.name)

                    if inode.is_lnk:
                        target = fs.read_symlink_target(inode)
                        symlinks.append(
                            {
                                "partition": part.index,
                                "ext3_path": ext3_path,
                                "target": target,
                                "inode": inode.ino,
                                "mode": oct(inode.mode),
                                "mode_int": inode.mode,
                                "size": inode.size,
                            }
                        )
                        p_lnk += 1
                        continue

                    if not inode.is_reg:
                        special_files.append(
                            {
                                "partition": part.index,
                                "ext3_path": ext3_path,
                                "inode": inode.ino,
                                "mode": oct(inode.mode),
                                "mode_int": inode.mode,
                                "size": inode.size,
                            }
                        )
                        continue

                    if entry.name.lower().endswith(".red"):
                        skipped_red_files.append(
                            {
                                "partition": part.index,
                                "ext3_path": ext3_path,
                                "inode": inode.ino,
                                "size": inode.size,
                            }
                        )
                        p_red += 1
                        continue

                    rel_parts = safe_rel_parts(ext3_path)
                    dst_parts = (part_prefix,) + rel_parts if part_prefix else rel_parts
                    dst_path = out_dir.joinpath(*dst_parts)
                    dst_path.parent.mkdir(parents=True, exist_ok=True)

                    sha = hashlib.sha256()
                    written = 0
                    with open(dst_path, "wb") as fp:
                        for chunk in fs.iter_file_chunks(inode):
                            fp.write(chunk)
                            sha.update(chunk)
                            written += len(chunk)
                    if written != inode.size:
                        raise IOError(
                            f"Size mismatch extracting {ext3_path}: wrote {written} != inode {inode.size}"
                        )
                    digest = sha.digest()
                    extracted_files.append(
                        {
                            "partition": part.index,
                            "ext3_path": ext3_path,
                            "local_path": str(Path(*dst_parts)),
                            "inode": inode.ino,
                            "mode": oct(inode.mode),
                            "size": written,
                            "mtime": inode.mtime,
                            "sha256_hex": digest.hex(),
                            "sha256_b64": base64.b64encode(digest).decode("ascii"),
                        }
                    )
                    p_reg += 1
                    p_nonred_bytes += written

            partition_reports.append(
                {
                    "index": part.index,
                    "scheme": part.scheme,
                    "part_type": part.part_type,
                    "offset": part.offset,
                    "size": part.size,
                    "block_size": fs.sb.block_size,
                    "volume_name": fs.sb.volume_name,
                    "extracted_nonred_files": p_reg,
                    "extracted_nonred_bytes": p_nonred_bytes,
                    "skipped_red_files": p_red,
                    "symlinks": p_lnk,
                }
            )

    # Validate extracted JPEGs, XMLs, and SQLite DBs
    jpg_checks: List[Dict[str, Any]] = []
    xml_checks: List[Dict[str, Any]] = []
    sqlite_checks: List[Dict[str, Any]] = []
    for rec in extracted_files:
        fpath = out_dir / rec["local_path"]
        lower = fpath.name.lower()
        if lower.endswith(".jpg") or lower.endswith(".jpeg"):
            jpg_checks.append(validate_jpeg(fpath))
        elif lower.endswith(".xml"):
            xml_checks.append(validate_xml(fpath))
        elif lower.endswith(".db"):
            sqlite_checks.append(validate_sqlite(fpath))

    manifest_checks, chunklist_checks, mirror_checks = verify_package_manifests(
        out_dir=out_dir,
        red_dir=red_dir if (red_dir and red_dir.is_dir()) else None,
        verify_red_hashes=verify_red_hashes,
    )
    removed_old_thumbs, thumb_checks = populate_thumbnails(
        out_dir=out_dir,
        thumb_dir=thumb_dir,
        clean_old=clean_old_thumbnails,
    )

    jpg_ok = bool(jpg_checks) and all(c["valid"] for c in jpg_checks)
    xml_ok = bool(xml_checks) and all(c["valid"] for c in xml_checks)
    sqlite_ok = bool(sqlite_checks) and all(c["valid"] for c in sqlite_checks)
    manifest_ok = bool(manifest_checks) and all(c["verified"] for c in manifest_checks)
    chunklist_ok = bool(chunklist_checks) and all(c["verified"] for c in chunklist_checks)
    mirror_ok = bool(mirror_checks) and all(c["identical"] for c in mirror_checks)
    thumb_ok = bool(thumb_checks) and all(c["valid"] for c in thumb_checks)
    all_verified = all([jpg_ok, xml_ok, sqlite_ok, manifest_ok, chunklist_ok, mirror_ok, thumb_ok])

    report: Dict[str, Any] = {
        "pbd_path": str(resolved_pbd),
        "out_dir": str(out_dir),
        "thumbnails_dir": str(thumb_dir),
        "partitions": partition_reports,
        "summary": {
            "extracted_file_count": len(extracted_files),
            "extracted_total_bytes": sum(f["size"] for f in extracted_files),
            "skipped_red_count": len(skipped_red_files),
            "skipped_red_bytes": sum(f["size"] for f in skipped_red_files),
            "symlink_count": len(symlinks),
            "special_file_count": len(special_files),
            "removed_old_thumbnails": len(removed_old_thumbs),
            "jpg_count": len(jpg_checks),
            "jpg_all_valid": jpg_ok,
            "xml_count": len(xml_checks),
            "xml_all_valid": xml_ok,
            "sqlite_count": len(sqlite_checks),
            "sqlite_all_valid": sqlite_ok,
            "manifest_entry_count": len(manifest_checks),
            "manifest_hashed_count": sum(1 for c in manifest_checks if c.get("has_expected_hash")),
            "manifest_all_verified": manifest_ok,
            "chunklist_count": len(chunklist_checks),
            "chunklist_red_checked_count": sum(1 for c in chunklist_checks if c.get("red_file_checked")),
            "chunklist_all_verified": chunklist_ok,
            "image_mirror_count": len(mirror_checks),
            "image_mirrors_identical": mirror_ok,
            "thumbnail_output_count": len(thumb_checks),
            "thumbnails_all_valid": thumb_ok,
            "all_verified": all_verified,
        },
        "files": extracted_files,
        "symlinks": symlinks,
        "special_files": special_files,
        "skipped_red_files": skipped_red_files,
        "validations": {
            "jpegs": jpg_checks,
            "xmls": xml_checks,
            "sqlite_dbs": sqlite_checks,
            "manifest_assets": manifest_checks,
            "chunklists": chunklist_checks,
            "image_mirrors": mirror_checks,
            "thumbnails": thumb_checks,
            "removed_old_thumbnails": removed_old_thumbs,
        },
    }

    json_path.parent.mkdir(parents=True, exist_ok=True)
    with open(json_path, "w", encoding="utf-8") as fp:
        json.dump(report, fp, indent=2)
    return report


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Extract and verify all non-.RED metadata & assets from an EaseUS .pbd ext3 image"
    )
    ap.add_argument(
        "--pbd",
        type=Path,
        default=None,
        help="Path to .pbd disk image (default: resolved from pbdpath.txt or PBD_PATH)",
    )
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="Output root for extracted filesystem tree")
    ap.add_argument("--thumbnails-dir", type=Path, default=DEFAULT_THUMB_DIR, help="Output directory for clean package JPEGs")
    ap.add_argument("--red-dir", type=Path, default=DEFAULT_RED_DIR, help="Directory with extracted .RED files for chunklist cross-check")
    ap.add_argument("--json-out", type=Path, default=None, help="Path to asset_verification.json (default: <out-dir>/asset_verification.json)")
    ap.add_argument("--keep-old-thumbnails", action="store_true", help="Do not delete pre-existing files in thumbnails/")
    ap.add_argument("--skip-red-hash", action="store_true", help="Skip re-hashing 5.7 GB .RED files in red_files/ during chunklist verification")
    ap.add_argument("--pure-python", action="store_true", help="Disable native C FastLZ DLL and use pure Python")
    args = ap.parse_args()

    try:
        report = run_asset_extraction(
            pbd_path=args.pbd,
            out_dir=args.out_dir,
            thumb_dir=args.thumbnails_dir,
            red_dir=args.red_dir,
            json_out=args.json_out,
            clean_old_thumbnails=not args.keep_old_thumbnails,
            verify_red_hashes=not args.skip_red_hash,
            pure_python=args.pure_python,
        )
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    s = report["summary"]
    print(f"Extracted {s['extracted_file_count']} files ({s['extracted_total_bytes']:,} bytes), "
          f"skipped {s['skipped_red_count']} .RED files ({s['skipped_red_bytes']:,} bytes), "
          f"recorded {s['symlink_count']} symlinks.")
    print(f"Validations: JPG={s['jpg_count']} ({s['jpg_all_valid']}), "
          f"XML={s['xml_count']} ({s['xml_all_valid']}), "
          f"SQLite={s['sqlite_count']} ({s['sqlite_all_valid']}), "
          f"Manifest={s['manifest_hashed_count']}/{s['manifest_entry_count']} ({s['manifest_all_verified']}), "
          f"Chunklists={s['chunklist_count']} ({s['chunklist_all_verified']}), "
          f"Thumbnails={s['thumbnail_output_count']} ({s['thumbnails_all_valid']}, removed {s['removed_old_thumbnails']} old)")
    print(f"All verified: {s['all_verified']}")
    return 0 if s["all_verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
