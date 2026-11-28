#!/usr/bin/env python3
"""
Extract and SHA-256-verify .RED media files directly from an EaseUS .pbd disk image.

Reads virtual disk blocks on demand via scripts/pbd_reader.py (no full-disk unpack),
parses MBR/GPT partition tables, walks the ext3 filesystem (direct and
single/double/triple-indirect block pointers i_block[0..14], plus ext4 extents),
parses XML manifests under /redray, streams .RED files into red_files/ with
collision-free naming, and verifies SHA-256 hashes against manifest <Hash> entries.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import posixpath
import struct
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Protocol, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
DEFAULT_OUT_DIR = os.path.join(REPO_ROOT, "red_files")

EXT2_SUPER_MAGIC = 0xEF53
EXT4_FEATURE_INCOMPAT_64BIT = 0x0080
EXT4_EXTENTS_FL = 0x00080000
EXT4_EXTENT_MAGIC = 0xF30A

S_IFMT = 0xF000
S_IFDIR = 0x4000
S_IFREG = 0x8000
S_IFLNK = 0xA000


class DiskReader(Protocol):
    @property
    def disk_size(self) -> int: ...

    def read(self, offset: int, size: int) -> bytes: ...


@dataclass
class PartitionInfo:
    index: int
    scheme: str
    part_type: str
    start_lba: int
    num_sectors: int
    name: str = ""

    @property
    def offset(self) -> int:
        return self.start_lba * 512

    @property
    def size(self) -> int:
        return self.num_sectors * 512


def _parse_gpt(disk: DiskReader) -> List[PartitionInfo]:
    hdr = disk.read(512, 512)
    if len(hdr) < 92 or hdr[:8] != b"EFI PART":
        return []
    part_entry_lba, num_entries, entry_size = struct.unpack_from("<QII", hdr, 72)
    if entry_size < 128 or num_entries == 0 or num_entries > 4096:
        return []
    table = disk.read(part_entry_lba * 512, num_entries * entry_size)
    parts: List[PartitionInfo] = []
    for i in range(num_entries):
        off = i * entry_size
        if off + 128 > len(table):
            break
        type_guid = table[off : off + 16]
        if type_guid == b"\x00" * 16:
            continue
        first_lba, last_lba = struct.unpack_from("<QQ", table, off + 32)
        if first_lba == 0 or last_lba < first_lba:
            continue
        raw_name = table[off + 56 : off + 128]
        name = raw_name.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
        parts.append(
            PartitionInfo(
                index=i + 1,
                scheme="GPT",
                part_type=type_guid.hex(),
                start_lba=first_lba,
                num_sectors=last_lba - first_lba + 1,
                name=name,
            )
        )
    return parts


def _parse_ebr_chain(disk: DiskReader, ext_start_lba: int, start_idx: int) -> List[PartitionInfo]:
    parts: List[PartitionInfo] = []
    cur_lba = ext_start_lba
    seen = set()
    idx = start_idx
    while cur_lba not in seen and len(parts) < 64:
        seen.add(cur_lba)
        sec = disk.read(cur_lba * 512, 512)
        if len(sec) < 512 or sec[510:512] != b"\x55\xAA":
            break
        # Entry 0: logical partition relative to cur_lba; Entry 1: next EBR relative to ext_start_lba
        ptype0, lba0, cnt0 = struct.unpack_from("<4xB3xII", sec, 446)
        if ptype0 != 0 and cnt0 > 0:
            parts.append(
                PartitionInfo(
                    index=idx,
                    scheme="MBR-EBR",
                    part_type=f"0x{ptype0:02x}",
                    start_lba=cur_lba + lba0,
                    num_sectors=cnt0,
                )
            )
            idx += 1
        ptype1, lba1, cnt1 = struct.unpack_from("<4xB3xII", sec, 462)
        if ptype1 in (0x05, 0x0F, 0x85) and lba1 > 0 and cnt1 > 0:
            cur_lba = ext_start_lba + lba1
        else:
            break
    return parts


def parse_partitions(disk: DiskReader) -> List[PartitionInfo]:
    """Parse MBR or GPT partition tables from virtual disk."""
    mbr = disk.read(0, 512)
    if len(mbr) < 512 or mbr[510:512] != b"\x55\xAA":
        return []
    entries = [struct.unpack_from("<B3xB3xII", mbr, 446 + 16 * i) for i in range(4)]
    if any(ptype == 0xEE for _, ptype, _, _ in entries):
        gpt_parts = _parse_gpt(disk)
        if gpt_parts:
            return gpt_parts

    parts: List[PartitionInfo] = []
    logical_idx = 5
    for i, (_, ptype, start_lba, count) in enumerate(entries):
        if ptype == 0 or count == 0:
            continue
        if ptype in (0x05, 0x0F, 0x85):
            ebr_parts = _parse_ebr_chain(disk, start_lba, logical_idx)
            parts.extend(ebr_parts)
            logical_idx += len(ebr_parts)
        else:
            parts.append(
                PartitionInfo(
                    index=i + 1,
                    scheme="MBR",
                    part_type=f"0x{ptype:02x}",
                    start_lba=start_lba,
                    num_sectors=count,
                )
            )
    return parts


@dataclass
class Ext3Superblock:
    inodes_count: int
    blocks_count: int
    free_blocks_count: int
    free_inodes_count: int
    first_data_block: int
    block_size: int
    blocks_per_group: int
    inodes_per_group: int
    rev_level: int
    inode_size: int
    feature_compat: int
    feature_incompat: int
    feature_ro_compat: int
    volume_name: str
    desc_size: int
    is_64bit: bool

    @property
    def num_groups(self) -> int:
        return (self.blocks_count + self.blocks_per_group - 1) // self.blocks_per_group


@dataclass
class Inode:
    ino: int
    mode: int
    uid: int
    size: int
    mtime: int
    dtime: int
    links_count: int
    blocks_lo: int
    flags: int
    i_block_raw: bytes
    i_blocks_u32: Tuple[int, ...]

    @property
    def is_dir(self) -> bool:
        return (self.mode & S_IFMT) == S_IFDIR

    @property
    def is_reg(self) -> bool:
        return (self.mode & S_IFMT) == S_IFREG

    @property
    def is_lnk(self) -> bool:
        return (self.mode & S_IFMT) == S_IFLNK


@dataclass
class DirEntry:
    ino: int
    name: str
    file_type: int
    inode: Optional[Inode] = None


class Ext3Filesystem:
    """Read-only pure-Python ext2/ext3/ext4 reader over a random-access DiskReader."""

    def __init__(self, disk: DiskReader, part_offset: int):
        self.disk = disk
        self.part_offset = part_offset
        sb_raw = disk.read(part_offset + 1024, 1024)
        if len(sb_raw) < 1024:
            raise ValueError("Truncated ext3 superblock")
        magic = struct.unpack_from("<H", sb_raw, 0x38)[0]
        if magic != EXT2_SUPER_MAGIC:
            raise ValueError(f"Invalid ext3 superblock magic: 0x{magic:04x}")

        inodes_count, blocks_lo, _, free_blocks_lo, free_inodes, first_data_block, log_bs = (
            struct.unpack_from("<7I", sb_raw, 0x00)
        )
        blocks_per_group = struct.unpack_from("<I", sb_raw, 0x20)[0]
        inodes_per_group = struct.unpack_from("<I", sb_raw, 0x28)[0]
        rev_level = struct.unpack_from("<I", sb_raw, 0x4C)[0]
        inode_size = struct.unpack_from("<H", sb_raw, 0x58)[0] if rev_level >= 1 else 128
        if inode_size < 128:
            inode_size = 128
        feat_compat, feat_incompat, feat_ro_compat = struct.unpack_from("<3I", sb_raw, 0x5C)
        vol_name = sb_raw[0x78:0x88].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        is_64bit = bool(feat_incompat & EXT4_FEATURE_INCOMPAT_64BIT)
        desc_size = struct.unpack_from("<H", sb_raw, 0xFE)[0] if is_64bit else 32
        if is_64bit and desc_size < 64:
            desc_size = 64
        blocks_hi = struct.unpack_from("<I", sb_raw, 0x150)[0] if is_64bit else 0
        blocks_count = blocks_lo | (blocks_hi << 32)
        block_size = 1024 << log_bs

        self.sb = Ext3Superblock(
            inodes_count=inodes_count,
            blocks_count=blocks_count,
            free_blocks_count=free_blocks_lo,
            free_inodes_count=free_inodes,
            first_data_block=first_data_block,
            block_size=block_size,
            blocks_per_group=blocks_per_group,
            inodes_per_group=inodes_per_group,
            rev_level=rev_level,
            inode_size=inode_size,
            feature_compat=feat_compat,
            feature_incompat=feat_incompat,
            feature_ro_compat=feat_ro_compat,
            volume_name=vol_name,
            desc_size=desc_size,
            is_64bit=is_64bit,
        )
        self.ptrs_per_block = block_size // 4
        self._inode_cache: Dict[int, Inode] = {}

        bgdt_block = first_data_block + 1
        bgdt_bytes = disk.read(
            part_offset + bgdt_block * block_size,
            self.sb.num_groups * desc_size,
        )
        self.inode_tables: List[int] = []
        for g in range(self.sb.num_groups):
            off = g * desc_size
            lo = struct.unpack_from("<I", bgdt_bytes, off + 0x08)[0]
            hi = struct.unpack_from("<I", bgdt_bytes, off + 0x28)[0] if is_64bit else 0
            self.inode_tables.append(lo | (hi << 32))

    @classmethod
    def probe_partition(cls, disk: DiskReader, part_offset: int) -> bool:
        sb_raw = disk.read(part_offset + 1024, 128)
        if len(sb_raw) < 0x3A:
            return False
        return struct.unpack_from("<H", sb_raw, 0x38)[0] == EXT2_SUPER_MAGIC

    def read_block(self, block_num: int, count: int = 1) -> bytes:
        if block_num == 0:
            return b"\x00" * (count * self.sb.block_size)
        return self.disk.read(
            self.part_offset + block_num * self.sb.block_size,
            count * self.sb.block_size,
        )

    def read_inode(self, ino: int) -> Inode:
        cached = self._inode_cache.get(ino)
        if cached is not None:
            return cached
        if ino < 1 or ino > self.sb.inodes_count:
            raise ValueError(f"Inode {ino} out of range 1..{self.sb.inodes_count}")
        group = (ino - 1) // self.sb.inodes_per_group
        idx = (ino - 1) % self.sb.inodes_per_group
        itable_block = self.inode_tables[group]
        off = self.part_offset + itable_block * self.sb.block_size + idx * self.sb.inode_size
        raw = self.disk.read(off, self.sb.inode_size)
        if len(raw) < 128:
            raise ValueError(f"Truncated inode {ino}")
        mode, uid, size_lo = struct.unpack_from("<HHI", raw, 0x00)
        mtime, dtime = struct.unpack_from("<II", raw, 0x10)
        links_count = struct.unpack_from("<H", raw, 0x1A)[0]
        blocks_lo, flags = struct.unpack_from("<II", raw, 0x1C)
        i_block_raw = raw[0x28:0x64]
        i_blocks_u32 = struct.unpack_from("<15I", raw, 0x28)
        size_hi = struct.unpack_from("<I", raw, 0x6C)[0]
        full_size = (size_lo | (size_hi << 32)) if (mode & S_IFMT) == S_IFREG else size_lo
        inode = Inode(
            ino=ino,
            mode=mode,
            uid=uid,
            size=full_size,
            mtime=mtime,
            dtime=dtime,
            links_count=links_count,
            blocks_lo=blocks_lo,
            flags=flags,
            i_block_raw=i_block_raw,
            i_blocks_u32=i_blocks_u32,
        )
        self._inode_cache[ino] = inode
        return inode

    def _iter_indirect_blocks(
        self, block_num: int, depth: int, max_logical: int
    ) -> Iterator[Tuple[int, int]]:
        """Yield (phys_block, count) covering at most max_logical blocks."""
        if max_logical <= 0:
            return
        span = self.ptrs_per_block ** depth
        if block_num == 0:
            yield (0, min(max_logical, span))
            return
        if depth == 0:
            yield (block_num, 1)
            return
        raw = self.read_block(block_num, 1)
        ptrs = struct.unpack(f"<{self.ptrs_per_block}I", raw)
        child_span = self.ptrs_per_block ** (depth - 1)
        rem = max_logical
        for ptr in ptrs:
            if rem <= 0:
                break
            take = min(rem, child_span)
            if depth == 1:
                yield (ptr, 1)
            else:
                yield from self._iter_indirect_blocks(ptr, depth - 1, take)
            rem -= take

    def _iter_extents(self, node_bytes: bytes) -> Iterator[Tuple[int, int, int]]:
        """Yield raw leaf (ee_block, block_count, phys_start_or_0) across an extent tree."""
        magic, entries, _, depth, _ = struct.unpack_from("<HHHHI", node_bytes, 0)
        if magic != EXT4_EXTENT_MAGIC:
            raise ValueError(f"Invalid ext4 extent magic: 0x{magic:04x}")
        if depth == 0:
            for i in range(entries):
                ee_block, ee_len, ee_start_hi, ee_start_lo = struct.unpack_from(
                    "<IHHI", node_bytes, 12 + i * 12
                )
                unwritten = bool(ee_len & 0x8000)
                cnt = ee_len & 0x7FFF
                phys = 0 if unwritten else (ee_start_lo | (ee_start_hi << 32))
                yield (ee_block, cnt, phys)
        else:
            for i in range(entries):
                _, ei_leaf_lo, ei_leaf_hi, _ = struct.unpack_from(
                    "<IIHH", node_bytes, 12 + i * 12
                )
                leaf = ei_leaf_lo | (ei_leaf_hi << 32)
                yield from self._iter_extents(self.read_block(leaf, 1))

    def _iter_extent_node(self, node_bytes: bytes, total_blocks: int) -> Iterator[Tuple[int, int]]:
        cur_lbn = 0
        for ee_block, cnt, phys in self._iter_extents(node_bytes):
            if cur_lbn >= total_blocks:
                break
            if ee_block > cur_lbn:
                gap = min(ee_block - cur_lbn, total_blocks - cur_lbn)
                yield (0, gap)
                cur_lbn += gap
            take = min(cnt, max(0, total_blocks - cur_lbn))
            if take > 0:
                yield (phys, take)
                cur_lbn += take
        if cur_lbn < total_blocks:
            yield (0, total_blocks - cur_lbn)

    def iter_inode_block_runs(
        self, inode: Inode, max_run_blocks: int = 1024
    ) -> Iterator[Tuple[int, int]]:
        """Yield coalesced (phys_block, block_count) runs for an inode's data."""
        bs = self.sb.block_size
        total_blocks = (inode.size + bs - 1) // bs
        if total_blocks == 0:
            return

        if inode.flags & EXT4_EXTENTS_FL:
            raw_runs = self._iter_extent_node(inode.i_block_raw, total_blocks)
        else:
            def _raw_indirect() -> Iterator[Tuple[int, int]]:
                rem = total_blocks
                for i in range(12):
                    if rem <= 0:
                        return
                    yield (inode.i_blocks_u32[i], 1)
                    rem -= 1
                for depth, slot in ((1, 12), (2, 13), (3, 14)):
                    if rem <= 0:
                        return
                    span = self.ptrs_per_block ** depth
                    take = min(rem, span)
                    yield from self._iter_indirect_blocks(inode.i_blocks_u32[slot], depth, take)
                    rem -= take

            raw_runs = _raw_indirect()

        cur_phys: Optional[int] = None
        cur_cnt = 0
        emitted = 0
        for phys, cnt in raw_runs:
            if emitted >= total_blocks:
                break
            cnt = min(cnt, total_blocks - emitted)
            emitted += cnt
            can_merge = (
                cur_phys is not None
                and ((phys == 0 and cur_phys == 0) or (phys != 0 and cur_phys != 0 and phys == cur_phys + cur_cnt))
                and cur_cnt + cnt <= max_run_blocks
            )
            if can_merge:
                cur_cnt += cnt
            else:
                if cur_phys is not None:
                    yield (cur_phys, cur_cnt)
                cur_phys, cur_cnt = phys, cnt
        if cur_phys is not None:
            yield (cur_phys, cur_cnt)

    def iter_file_chunks(self, inode: Inode, max_run_blocks: int = 1024) -> Iterator[bytes]:
        """Stream an inode's exact i_size bytes in multi-block chunks."""
        if inode.size == 0:
            return
        bs = self.sb.block_size
        remaining = inode.size
        for phys, cnt in self.iter_inode_block_runs(inode, max_run_blocks=max_run_blocks):
            if remaining <= 0:
                break
            nbytes = min(remaining, cnt * bs)
            if phys == 0:
                yield b"\x00" * nbytes
            else:
                data = self.disk.read(self.part_offset + phys * bs, nbytes)
                if len(data) != nbytes:
                    raise IOError(f"Short read at phys block {phys}: got {len(data)}/{nbytes}")
                yield data
            remaining -= nbytes

    def read_file(self, inode: Inode) -> bytes:
        return b"".join(self.iter_file_chunks(inode))

    def read_symlink_target(self, inode: Inode) -> str:
        if inode.size <= 60 and inode.blocks_lo == 0:
            return inode.i_block_raw[: inode.size].decode("utf-8", errors="replace")
        return self.read_file(inode)[: inode.size].decode("utf-8", errors="replace")

    def list_dir(self, ino: int) -> List[DirEntry]:
        inode = self.read_inode(ino)
        if not inode.is_dir:
            raise NotADirectoryError(f"Inode {ino} is not a directory")
        data = self.read_file(inode)
        bs = self.sb.block_size
        entries: List[DirEntry] = []
        for blk_off in range(0, len(data), bs):
            blk = data[blk_off : blk_off + bs]
            off = 0
            while off + 8 <= len(blk):
                e_ino, rec_len, name_len, ftype = struct.unpack_from("<IHBB", blk, off)
                if rec_len < 8 or off + rec_len > len(blk):
                    break
                if e_ino != 0 and name_len > 0 and 8 + name_len <= rec_len:
                    name = blk[off + 8 : off + 8 + name_len].decode("utf-8", errors="replace")
                    if name not in (".", ".."):
                        entries.append(
                            DirEntry(
                                ino=e_ino,
                                name=name,
                                file_type=ftype,
                                inode=self.read_inode(e_ino),
                            )
                        )
                off += rec_len
        return entries

    def lookup_path(self, path: str) -> Optional[Inode]:
        parts = [p for p in path.split("/") if p]
        cur_ino = 2
        for part in parts:
            entries = self.list_dir(cur_ino)
            match = next((e for e in entries if e.name == part), None)
            if match is None:
                return None
            cur_ino = match.ino
        return self.read_inode(cur_ino)

    def walk(self, start_path: str = "/") -> Iterator[Tuple[str, List[DirEntry], List[DirEntry]]]:
        """Recursively yield (posix_dir_path, subdirs, files) starting at start_path."""
        root_inode = self.lookup_path(start_path)
        if root_inode is None or not root_inode.is_dir:
            return
        norm_start = "/" + "/".join(p for p in start_path.split("/") if p)
        stack: List[Tuple[str, int]] = [(norm_start, root_inode.ino)]
        visited_dirs = set()
        while stack:
            cur_path, cur_ino = stack.pop(0)
            if cur_ino in visited_dirs:
                continue
            visited_dirs.add(cur_ino)
            entries = sorted(self.list_dir(cur_ino), key=lambda e: e.name)
            subdirs = [e for e in entries if e.inode is not None and e.inode.is_dir]
            files = [e for e in entries if e.inode is not None and not e.inode.is_dir]
            yield cur_path, subdirs, files
            for d in subdirs:
                child = posixpath.join(cur_path, d.name)
                stack.append((child, d.ino))


def find_ext3_filesystems(disk: DiskReader) -> List[Tuple[PartitionInfo, Ext3Filesystem]]:
    """Locate and open all ext2/3/4 filesystems on the virtual disk."""
    parts = parse_partitions(disk)
    found: List[Tuple[PartitionInfo, Ext3Filesystem]] = []
    for p in parts:
        if Ext3Filesystem.probe_partition(disk, p.offset):
            found.append((p, Ext3Filesystem(disk, p.offset)))
    if not found and Ext3Filesystem.probe_partition(disk, 0):
        raw_part = PartitionInfo(0, "RAW", "ext3", 0, disk.disk_size // 512)
        found.append((raw_part, Ext3Filesystem(disk, 0)))
    return found


def parse_manifest_xml(xml_bytes: bytes, manifest_path: str) -> dict:
    """Parse a REDRAY XML manifest cleanly and return extracted file/clip metadata."""
    text = xml_bytes.decode("utf-8", errors="replace").lstrip("\ufeff\x00 \t\r\n")
    root = ET.fromstring(text)

    def _find_text(elem: ET.Element, tag: str) -> Optional[str]:
        node = elem.find(f".//{tag}")
        return node.text.strip() if node is not None and node.text else None

    file_entries = []
    # Support <ChunkList>/<Chunk>, <AssetList>/<Asset>, <File>, or root <Clip>
    candidates = (
        root.findall(".//Chunk")
        or root.findall(".//Asset")
        or root.findall(".//File")
        or [root]
    )
    for node in candidates:
        rel_path = _find_text(node, "Path")
        size_s = _find_text(node, "Size")
        hash_s = _find_text(node, "Hash")
        if rel_path or size_s or hash_s:
            parts = []
            for pnode in node.findall(".//Part"):
                parts.append(
                    {
                        "offset": _find_text(pnode, "Offset"),
                        "duration": _find_text(pnode, "Duration"),
                        "interleave_index": _find_text(pnode, "InterleaveIndex"),
                    }
                )
            file_entries.append(
                {
                    "path": rel_path,
                    "size": int(size_s) if size_s and size_s.isdigit() else None,
                    "hash": hash_s,
                    "parts": parts,
                }
            )

    return {
        "manifest_ext3_path": manifest_path,
        "root_tag": root.tag,
        "root_attrib": dict(root.attrib),
        "title_id": _find_text(root, "TitleId"),
        "package_id": _find_text(root, "PackageId"),
        "description": _find_text(root, "Description"),
        "clip_type": _find_text(root, "Type"),
        "entries": file_entries,
    }


def make_output_filename(ext3_path: str, existing_names: set) -> str:
    """Build a descriptive, collision-free filename inside red_files/ from an ext3 path."""
    rel = ext3_path.lstrip("/")
    if rel.startswith("redray/"):
        rel = rel[len("redray/") :]
    safe = rel.replace("/", "__")
    if safe not in existing_names:
        existing_names.add(safe)
        return safe
    stem, ext = os.path.splitext(safe)
    n = 2
    while f"{stem}_{n}{ext}" in existing_names:
        n += 1
    unique = f"{stem}_{n}{ext}"
    existing_names.add(unique)
    return unique


def inspect_filesystem(disk: DiskReader, start_dir: str = "/redray", dump_xml_dir: Optional[str] = None) -> None:
    filesystems = find_ext3_filesystems(disk)
    if not filesystems:
        print("No ext2/3/4 filesystems found on disk.")
        return
    for part, fs in filesystems:
        print(
            f"Partition #{part.index} ({part.scheme} {part.part_type} {part.name}): "
            f"offset={part.offset} size={part.size:,} "
            f"ext_vol='{fs.sb.volume_name}' bs={fs.sb.block_size} "
            f"blocks={fs.sb.blocks_count:,} inodes={fs.sb.inodes_count:,}"
        )
        print("Top-level '/' entries:")
        for e in sorted(fs.list_dir(2), key=lambda x: x.name):
            kind = "DIR" if (e.inode and e.inode.is_dir) else ("LNK" if (e.inode and e.inode.is_lnk) else "REG")
            sz = e.inode.size if e.inode else 0
            print(f"  {kind} ino={e.ino:8d} size={sz:12,d} {e.name}")

        total_red = 0
        total_red_bytes = 0
        xml_count = 0
        print(f"\nWalking '{start_dir}':")
        for cur_dir, subdirs, files in fs.walk(start_dir):
            for f in files:
                assert f.inode is not None
                fpath = posixpath.join(cur_dir, f.name)
                kind = "LNK" if f.inode.is_lnk else "REG"
                print(f"  {kind} ino={f.ino:8d} size={f.inode.size:12,d} {fpath}")
                if f.name.upper().endswith(".RED") and f.inode.is_reg:
                    total_red += 1
                    total_red_bytes += f.inode.size
                elif f.name.lower().endswith(".xml") and f.inode.is_reg:
                    xml_count += 1
                    if dump_xml_dir:
                        os.makedirs(dump_xml_dir, exist_ok=True)
                        out_xml = os.path.join(dump_xml_dir, make_output_filename(fpath, set()))
                        with open(out_xml, "wb") as fp:
                            fp.write(fs.read_file(f.inode))
        print(f"\nSummary under {start_dir}: {total_red} .RED files ({total_red_bytes / 1e9:.3f} GB), {xml_count} .xml files")


def run_extraction(
    pbd_path: Optional[Path | str] = None,
    out_dir: str = DEFAULT_OUT_DIR,
    start_dir: str = "/redray",
    remove_old_corrupt: bool = True,
) -> Dict:
    from pbd_reader import PbdDiskReader, resolve_pbd_path  # local scripts/ import

    resolved_pbd = resolve_pbd_path(pbd_path)
    with PbdDiskReader(resolved_pbd) as disk:
        os.makedirs(out_dir, exist_ok=True)
        filesystems = find_ext3_filesystems(disk)
        if not filesystems:
            raise RuntimeError("No ext2/3/4 filesystem found in .pbd image")
        part, fs = filesystems[0]

        red_files: List[Tuple[str, Inode]] = []
        xml_files: List[Tuple[str, Inode]] = []
        for cur_dir, _, files in fs.walk(start_dir):
            for f in files:
                if f.inode is None or not f.inode.is_reg:
                    continue
                fpath = posixpath.join(cur_dir, f.name)
                if f.name.upper().endswith(".RED"):
                    red_files.append((fpath, f.inode))
                elif f.name.lower().endswith(".xml"):
                    xml_files.append((fpath, f.inode))

        manifests_by_dir: Dict[str, List[dict]] = {}
        for x_path, x_ino in xml_files:
            raw_xml = fs.read_file(x_ino)
            try:
                parsed = parse_manifest_xml(raw_xml, x_path)
                manifests_by_dir.setdefault(posixpath.dirname(x_path), []).append(parsed)
            except Exception as exc:
                manifests_by_dir.setdefault(posixpath.dirname(x_path), []).append(
                    {"manifest_ext3_path": x_path, "parse_error": str(exc)}
                )

        # Build lookup from ext3 path -> manifest entry (prefer ChunkList/complete entries)
        expected_map: Dict[str, dict] = {}
        clip_hashes_by_dir: Dict[str, str] = {}
        for x_dir, mlist in manifests_by_dir.items():
            for m in mlist:
                if m.get("root_tag") == "Clip":
                    for entry in m.get("entries", []):
                        if entry.get("hash"):
                            clip_hashes_by_dir[x_dir] = entry["hash"]
                for entry in m.get("entries", []):
                    rel = entry.get("path")
                    if rel:
                        norm = posixpath.normpath(posixpath.join(x_dir, rel))
                        prev = expected_map.get(norm)
                        if prev is None or (m.get("root_tag") == "ChunkList"):
                            expected_map[norm] = {**entry, "manifest": m["manifest_ext3_path"]}

        used_names = set()
        results = []
        total_written = 0
        all_ok = True
        verified_count = 0
        manifest_required_count = 0

        for ext3_path, inode in sorted(red_files, key=lambda x: x[0]):
            out_name = make_output_filename(ext3_path, used_names)
            out_path = os.path.join(out_dir, out_name)
            sha = hashlib.sha256()
            cnt_1f = 0
            head = b""
            written = 0
            with open(out_path, "wb") as fp:
                for chunk in fs.iter_file_chunks(inode):
                    if not head:
                        head = chunk[:64]
                    fp.write(chunk)
                    sha.update(chunk)
                    cnt_1f += chunk.count(0x1F)
                    written += len(chunk)
            total_written += written
            digest = sha.digest()
            b64_hash = base64.b64encode(digest).decode("ascii")
            norm_path = posixpath.normpath(ext3_path)
            exp = expected_map.get(norm_path, {})
            exp_hash = exp.get("hash")
            exp_size = exp.get("size")
            clip_hash = clip_hashes_by_dir.get(posixpath.dirname(norm_path))
            hash_match = (b64_hash == exp_hash) if exp_hash else None
            clip_hash_match = (b64_hash == clip_hash) if clip_hash else None
            size_match = (written == exp_size) if exp_size is not None else None
            requires_manifest = norm_path.startswith("/redray/content/")
            if requires_manifest:
                manifest_required_count += 1
                if hash_match is not True or size_match is not True or clip_hash_match is False:
                    all_ok = False
            if hash_match is False or size_match is False or written != inode.size:
                all_ok = False
            if hash_match is True and size_match is True:
                verified_count += 1
            pct_1f = (100.0 * cnt_1f / written) if written else 0.0
            u32_0 = struct.unpack_from("<I", head, 0)[0] if len(head) >= 4 else None
            rra1_at_4 = head[4:8] == b"RRA1" if len(head) >= 8 else False
            mdt1_at_16 = head[16:20] == b"MDT1" if len(head) >= 20 else False
            rec = {
                "output_filename": out_name,
                "ext3_path": ext3_path,
                "inode": inode.ino,
                "inode_size": inode.size,
                "actual_size": written,
                "expected_size": exp_size,
                "size_match": size_match,
                "actual_sha256_b64": b64_hash,
                "actual_sha256_hex": digest.hex(),
                "expected_sha256_b64": exp_hash,
                "hash_match": hash_match,
                "clip_xml_hash_match": clip_hash_match,
                "manifest_path": exp.get("manifest"),
                "u32_prefix_0": u32_0,
                "rra1_at_4": rra1_at_4,
                "mdt1_at_16": mdt1_at_16,
                "magic_hex": head[:24].hex(),
                "pct_0x1F": round(pct_1f, 4),
            }
            results.append(rec)
            print(
                f"{out_name}\n  size={written:,d} (exp={exp_size}) sha256={b64_hash} "
                f"hash_ok={hash_match} clip_ok={clip_hash_match} "
                f"0x1F={pct_1f:.3f}% rra1@4={rra1_at_4} mdt1@16={mdt1_at_16}"
            )

        removed_old = []
        if remove_old_corrupt and all_ok and results:
            new_names = {r["output_filename"] for r in results}
            for fn in sorted(os.listdir(out_dir)):
                if fn.upper().endswith(".RED") and fn not in new_names:
                    os.remove(os.path.join(out_dir, fn))
                    removed_old.append(fn)

        report = {
            "pbd_path": str(resolved_pbd),
            "partition": {
                "index": part.index,
                "scheme": part.scheme,
                "offset": part.offset,
                "size": part.size,
                "volume_name": fs.sb.volume_name,
                "block_size": fs.sb.block_size,
            },
            "total_red_files": len(results),
            "manifest_required_count": manifest_required_count,
            "manifest_verified_count": verified_count,
            "total_bytes_written": total_written,
            "removed_old_corrupt_files": removed_old,
            "all_verified": all_ok,
            "files": results,
        }
        ver_path = os.path.join(out_dir, "manifest_verification.json")
        with open(ver_path, "w", encoding="utf-8") as fp:
            json.dump(report, fp, indent=2)
        return report


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract and verify .RED files from .pbd image")
    ap.add_argument(
        "--pbd",
        default=None,
        help="Path to .pbd image (default: resolved from pbdpath.txt or PBD_PATH)",
    )
    ap.add_argument("--out-dir", default=DEFAULT_OUT_DIR, help="Output directory for .RED files")
    ap.add_argument("--start-dir", default="/redray", help="Root ext3 directory to walk")
    ap.add_argument("--inspect-fs", action="store_true", help="Inspect partitions, ext3 tree, and XMLs only")
    ap.add_argument("--dump-xml-dir", default=None, help="Optional dir to dump XML manifests during --inspect-fs")
    ap.add_argument("--keep-old", action="store_true", help="Do not delete old corrupted .RED carves")
    args = ap.parse_args()

    try:
        if args.inspect_fs:
            from pbd_reader import PbdDiskReader

            with PbdDiskReader(args.pbd) as disk:
                inspect_filesystem(disk, start_dir=args.start_dir, dump_xml_dir=args.dump_xml_dir)
            return 0

        report = run_extraction(
            pbd_path=args.pbd,
            out_dir=args.out_dir,
            start_dir=args.start_dir,
            remove_old_corrupt=not args.keep_old,
        )
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(
        f"\nExtracted {report['total_red_files']} files, "
        f"{report['total_bytes_written'] / 1e9:.3f} GB, all_verified={report['all_verified']}"
    )
    return 0 if report["all_verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
