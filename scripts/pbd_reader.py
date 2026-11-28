#!/usr/bin/env python3
"""
Indexed O(1) random-access reader for EaseUS .pbd (IMGF v0x20000) disk backup images.

Parses the IMGF forward header, reversed IMGF footer, compressed HMGF/GMGF
volume metadata, VOLM geometry, Track-0 boot area (0x400100), and 0x400001
LBA-to-record index tables with IEEE CRC-32 verification at every layer.

Uses reddecoder/pbd_fastdec.dll (x64 MSVC FastLZ L1/L2 decoder) via ctypes
when available for >500 MB/s decompression, falling back automatically to pure
Python FastLZ decompression when the DLL is not present.

Image path configuration:
  Pass a .pbd path explicitly, create 'pbdpath.txt' in the repository root
  with 'PBD_PATH=<path/to/backup.pbd>', or set the PBD_PATH environment variable.

Compression credit:
  FastLZ Level 1 / Level 2 compression format and algorithm by Ariya Hidayat
  (https://ariya.github.io/FastLZ/ / https://github.com/ariya/FastLZ), MIT License.
"""
from __future__ import annotations

import argparse
import bisect
import ctypes
import os
import struct
import sys
import time
import zlib
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
PBDPATH_FILE = REPO_ROOT / "pbdpath.txt"
DEFAULT_FASTDEC_DLL = REPO_ROOT / "reddecoder" / "pbd_fastdec.dll"

IMGF_VERSION_V2 = 0x20000


def _strip_optional_quotes(val: str) -> str:
    val = val.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
        return val[1:-1].strip()
    return val


def resolve_pbd_path(path: Optional[Path | str] = None) -> Path:
    """
    Resolve the target .pbd image path from an explicit path argument,
    REPO_ROOT / 'pbdpath.txt' (PBD_PATH=<val>), or the PBD_PATH environment variable.
    """
    if path is not None:
        raw = _strip_optional_quotes(str(path))
        if raw:
            expanded = os.path.expanduser(os.path.expandvars(raw))
            return Path(expanded)

    if PBDPATH_FILE.is_file():
        for raw_line in PBDPATH_FILE.read_text(encoding="utf-8-sig").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            if key.strip() == "PBD_PATH":
                cleaned = _strip_optional_quotes(val)
                if cleaned:
                    expanded = os.path.expanduser(os.path.expandvars(cleaned))
                    candidate = Path(expanded)
                    if not candidate.is_absolute():
                        candidate = (REPO_ROOT / candidate).resolve()
                    return candidate

    env_val = os.environ.get("PBD_PATH")
    if env_val is not None:
        cleaned_env = _strip_optional_quotes(env_val)
        if cleaned_env:
            expanded = os.path.expanduser(os.path.expandvars(cleaned_env))
            return Path(expanded)

    raise FileNotFoundError(
        "No .pbd image path configured. Pass the path via CLI or create "
        "'pbdpath.txt' in the repo root with 'PBD_PATH=<path/to/backup.pbd>'."
    )


def _load_fastdec_dll(dll_path: Path = DEFAULT_FASTDEC_DLL):
    if not dll_path.is_file():
        return None
    try:
        lib = ctypes.CDLL(str(dll_path))
        fn = lib.fastlz_dec
        fn.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
        fn.restype = ctypes.c_int64
        return fn
    except OSError:
        return None


_C_FASTLZ_DEC = _load_fastdec_dll()


def fastlz_decompress_py(data: bytes, expected_len: Optional[int] = None) -> bytes:
    """
    Pure-Python raw FastLZ Level 1 / Level 2 decompressor.

    Implements the FastLZ format by Ariya Hidayat
    (https://ariya.github.io/FastLZ/ / https://github.com/ariya/FastLZ, MIT License).
    """
    if not data:
        if expected_len not in (None, 0):
            raise ValueError(f"Empty FastLZ stream, expected {expected_len} bytes")
        return b""

    ip = 0
    n = len(data)
    level = (data[0] >> 5) + 1
    if level not in (1, 2):
        raise ValueError(f"Unsupported FastLZ level {level} (b0={data[0]:#x})")

    out = bytearray()
    ctrl = data[ip] & 31
    ip += 1

    while True:
        if ctrl >= 32:
            match_len = (ctrl >> 5) - 1
            ofs = (ctrl & 31) << 8
            if match_len == 6:
                if level == 1:
                    if ip >= n:
                        raise ValueError("Truncated FastLZ L1 match length")
                    match_len += data[ip]
                    ip += 1
                else:
                    while True:
                        if ip >= n:
                            raise ValueError("Truncated FastLZ L2 match length")
                        code = data[ip]
                        ip += 1
                        match_len += code
                        if code != 255:
                            break
            if ip >= n:
                raise ValueError("Truncated FastLZ match offset")
            code = data[ip]
            ip += 1
            if level == 2 and code == 255 and (ctrl & 31) == 31:
                if ip + 1 >= n:
                    raise ValueError("Truncated FastLZ L2 far offset")
                far_ofs = (data[ip] << 8) | data[ip + 1]
                ip += 2
                ref = len(out) - far_ofs - 8192 - 1
            else:
                ref = len(out) - ofs - code - 1
            if ref < 0:
                raise ValueError(f"Invalid FastLZ backreference ref={ref} at ip={ip}")
            for _ in range(match_len + 3):
                out.append(out[ref])
                ref += 1
        else:
            lit_len = ctrl + 1
            if ip + lit_len > n:
                raise ValueError("Truncated FastLZ literal run")
            out.extend(data[ip : ip + lit_len])
            ip += lit_len

        if ip >= n:
            break
        ctrl = data[ip]
        ip += 1

    if expected_len is not None and len(out) != expected_len:
        raise ValueError(f"FastLZ size mismatch: got {len(out)}, expected {expected_len}")
    return bytes(out)


def fastlz_decompress(
    data: bytes,
    expected_len: int,
    use_native: bool = True,
    out_buf: Optional[ctypes.Array] = None,
) -> bytes:
    """Decompress raw FastLZ level 1/2 stream using C DLL when available."""
    if use_native and _C_FASTLZ_DEC is not None:
        buf = out_buf if (out_buf is not None and len(out_buf) >= expected_len) else ctypes.create_string_buffer(expected_len)
        rc = _C_FASTLZ_DEC(data, len(data), buf, expected_len)
        if rc < 0:
            raise ValueError(f"Native FastLZ decompression failed with code {rc}")
        if rc != expected_len:
            raise ValueError(f"FastLZ size mismatch: got {rc}, expected {expected_len}")
        return buf.raw[:expected_len]
    return fastlz_decompress_py(data, expected_len=expected_len)


def decompress_block(
    data: bytes,
    algo: int,
    expected_len: int,
    enc_mode: int = 0,
    use_native: bool = True,
    out_buf: Optional[ctypes.Array] = None,
) -> bytes:
    """Decompress a single container/record payload according to DsImgFile.dll."""
    if enc_mode != 0:
        raise NotImplementedError(f"Encrypted block (enc_mode={enc_mode}) not supported")
    if algo == 0:
        if len(data) != expected_len:
            raise ValueError(f"Raw block size mismatch: {len(data)} != {expected_len}")
        return data
    if algo == 1:
        return fastlz_decompress(data, expected_len=expected_len, use_native=use_native, out_buf=out_buf)
    if algo in (2, 4, 5, 7, 9):
        out = zlib.decompress(data)
        if len(out) != expected_len:
            raise ValueError(f"Zlib size mismatch: {len(out)} != {expected_len}")
        return out
    if algo == 3:
        import lz4.block  # type: ignore

        sz = struct.unpack_from("<I", data, 0)[0]
        return lz4.block.decompress(data[4 : 4 + sz], uncompressed_size=expected_len)
    if algo in (6, 8):
        import zstandard  # type: ignore

        sz = struct.unpack_from("<I", data, 0)[0]
        return zstandard.ZstdDecompressor().decompress(data[4 : 4 + sz], max_output_size=expected_len)
    raise ValueError(f"Unknown compression algo={algo}")


def verify_crc32_masked(buf: bytes, crc_offset: int) -> int:
    """Verify IEEE CRC-32 with the 4-byte checksum field masked to zero."""
    stored = struct.unpack_from("<I", buf, crc_offset)[0]
    tmp = bytearray(buf)
    tmp[crc_offset : crc_offset + 4] = b"\x00\x00\x00\x00"
    calc = zlib.crc32(tmp) & 0xFFFFFFFF
    if calc != stored:
        raise ValueError(f"CRC-32 mismatch at {crc_offset:#x}: calc={calc:#010x} != stored={stored:#010x}")
    return stored


def parse_forward_tlv(
    buf: bytes, expected_magic: Optional[bytes] = None
) -> Tuple[bytes, int, Dict[int, bytes], List[Tuple[int, bytes]]]:
    """Parse a forward IMGF/HMGF/GMGF TLV container."""
    magic, total_sz, ver, _crc, n_tlv, _tbl_sz, tbl_off, _u1, _pay_sz, pay_off, _u2 = struct.unpack_from(
        "<4s10I", buf, 0
    )
    if expected_magic is not None and magic != expected_magic:
        raise ValueError(f"Unexpected container magic {magic!r}, expected {expected_magic!r}")
    verify_crc32_masked(buf[:total_sz], 0x0C)
    items: List[Tuple[int, bytes]] = []
    by_tag: Dict[int, bytes] = {}
    pos = pay_off
    for i in range(n_tlv):
        tag, sz = struct.unpack_from("<II", buf, tbl_off + i * 8)
        val = buf[pos : pos + sz]
        items.append((tag, val))
        by_tag[tag] = val
        pos += sz
    return magic, ver, by_tag, items


def find_and_parse_footer(f: BinaryIO) -> Tuple[int, int, Dict[int, bytes]]:
    """Locate the reversed IMGF footer past trailing 0xFF padding and validate CRC-32."""
    f.seek(0, 2)
    fsize = f.tell()
    tail_probe = min(fsize, 65536)
    f.seek(fsize - tail_probe)
    buf = f.read(tail_probe)

    end = len(buf)
    while end > 0 and buf[end - 1] == 0xFF:
        end -= 1
    if end < 0x2C or buf[end - 0x10 : end - 0xC] != b"IMGF":
        raise ValueError("Could not locate reversed IMGF footer trailer")

    total_sz, ver, _crc = struct.unpack_from("<III", buf, end - 0x0C)
    if ver != IMGF_VERSION_V2:
        raise ValueError(f"Unsupported IMGF footer version {ver:#x}")
    footer_start = end - total_sz
    if footer_start < 0:
        raise ValueError("Footer spans before probe window")

    ftr = buf[footer_start:end]
    verify_crc32_masked(ftr, len(ftr) - 4)
    n_tlv, _tbl_sz, tbl_off, _u1, _pay_sz, pay_off, _u2 = struct.unpack_from("<7I", ftr, len(ftr) - 0x2C)

    by_tag: Dict[int, bytes] = {}
    pos = pay_off
    for i in range(n_tlv):
        tag, sz = struct.unpack_from("<II", ftr, tbl_off + i * 8)
        by_tag[tag] = ftr[pos : pos + sz]
        pos += sz
    return fsize - tail_probe + footer_start, total_sz, by_tag


@dataclass(frozen=True)
class RecordEntry:
    rec_id: int
    uncomp_sz: int
    comp_sz: int
    payload_crc: int
    foff_rel: int


@dataclass
class IndexChunk:
    chunk_idx: int
    rec_bytes: int
    unit_sz: int
    bmp_len: int
    sector_sz: int
    base_sec: int
    end_sec: int
    entries: List[RecordEntry]


@dataclass
class VolumeInfo:
    vol_index: int
    flags: int
    disk_sig: int
    start_sector: int
    num_sectors: int
    bytes_per_sector: int
    total_disk_sectors: int
    track0: bytes
    chunks: List[IndexChunk]
    chunk_base_secs: List[int]

    @property
    def end_sector(self) -> int:
        return self.start_sector + self.num_sectors


class PbdDiskReader:
    """
    Indexed O(1) random-access disk reader for IMGF v0x20000 EaseUS .pbd images.

    Exposes `.disk_size`, `.sector_size`, `.read(offset, size)`,
    `.read_sectors(lba, count)`, and `.read_block(offset, size)`.
    """

    def __init__(
        self,
        path: Optional[Path | str] = None,
        cache_records: int = 256,
        use_native: bool = True,
    ) -> None:
        self.path = resolve_pbd_path(path)
        if not self.path.is_file():
            raise FileNotFoundError(f".pbd image file not found: {self.path}")
        self.f: BinaryIO = open(self.path, "rb")
        self.cache_records = cache_records
        self.use_native = use_native and (_C_FASTLZ_DEC is not None)
        self._rec_cache: "OrderedDict[Tuple[int, int, int], bytes]" = OrderedDict()
        self._zero_cache: Dict[int, bytes] = {}
        self._dec_scratch = ctypes.create_string_buffer(2 * 1024 * 1024)

        # 1. File Header
        hdr_prefix = self.f.read(0x2C)
        if len(hdr_prefix) < 0x2C:
            raise ValueError("Truncated .pbd header")
        magic, hdr_sz, ver = struct.unpack_from("<4sII", hdr_prefix, 0)
        if magic != b"IMGF" or ver != IMGF_VERSION_V2:
            raise ValueError(f"Unsupported PBD header magic={magic!r} ver={ver:#x}")
        self.f.seek(0)
        hdr_buf = self.f.read(hdr_sz)
        _, _, self.header_tlvs, _ = parse_forward_tlv(hdr_buf, b"IMGF")

        comp_cfg = self.header_tlvs.get(0x200001, b"\x01\x00\x00\x00\x01\x00\x00\x00")
        self.algo = struct.unpack_from("<I", comp_cfg, 0)[0]
        self.enc_mode = struct.unpack_from("<I", self.header_tlvs.get(0x200005, b"\x00\x00\x00\x00"), 0)[0]

        # 2. Footer & DATA_BASE
        self.footer_abs, self.footer_sz, self.footer_tlvs = find_and_parse_footer(self.f)
        self.data_base = struct.unpack_from("<I", self.footer_tlvs[0x200103], 0x10)[0]
        if self.data_base != hdr_sz:
            raise ValueError(f"DATA_BASE {self.data_base:#x} != header size {hdr_sz:#x}")

        # 3. HMGF & GMGF Volumes
        h_off_rel, h_usz, h_csz = struct.unpack_from("<QII", self.footer_tlvs[0x200101], 0)
        self.f.seek(self.data_base + h_off_rel)
        hmgf_bytes = decompress_block(
            self.f.read(h_csz), self.algo, h_usz, self.enc_mode, use_native=self.use_native, out_buf=self._dec_scratch
        )
        _, _, _, hmgf_items = parse_forward_tlv(hmgf_bytes, b"HMGF")

        self.volumes: List[VolumeInfo] = []
        for vi, (_, g_raw) in enumerate(hmgf_items):
            _, _, g_tlvs, _ = parse_forward_tlv(g_raw, b"GMGF")
            volm = g_tlvs[0x400000]
            if volm[:4] != b"VOLM":
                raise ValueError(f"Invalid VOLM signature in GMGF[{vi}]: {volm[:4]!r}")
            vol_flags = struct.unpack_from("<I", volm, 0x08)[0]
            disk_sig = struct.unpack_from("<I", volm, 0x10)[0]
            start_sec, num_sec = struct.unpack_from("<QQ", volm, 0x120)
            bps = struct.unpack_from("<I", volm, 0x148)[0]
            total_disk_sec = struct.unpack_from("<Q", volm, 0x16C)[0] if len(volm) >= 0x174 else 0
            track0 = g_tlvs.get(0x400100, b"")

            idx_desc_blob = g_tlvs.get(0x400001) or g_tlvs.get(0x400004, b"")
            chunks: List[IndexChunk] = []
            for ci in range(0, len(idx_desc_blob), 0x40):
                desc = idx_desc_blob[ci : ci + 0x40]
                cidx, c_usz, c_csz, c_foff, c_crc = struct.unpack_from("<IIIQI", desc, 0)
                rec_b, unit_b, bmp_b, sec_sz, base_sec, end_sec, _rec_cnt = struct.unpack_from("<IIIIQQQ", desc, 0x18)

                self.f.seek(self.data_base + c_foff)
                idx_bytes = decompress_block(
                    self.f.read(c_csz), self.algo, c_usz, self.enc_mode, use_native=self.use_native
                )
                if (zlib.crc32(idx_bytes) & 0xFFFFFFFF) != c_crc:
                    raise ValueError(f"Index chunk CRC mismatch vol={vi} chunk={ci}")

                entries = [
                    RecordEntry(*struct.unpack_from("<IIIIQ", idx_bytes, off))
                    for off in range(0, len(idx_bytes), 0x18)
                ]
                chunks.append(
                    IndexChunk(
                        chunk_idx=cidx,
                        rec_bytes=rec_b,
                        unit_sz=unit_b,
                        bmp_len=bmp_b,
                        sector_sz=sec_sz,
                        base_sec=base_sec,
                        end_sec=end_sec,
                        entries=entries,
                    )
                )

            chunks.sort(key=lambda ch: ch.base_sec)
            self.volumes.append(
                VolumeInfo(
                    vol_index=vi,
                    flags=vol_flags,
                    disk_sig=disk_sig,
                    start_sector=start_sec,
                    num_sectors=num_sec,
                    bytes_per_sector=bps,
                    total_disk_sectors=total_disk_sec,
                    track0=track0,
                    chunks=chunks,
                    chunk_base_secs=[ch.base_sec for ch in chunks],
                )
            )

        self._sector_size = self.volumes[0].bytes_per_sector if self.volumes else 512
        self._track0 = next((v.track0 for v in self.volumes if v.track0), b"")
        max_vol_sec = max((v.end_sector for v in self.volumes), default=0)
        max_total_sec = max([v.total_disk_sectors for v in self.volumes] + [max_vol_sec])
        self._disk_size = max_total_sec * self._sector_size

    @property
    def sector_size(self) -> int:
        return self._sector_size

    @property
    def disk_size(self) -> int:
        return self._disk_size

    def close(self) -> None:
        if not self.f.closed:
            self.f.close()

    def __enter__(self) -> "PbdDiskReader":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _zeros(self, n: int) -> bytes:
        z = self._zero_cache.get(n)
        if z is None:
            z = b"\x00" * n
            self._zero_cache[n] = z
        return z

    def decode_record(self, rec: RecordEntry, bmp_len: int, rec_bytes: int, unit_sz: int) -> bytes:
        """Read, decompress, CRC32-verify, and sparse-bitmap-reconstruct one data record."""
        if rec.comp_sz == 0 and rec.uncomp_sz == 0:
            return self._zeros(rec_bytes)
        self.f.seek(self.data_base + rec.foff_rel)
        raw = self.f.read(rec.comp_sz)
        dec = decompress_block(
            raw, self.algo, rec.uncomp_sz, self.enc_mode, use_native=self.use_native, out_buf=self._dec_scratch
        )
        bmp = dec[:bmp_len]
        pay = dec[bmp_len:]
        calc_crc = (zlib.crc32(pay) & 0xFFFFFFFF) if pay else 0
        if calc_crc != rec.payload_crc:
            raise ValueError(
                f"Record {rec.rec_id} payload CRC mismatch: {calc_crc:#010x} != {rec.payload_crc:#010x}"
            )

        n_units = rec_bytes // unit_sz
        if bmp_len == 0:
            return pay
        if n_units == 1:
            return pay if (bmp[0] & 1) else self._zeros(rec_bytes)

        out = bytearray(rec_bytes)
        ppos = 0
        for ui in range(n_units):
            if (bmp[ui >> 3] >> (ui & 7)) & 1:
                out[ui * unit_sz : (ui + 1) * unit_sz] = pay[ppos : ppos + unit_sz]
                ppos += unit_sz
        return bytes(out)

    def _get_record_cached(self, vol_idx: int, chunk: IndexChunk, rec_idx: int) -> bytes:
        key = (vol_idx, chunk.chunk_idx, rec_idx)
        hit = self._rec_cache.get(key)
        if hit is not None:
            self._rec_cache.move_to_end(key)
            return hit
        data = self.decode_record(chunk.entries[rec_idx], chunk.bmp_len, chunk.rec_bytes, chunk.unit_sz)
        self._rec_cache[key] = data
        if len(self._rec_cache) > self.cache_records:
            self._rec_cache.popitem(last=False)
        return data

    def _find_chunk(self, vol: VolumeInfo, sec: int) -> IndexChunk:
        idx = bisect.bisect_right(vol.chunk_base_secs, sec) - 1
        if idx < 0:
            raise KeyError(f"Volume {vol.vol_index} sector {sec:#x} before first chunk")
        ch = vol.chunks[idx]
        if not (ch.base_sec <= sec <= ch.end_sec):
            raise KeyError(f"Volume {vol.vol_index} sector {sec:#x} not indexed")
        return ch

    def read_volume(self, vol_idx: int, byte_off: int, size: int) -> bytes:
        """Read arbitrary byte range relative to the start of a backed-up volume."""
        vol = self.volumes[vol_idx]
        vol_bytes = vol.num_sectors * vol.bytes_per_sector
        if byte_off < 0 or size < 0 or byte_off + size > vol_bytes:
            raise IndexError(f"Volume read out of range: off={byte_off:#x} size={size:#x}")
        if size == 0:
            return b""
        out = bytearray()
        cur = byte_off
        rem = size
        bps = vol.bytes_per_sector

        while rem > 0:
            sec = cur // bps
            chosen = self._find_chunk(vol, sec)
            secs_per_rec = chosen.rec_bytes // bps
            local_sec = sec - chosen.base_sec
            rec_idx = local_sec // secs_per_rec
            in_rec_off = cur - (chosen.base_sec + rec_idx * secs_per_rec) * bps
            rec_data = self._get_record_cached(vol_idx, chosen, rec_idx)
            take = min(rem, chosen.rec_bytes - in_rec_off)
            out.extend(rec_data[in_rec_off : in_rec_off + take])
            cur += take
            rem -= take
        return bytes(out)

    def read(self, offset: int, size: int) -> bytes:
        """Read arbitrary virtual disk byte range (Track-0 MBR, gaps, and volumes)."""
        if offset < 0 or size < 0:
            raise ValueError(f"Negative offset/size: offset={offset}, size={size}")
        if size == 0 or offset >= self._disk_size:
            return b""
        rem = min(size, self._disk_size - offset)
        cur = offset
        out = bytearray()
        bps = self._sector_size
        track0 = self._track0

        while rem > 0:
            if cur < len(track0):
                take = min(rem, len(track0) - cur)
                out.extend(track0[cur : cur + take])
                cur += take
                rem -= take
                continue

            sec = cur // bps
            vol = next((v for v in self.volumes if v.start_sector <= sec < v.end_sector), None)
            if vol is not None:
                vol_start_byte = vol.start_sector * bps
                vol_end_byte = vol.end_sector * bps
                take = min(rem, vol_end_byte - cur)
                out.extend(self.read_volume(vol.vol_index, cur - vol_start_byte, take))
                cur += take
                rem -= take
                continue

            next_boundaries = [v.start_sector * bps for v in self.volumes if v.start_sector * bps > cur]
            gap_end = min(next_boundaries) if next_boundaries else cur + rem
            take = min(rem, gap_end - cur)
            out.extend(b"\x00" * take)
            cur += take
            rem -= take
        return bytes(out)

    def read_sectors(self, lba: int, count: int) -> bytes:
        return self.read(lba * self._sector_size, count * self._sector_size)

    def read_block(self, block_offset: int, block_size: int = 4096) -> bytes:
        return self.read(block_offset, block_size)

    def iter_records_by_offset(self) -> List[Tuple[int, int, IndexChunk, RecordEntry]]:
        """Return all indexed data records sorted by physical .pbd file offset."""
        recs: List[Tuple[int, int, IndexChunk, RecordEntry]] = []
        for vi, vol in enumerate(self.volumes):
            for ch in vol.chunks:
                for ei, ent in enumerate(ch.entries):
                    recs.append((vi, ei, ch, ent))
        recs.sort(key=lambda item: item[3].foff_rel)
        return recs


def _print_info(reader: PbdDiskReader) -> None:
    print(f"File: {reader.path}")
    print(
        f"Native FastLZ DLL: {'ENABLED' if reader.use_native else 'DISABLED (pure Python)'} "
        f"({DEFAULT_FASTDEC_DLL})"
    )
    print(
        f"DATA_BASE={reader.data_base:#x}, algo={reader.algo}, enc_mode={reader.enc_mode}, "
        f"disk_size={reader.disk_size:,} B ({reader.disk_size / 1e9:.2f} GB)"
    )
    for vol in reader.volumes:
        print(
            f"  Volume[{vol.vol_index}]: flags={vol.flags:#x} sig={vol.disk_sig:#010x} "
            f"start_lba={vol.start_sector:#x} sectors={vol.num_sectors:#x} "
            f"track0={len(vol.track0)} B"
        )
        for ch in vol.chunks:
            print(
                f"    Chunk[{ch.chunk_idx}]: base_sec={ch.base_sec:#x}..{ch.end_sec:#x} "
                f"rec_bytes={ch.rec_bytes} unit_sz={ch.unit_sz} bmp_len={ch.bmp_len} "
                f"records={len(ch.entries):,}"
            )


def _verify_native_vs_py(reader: PbdDiskReader, sample_count: int) -> None:
    recs = reader.iter_records_by_offset()
    nonempty = [r for r in recs if r[3].comp_sz > 0 and r[3].uncomp_sz > 100]
    step = max(1, len(nonempty) // max(1, sample_count))
    picked = nonempty[::step][:sample_count]
    total_dec_bytes = 0
    t0 = time.perf_counter()
    for _vi, _ei, ch, ent in picked:
        reader.f.seek(reader.data_base + ent.foff_rel)
        raw = reader.f.read(ent.comp_sz)
        dec_c = fastlz_decompress(raw, ent.uncomp_sz, use_native=True)
        dec_py = fastlz_decompress_py(raw, ent.uncomp_sz)
        if dec_c != dec_py:
            raise AssertionError(f"C vs Python FastLZ mismatch on rec_id={ent.rec_id}")
        pay = dec_c[ch.bmp_len :]
        crc = (zlib.crc32(pay) & 0xFFFFFFFF) if pay else 0
        if crc != ent.payload_crc:
            raise AssertionError(f"CRC mismatch on rec_id={ent.rec_id}")
        total_dec_bytes += len(dec_c)
    dt_cross = time.perf_counter() - t0

    # Pure C decompression throughput benchmark (reusing in-memory raw buffers)
    raw_samples = []
    for _vi, _ei, _ch, ent in picked:
        reader.f.seek(reader.data_base + ent.foff_rel)
        raw_samples.append((reader.f.read(ent.comp_sz), ent.uncomp_sz))
    scratch = ctypes.create_string_buffer(2 * 1024 * 1024)
    t1 = time.perf_counter()
    loops = 5
    for _ in range(loops):
        for raw, usz in raw_samples:
            fastlz_decompress(raw, usz, use_native=True, out_buf=scratch)
    dt_c = time.perf_counter() - t1
    mb_s = (total_dec_bytes * loops / 1e6) / dt_c if dt_c > 0 else 0.0
    print(
        f"Verified {len(picked)} records ({total_dec_bytes / 1e6:.2f} MB) C == Python & CRC-32 OK "
        f"(cross-check {dt_cross:.2f}s; native C speed {mb_s:.1f} MB/s)"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Random-access EaseUS .pbd (IMGF v0x20000) reader")
    ap.add_argument(
        "pbd",
        nargs="?",
        default=None,
        help="Path to .pbd image (default: resolved from pbdpath.txt or PBD_PATH)",
    )
    ap.add_argument("--info", action="store_true", help="Print image geometry and chunk info")
    ap.add_argument("--pure-python", action="store_true", help="Disable native C FastLZ DLL")
    ap.add_argument("--verify-sample", type=int, default=0, help="Verify N records C vs Python & benchmark")
    ap.add_argument("--read-lba", nargs=2, type=int, metavar=("LBA", "COUNT"), help="Hexdump LBA sectors")
    args = ap.parse_args()

    try:
        with PbdDiskReader(args.pbd, use_native=not args.pure_python) as reader:
            if args.info or (args.verify_sample == 0 and args.read_lba is None):
                _print_info(reader)
            if args.verify_sample > 0:
                _verify_native_vs_py(reader, args.verify_sample)
            if args.read_lba is not None:
                lba, cnt = args.read_lba
                data = reader.read_sectors(lba, cnt)
                print(f"LBA {lba} ({cnt} sectors, {len(data)} bytes) crc32={zlib.crc32(data):#010x}")
                print(data[:128].hex())
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
