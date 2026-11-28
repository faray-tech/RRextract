# `scripts/` — Python Tooling Reference

Standalone Python 3.9+ tools (standard library only) for indexed $O(1)$ random-access reading, `ext3` filesystem traversal, extraction, and SHA-256 verification of EaseUS `.pbd` (`IMGF v0x20000`) REDRAY HDD backup images without unpacking a 1 TB raw disk image.

See the root [`README.md`](../README.md) for the full `IMGF v0x20000` and `.RED` (`RRA1` / `MDT1` / `BOD1`) binary format specifications and legal/interoperability notice.

---

## Configuring the `.pbd` Image Path (`pbdpath.txt`)

All three scripts resolve the source `.pbd` backup image via `resolve_pbd_path()` in [`pbd_reader.py`](pbd_reader.py) using the following precedence order:

1. **CLI path argument**: positional `[pbd]` in `pbd_reader.py`, or `--pbd <path>` in `extract_red_files.py` and `extract_assets.py`.
2. **Repository-root `pbdpath.txt`** (ignored by [`.gitignore`](../.gitignore)): create `pbdpath.txt` in the repository root with:
   ```ini
   # Local path to your EaseUS .pbd disk backup image
   PBD_PATH=C:\path\to\backup.pbd
   ```
   Blank lines and `#` comments are ignored; surrounding quotes, `%VAR%` / `$VAR` environment variables, `~`, and repository-relative paths are expanded automatically.
3. **`PBD_PATH` environment variable**: used when neither a CLI argument nor `pbdpath.txt` is supplied.

If no `.pbd` path is configured, the CLI exits cleanly with code `1` and an instructions message on `stderr` (`--help` always works without `pbdpath.txt`).

---

## 1. [`pbd_reader.py`](pbd_reader.py) — Indexed $O(1)$ EaseUS `.pbd` (`IMGF v0x20000`) Reader

Provides `PbdDiskReader` for arbitrary virtual-disk byte and sector reads (`read(offset, size)`, `read_sectors(lba, count)`, `read_block(offset, size)`) over EaseUS `IMGF v0x20000` (`DsImgFile.dll`) backup images.

- **Container parsing & CRC verification**: Validates masked IEEE CRC-32 checksums across the forward `IMGF` header (`0x0000..0x052C`), reversed `IMGF` footer, compressed `HMGF` / `GMGF` volume trees, `VOLM` (`0x400000`) geometry, `Track-0` (`0x400100`, `32,256` B), `0x400001` FastLZ index chunk tables, and per-record payload CRC-32 after splitting the 1-byte sparse bitmap (`dec[:1]`).
- **FastLZ decompression**: Automatically loads `reddecoder/pbd_fastdec.dll` (built from [`../reddecoder/pbd_fastdec.c`](../reddecoder/pbd_fastdec.c) via [`../reddecoder/build.bat`](../reddecoder/build.bat)) via `ctypes` for `>500 MB/s` native x64 decompression when present, falling back transparently to pure-Python `fastlz_decompress_py()`. Also supports stored/zlib/LZ4/Zstd block modes where optional modules are installed.

### CLI Usage

```powershell
python scripts\pbd_reader.py [pbd] [--info] [--pure-python] [--verify-sample N] [--read-lba LBA COUNT]
```

| Option | Description |
|---|---|
| `pbd` | Optional path to `.pbd` image (default: resolved from `pbdpath.txt` or `PBD_PATH`). |
| `--info` | Print `DATA_BASE`, compression/encryption modes, virtual disk size, volume geometry, and index chunks (default when no other action flag is given). |
| `--pure-python` | Disable `pbd_fastdec.dll` and force pure-Python FastLZ decompression. |
| `--verify-sample N` | Cross-check `N` non-empty records (`C == Python` and IEEE CRC-32) and benchmark native C throughput. |
| `--read-lba LBA COUNT` | Read `COUNT` 512-byte virtual sectors starting at `LBA`, printing CRC-32 and a 128-byte hex preview. |

---

## 2. [`extract_red_files.py`](extract_red_files.py) — `ext3` `.RED` Extractor & SHA-256 Verifier

Mounts Linux `ext2`/`ext3`/`ext4` partitions directly over `PbdDiskReader` and streams `.RED` media files to disk with on-the-fly SHA-256 verification.

- **Partition & filesystem engine**: `parse_partitions()` supports MBR, MBR-EBR logical chains, and GPT; `Ext3Filesystem` resolves directory trees and `i_block[0..14]` direct, single-, double-, and triple-indirect block pointers as well as sparse holes and `ext4` extents (avoiding the 4 KiB indirect-block corruption caused by raw contiguous sector carving).
- **Manifest verification**: Parses `chunklist.xml` and `clip.xml` under `/redray`, writes collision-free filenames (`content__<Package>__...__0001.RED` plus `splash.red`) into `red_files/`, verifies package sizes and SHA-256 digests (`12/12` package clips + `splash.red`), and writes `red_files/manifest_verification.json`.

### CLI Usage

```powershell
python scripts\extract_red_files.py [--pbd PBD] [--out-dir OUT_DIR] [--start-dir START_DIR] [--inspect-fs] [--dump-xml-dir DIR] [--keep-old]
```

| Option | Description |
|---|---|
| `--pbd PBD` | Path to `.pbd` image (default: resolved from `pbdpath.txt` or `PBD_PATH`). |
| `--out-dir OUT_DIR` | Output directory for `.RED` files and `manifest_verification.json` (default: `red_files/`). |
| `--start-dir START_DIR` | Root `ext3` directory path to walk (default: `/redray`). |
| `--inspect-fs` | Read-only mode: print partitions, top-level `/` entries, and walk `START_DIR` without extracting `.RED` files. |
| `--dump-xml-dir DIR` | Optional local directory to write decoded `.xml` manifests during `--inspect-fs`. |
| `--keep-old` | Keep pre-existing non-matching `.RED` files in `--out-dir` instead of pruning them after successful verification. |

---

## 3. [`extract_assets.py`](extract_assets.py) — Non-`.RED` Filesystem Extractor & Validator

Reuses `PbdDiskReader`, `parse_partitions()`, and `Ext3Filesystem` to extract and validate every non-`.RED` file across all `ext3` partitions into `extracted_fs/` and export verified package artwork into `thumbnails/`.

- **Extraction**: Streams all non-`.RED` regular files (preserving POSIX directory hierarchy under `extracted_fs/`), skips `.RED` media files, and records symlinks in JSON without requiring elevated Windows symlink privileges.
- **Validation & report**: Writes `extracted_fs/asset_verification.json` verifying JPEG markers (`FF D8..FF D9` + dimensions), XML well-formedness (`xml.etree.ElementTree`), SQLite database integrity (`PRAGMA integrity_check = ok`), `manifest.xml` SHA-256 hashes (raw JPEGs + CRLF→LF-normalized XMLs), `/redray/images/<pkg>` mirror equality, `chunklist.xml` / `clip.xml` cross-checks against `red_files/`, and clean artwork copies in `thumbnails/` (`<PackageDir>__poster.jpg` & `<PackageDir>__thumbnail.jpg`).

### CLI Usage

```powershell
python scripts\extract_assets.py [--pbd PBD] [--out-dir OUT_DIR] [--thumbnails-dir THUMBNAILS_DIR] [--red-dir RED_DIR] [--json-out JSON_OUT] [--keep-old-thumbnails] [--skip-red-hash] [--pure-python]
```

| Option | Description |
|---|---|
| `--pbd PBD` | Path to `.pbd` disk image (default: resolved from `pbdpath.txt` or `PBD_PATH`). |
| `--out-dir OUT_DIR` | Output root for extracted filesystem tree (default: `extracted_fs/`). |
| `--thumbnails-dir THUMBNAILS_DIR` | Output directory for clean package poster & thumbnail JPEGs (default: `thumbnails/`). |
| `--red-dir RED_DIR` | Directory containing extracted `.RED` files for chunklist cross-checking (default: `red_files/`). |
| `--json-out JSON_OUT` | Verification report path (default: `<out-dir>/asset_verification.json`). |
| `--keep-old-thumbnails` | Do not delete pre-existing files in `thumbnails/`. |
| `--skip-red-hash` | Skip re-hashing extracted `.RED` files in `red_files/` during chunklist checks. |
| `--pure-python` | Disable `pbd_fastdec.dll` and use pure-Python FastLZ decompression. |

---

## Credits

- **FastLZ** by **Ariya Hidayat** ([https://github.com/ariya/FastLZ](https://github.com/ariya/FastLZ) / [https://ariya.github.io/FastLZ/](https://ariya.github.io/FastLZ/), **MIT License**) — FastLZ Level 1 / Level 2 compression format and algorithm implemented in [`pbd_reader.py`](pbd_reader.py) and [`../reddecoder/pbd_fastdec.c`](../reddecoder/pbd_fastdec.c).
