# RRextract

**Backup recovery and .RED container inspection toolkit for REDRAY media players**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![C++](https://img.shields.io/badge/C%2B%2B-17-brightgreen.svg)](reddecoder/red_decode.cpp)

RRextract is an open-source Python and C++17 toolkit that reads EaseUS .pbd (IMGF v0x20000) disk backups from REDRAY 4K Cinema Players directly on demand. It mounts the player's Linux ext3 partitions in memory to extract and SHA-256-verify preloaded .RED media packages alongside posters, XML manifests, SQLite databases, and logs, and includes a 64-bit native inspector/demuxer for .RED (RRA1 / MDT1 / BOD1) containers. For full Python CLI flag tables and module details, see [scripts/README.md](scripts/README.md).

## Requirements

### Backup Image
- **EaseUS .pbd sector-by-sector backup** of a REDRAY 4K Cinema Player internal 1 TB HDD

### Software
- **Python 3.11+**

## Setup

### Configuration

Create a pbdpath.txt file in the repository root pointing to your .pbd backup file:

```ini
# Path to your local EaseUS .pbd backup image
PBD_PATH=C:\path\to\backup.pbd
```

You can also pass a backup path directly on the command line. Use [pbd] in pbd_reader.py and --pbd <path> in the extraction scripts or set the PBD_PATH environment variable.

### Building Native Tools (Optional)

**Prerequisites**: Visual Studio 2022 with the Desktop development with C++ workload installed.

The Python scripts work out of the box using a pure-Python fallback, but running [reddecoder/build.bat](reddecoder/build.bat) enables >500 MB/s C-accelerated FastLZ decompression and builds the C++ .RED inspector red_decode.exe:

```bat
:: Build red_decode.exe (and pbd_fastdec.dll if not yet built)
reddecoder\build.bat

:: Rebuild both red_decode.exe and pbd_fastdec.dll
reddecoder\build.bat --all

:: Show build script options
reddecoder\build.bat --help
```

## Usage

1. **Inspect the backup image**
   Check the .pbd container header, virtual disk capacity, and backed-up partition volumes with [scripts/pbd_reader.py](scripts/pbd_reader.py):
   ```powershell
   python scripts\pbd_reader.py --info
   ```

2. **Extract & verify .RED media files**
   Use [scripts/extract_red_files.py](scripts/extract_red_files.py) to read the player's ext3 filesystem directly from the backup, stream all .RED files into red_files/, and verify every clip's size and SHA-256 hash against its on-disk XML manifests:
   ```powershell
   # Preview partitions and /redray directory contents without extracting
   python scripts\extract_red_files.py --inspect-fs

   # Extract all .RED files into red_files/ and write manifest_verification.json
   python scripts\extract_red_files.py
   ```

3. **Extract posters, manifests & player logs**
   Use [scripts/extract_assets.py](scripts/extract_assets.py) to extract all non-.RED files (XML manifests, SQLite databases, /etc configs, and player logs) into extracted_fs/ and export verified poster and thumbnail JPEGs into thumbnails/:
   ```powershell
   python scripts\extract_assets.py
   ```

4. **Inspect or demux .RED files**
   Examine RRA1 part structure, MDT1 metadata, and BOD1 packet statistics & and demux container boxes with red_decode.exe:
   ```powershell
   # Print per-part duration, box counts, and payload summary
   reddecoder\red_decode.exe red_files\<clip>.RED --info

   # Strictly validate RRA1 / MDT1 / BOD1 framing up to exact EOF
   reddecoder\red_decode.exe red_files\<clip>.RED --verify

   # Export JSON metadata, extract MDT1 headers, or demux BOD1 payloads
   reddecoder\red_decode.exe red_files\<clip>.RED --json
   reddecoder\red_decode.exe red_files\<clip>.RED --extract-mdt1 out_mdt1
   reddecoder\red_decode.exe red_files\<clip>.RED --demux out_demux
   ```

See [`scripts/README.md`](scripts/README.md) for all additional command-line options (`--out-dir`, `--thumbnails-dir`, `--skip-red-hash`, `--read-lba`, `--pure-python`, and more).

## REDRAY Filesystem Layout

The REDRAY uses a Linux operating system whose player binaries reside on the NAND flash, which is not user accessible. The internal 1 TB SATA HDD uses a standard MBR partition table with two ext3 volumes:

| Partition | Type | Size | Role |
| :--- | :--- | :--- | :--- |
| **Partition 1** | MBR 0x83 (ext3) | ~989.5 GB | Persistent /etc network & clock overlay and /redray catalog, logs & media packages |
| **Partition 2** | MBR 0x83 (ext3) | 10.0 GiB | Empty reserve / scratch ext3 volume |

### Directory Map (Partition 1)

```text
/
├── etc/                                     # Persistent network & timezone config overlaid onto NAND OS
│   ├── hostname                             # Player hostname
│   ├── localtime -> /usr/share/zoneinfo/... # Symlink to active POSIX timezone
│   ├── eth0_resolv.conf                     # Ethernet DNS resolver state
│   ├── wpa_supplicant.conf                  # Wi-Fi credentials & WPA supplicant config
│   └── network/                             # Interface definitions & if-up/down hooks
└── redray/                                  # Player application, catalog & media storage root
    ├── splash.red                           # Raw boot graphic blob, ~4.8 MB, non-RRA1
    ├── contentInfo.db                       # SQLite 3 catalog of installed packages & playlists
    ├── stateMgr.db                          # SQLite 3 player state, display settings & system info
    ├── certs/
    │   └── com.odemax                       # Vendor public verification certificate data
    ├── firmware/                            # Staging directory for firmware updates
    ├── scripts/
    │   ├── firmware/                        # Update discovery, verification & install *.sh scripts
    │   └── net/                             # DHCP, DNS, gateway & Wi-Fi SSID helper *.sh scripts
    ├── logs/                                # redray.log player log plus staging/ and archive/ rotation dirs
    ├── images/                              # UI artwork cache mirroring package images
    │   └── <PackageTitle>_<UUID>/
    │       ├── poster.jpg                   # 1024×540 package poster JPEG
    │       └── thumbnail.jpg                # 256×135 package thumbnail JPEG
    └── content/                             # Media packages
        ├── readme.txt
        └── <PackageTitle>_<UUID>/
            ├── manifest.xml                 # SHA-256 hashes & byte sizes of package assets
            ├── manifest.sig                 # 256-byte cryptographic signature for manifest.xml
            ├── license.xml                  # Package playback license metadata
            ├── license.sig                  # 256-byte cryptographic signature for license.xml
            ├── metadata-en.xml              # Localized title, synopsis, credits & release info
            ├── images/
            │   ├── poster.jpg               # 1024×540 package poster JPEG
            │   └── thumbnail.jpg            # 256×135 package thumbnail JPEG
            ├── playlists/
            │   └── playlist-en.xml          # Binds video_001 and audio_001 clips into a playable timeline
            └── clips/
                ├── video_001/
                │   ├── 0001.RED             # Encrypted 4K video stream with multi-part RRA1 / MDT1 / BOD1
                │   ├── clip.xml             # Video stream type & whole-file SHA-256 digest
                │   └── chunklist.xml        # Per-part RRA1 layout & total byte size
                └── audio_001/en/
                    ├── 0001.RED             # Encrypted audio stream with single-part RRA1 / MDT1 / BOD1
                    ├── clip.xml             # Audio stream type & whole-file SHA-256 digest
                    └── chunklist.xml        # Audio chunk size
```

### REDRAY Internal SQLite Databases

`contentInfo.db` (installed media catalog):
- The **contentPkgTable** table contains the columns Pkg_ID (pk), Title_ID, Vendor, Pkg_path, Synopsis, Keywords, LicenseType, LoadState.
- The **contentPlaylist** table contains the columns Pkg_ID, Playlist_ID, PlaylistPath, Title, Language, Year, Runtime, Framerate, FramerateDenom, VideoWidth, VideoHeight, Thumbnail_path, Poster_path, Playability, Disk_type, Media_path, Media_name, Media_type, Curent_tc, Director, Producers, Distributor, YearOfRelease, Genre, CastCrew, Synopsis, Region, Rating.

`stateMgr.db` (player state, picture configuration & device info):
- The **sys_info** table contains the columns PlayerPin (pk), PlayerName, SerialNum, FwVersion, OldFwVersion, Timezone.
- The **state_table** table contains the columns LoadedPkgId, LoadedPlistId, Playstate, PlaySpeed, Mute, AudioOut.
- The **picture_settings** table contains the columns Gamut, Gamma, Contrast, Brightness, Saturation, Sharpness.
- The **settings** table contains the columns Settings1, Settings2, Settings3, Settings4, Settings5, Settings6, Settings7, Settings8, Settings9, Settings10.

## About the .RED Format

The .RED file format is not .R3D (REDCODE RAW).
Package .RED files stored under /redray/content/ wrap 4096×2160 video and audio streams in a lightweight box container:

- **Multi-part RRA1 layout**: Each package .RED file consists of concatenated RRA1 parts up to exact end-of-file.
- **Metadata & media boxes**: Every RRA1 part begins with a single MDT1 metadata box followed by a contiguous stream of length-prefixed BOD1 media packet boxes.
- **Hardware-bound encryption**: Both the MDT1/BOD1 elementary stream payloads. On a REDRAY player, the Linux operating system, playback engine, and decryption keys reside on internal NAND flash rather than on the 1 TB media hard drive.

## Troubleshooting

### Can extracted .RED files be played directly in MPC-HC/VLC?

- **No.** While RRextract losslessly recovers the .RED files and parses their container framing, the inner audio & video payloads are encrypted for the REDRAY hardware. RRextract intentionally does not decrypt media streams or circumvent DRM.

### "No .pbd image path configured" error

1. Confirm pbdpath.txt exists in the repository root and contains PBD_PATH=C:\path\to\backup.pbd
2. Or pass the path explicitly with --pbd C:\path\to\backup.pbd or as a positional argument to pbd_reader.py
3. Or set the PBD_PATH environment variable in your shell

### Extraction feels slow

- Without the native C library, [scripts/pbd_reader.py](scripts/pbd_reader.py) falls back to pure-Python FastLZ decompression, which is much slower on multi-gigabyte media files.
- Run reddecoder\build.bat --all to compile reddecoder\pbd_fastdec.dll from [reddecoder/pbd_fastdec.c](reddecoder/pbd_fastdec.c) for faster decompression speeds.

### splash.red fails red_decode.exe --verify

- splash.red is a raw boot graphic blob and does not use RRA1 / MDT1 / BOD1 container headers, so --verify exits non-zero by design.
- Use reddecoder\red_decode.exe red_files\splash.red --info instead to inspect its size, byte statistics, and raw container status.

## Acknowledgments

- RED Digital Cinema for building the REDRAY
- FastLZ by Ariya Hidayat for creating the algorithm used in .pbd block decompression

## Disclaimer

This project is not affiliated with, endorsed by, or sponsored by RED Digital Cinema, EaseUS, or Odemax. REDRAY and RED are trademarks of RED Digital Cinema. All product names, trademarks, and registered trademarks are property of their respective owners.

**DMCA § 1201(f) / EU Directive 2009/24/EC Interoperability & Archival Notice**:
- Interoperability & data recovery: All format documentation and source code in this repository are the result of clean-room reverse engineering conducted solely for interoperability, legitimate data recovery, and archival preservation of user-owned hardware and user-created disk backups pursuant to 17 U.S.C. § 1201(f) and EU Directive 2009/24/EC Article 6.
- No DRM circumvention: This repository contains zero decryption keys, private keys, firmware binaries, or decryption routines. Encrypted media payloads remain encrypted exactly as stored on disk.
- No proprietary or copyrighted files: No firmware binaries, commercial backup software binaries, or copyrighted .RED media files are included in or distributed by this repository.

The source code of RRextract is fully LLM-generated.
Used models: GLM-5.3, Gemini 4 Carbon.

## Development

### Project Structure

```
RRextract/
├── scripts/
│   ├── pbd_reader.py          # .pbd block reader & CRC-32 verifier
│   ├── extract_red_files.py   # ext3 parser & SHA-256 .RED media extractor
│   ├── extract_assets.py      # Non-.RED asset, poster, DB & log extractor
│   └── README.md              # Detailed Python CLI option reference
├── reddecoder/
│   ├── red_decode.cpp         # 64-bit C++17 .RED inspector, verifier & demuxer
│   ├── pbd_fastdec.c          # Native x64 C FastLZ decompression DLL source
│   └── build.bat              # MSVC 2022 x64 build script
├── .gitignore                 # Excludes local backups, outputs & binaries
├── LICENSE                    # 3-Clause BSD License
├── README.md                  # Project overview & quickstart guide
├── pbdpath.txt                # (gitignored) Local PBD_PATH=... configuration
├── red_files/                 # (gitignored) Extracted .RED files & manifest report
├── extracted_fs/              # (gitignored) Extracted ext3 files & asset report
└── thumbnails/                # (gitignored) Exported package poster/thumbnail JPEGs
```

### Verification Checks

```powershell
# Cross-check C vs. pure-Python FastLZ decompression and record CRC-32
python scripts\pbd_reader.py --verify-sample 20

# Verify extracted .RED clips against chunklist.xml & clip.xml SHA-256 hashes
python scripts\extract_red_files.py

# Validate extracted JPEGs, XML manifests, and SQLite databases
python scripts\extract_assets.py --skip-red-hash

# Validate RRA1 / MDT1 / BOD1 framing to exact EOF on package .RED files
reddecoder\red_decode.exe red_files\<clip>.RED --verify
```

Checks verify:
- ✅ `.pbd` header, footer, index table, and per-block IEEE CRC-32 integrity
- ✅ Bit-identical output between native C pbd_fastdec.dll and pure-Python FastLZ decoders
- ✅ Exact file sizes and SHA-256 digests across extracted .RED media packages
- ✅ Valid JPEG markers, well-formed XML manifests, and PRAGMA integrity_check on SQLite databases
- ✅ Zero orphan bytes across RRA1 parts, MDT1 metadata boxes, and BOD1 packet chains

---

**Made with ❤️ for the RED community**