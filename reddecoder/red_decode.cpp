/*
 * red_decode.cpp — 64-bit streaming inspector, verifier, and demuxer for
 * RED REDRAY .RED media files (RRA1 / MDT1 / BOD1 container + raw non-RRA1).
 *
 * Verified binary layout of package .RED files:
 *   1..N concatenated RRA1 Parts up to exact EOF:
 *     +0   u32 LE  part_size       (total bytes in Part, incl. this u32)
 *     +4   4s      "RRA1"
 *     +8   u32 LE  duration_ticks  (480,000 Hz timebase)
 *     +12  u32 LE  mdt1_box_size   (total bytes of MDT1 box incl. 8B header)
 *     +16  4s      "MDT1"
 *     +20  ..      MDT1 payload    (mdt1_box_size - 8 bytes)
 *     Followed from part_offset + 12 + mdt1_box_size to part_offset + part_size
 *     by contiguous length-prefixed BOD1 boxes:
 *       +0  u32 LE bod1_box_size   (total bytes of BOD1 box incl. 8B header)
 *       +4  4s     "BOD1"
 *       +8  ..     BOD1 payload    (bod1_box_size - 8 bytes; uniform ~8.0 b/B)
 *
 *   Non-RRA1 .red files (e.g. splash.red) contain raw encrypted data without
 *   RRA1 framing.
 *
 * Usage:
 *   red_decode <file.RED> [--info] [--verify] [--json]
 *              [--extract-mdt1 <out_dir_or_file>] [--demux <outdir>]
 *
 * Exit codes:
 *   0 = success (and valid RRA1 when --verify is used)
 *   1 = usage / CLI argument error
 *   2 = structural / parse / verification error (or non-RRA1 on --verify/--demux/--extract-mdt1)
 *   3 = file I/O error
 */

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

constexpr uint32_t kTimebaseHz = 480000u;
constexpr size_t kIoBufSize = 256u * 1024u;
constexpr uint64_t kFullSampleThreshold = 8ULL * 1024ULL * 1024ULL;
constexpr uint64_t kSampleSlotsPerPart = 256ULL;
constexpr uint64_t kSamplePerSlotMax = 32ULL * 1024ULL;

struct FileGuard {
    FILE* fp = nullptr;
    FileGuard() = default;
    explicit FileGuard(FILE* f) : fp(f) {}
    ~FileGuard() {
        if (fp) {
            std::fclose(fp);
        }
    }
    FileGuard(const FileGuard&) = delete;
    FileGuard& operator=(const FileGuard&) = delete;
    void reset(FILE* f = nullptr) {
        if (fp) {
            std::fclose(fp);
        }
        fp = f;
    }
};

FILE* openFile(const fs::path& p, const char* mode) {
#ifdef _WIN32
    std::wstring wmode;
    for (const char* c = mode; *c != '\0'; ++c) {
        wmode.push_back(static_cast<wchar_t>(*c));
    }
    return _wfopen(p.c_str(), wmode.c_str());
#else
    return std::fopen(p.c_str(), mode);
#endif
}

bool seek64(FILE* f, uint64_t offset) {
    if (offset > static_cast<uint64_t>(std::numeric_limits<long long>::max())) {
        return false;
    }
#ifdef _WIN32
    return _fseeki64(f, static_cast<long long>(offset), SEEK_SET) == 0;
#else
    return fseeko(f, static_cast<off_t>(offset), SEEK_SET) == 0;
#endif
}

bool queryFileSize64(FILE* f, uint64_t& outSize) {
#ifdef _WIN32
    if (_fseeki64(f, 0, SEEK_END) != 0) {
        return false;
    }
    const long long pos = _ftelli64(f);
    if (pos < 0) {
        return false;
    }
    if (_fseeki64(f, 0, SEEK_SET) != 0) {
        return false;
    }
    outSize = static_cast<uint64_t>(pos);
    return true;
#else
    if (fseeko(f, 0, SEEK_END) != 0) {
        return false;
    }
    const off_t pos = ftello(f);
    if (pos < 0) {
        return false;
    }
    if (fseeko(f, 0, SEEK_SET) != 0) {
        return false;
    }
    outSize = static_cast<uint64_t>(pos);
    return true;
#endif
}

bool readExact(FILE* f, void* dst, size_t n) {
    if (n == 0) {
        return true;
    }
    return std::fread(dst, 1, n, f) == n;
}

bool writeExact(FILE* f, const void* src, size_t n) {
    if (n == 0) {
        return true;
    }
    return std::fwrite(src, 1, n, f) == n;
}

uint32_t readU32LE(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

double entropyFromHist(const std::array<uint64_t, 256>& hist, uint64_t total) {
    if (total == 0) {
        return 0.0;
    }
    double e = 0.0;
    const double inv = 1.0 / static_cast<double>(total);
    for (size_t i = 0; i < 256; ++i) {
        if (hist[i] == 0) {
            continue;
        }
        const double p = static_cast<double>(hist[i]) * inv;
        e -= p * std::log2(p);
    }
    return e;
}

bool accumulateHistCurrent(FILE* f, uint64_t nBytes, std::array<uint64_t, 256>& hist, std::vector<uint8_t>& buf) {
    uint64_t rem = nBytes;
    while (rem > 0) {
        const size_t chunk = static_cast<size_t>(std::min<uint64_t>(rem, buf.size()));
        if (!readExact(f, buf.data(), chunk)) {
            return false;
        }
        for (size_t i = 0; i < chunk; ++i) {
            hist[buf[i]]++;
        }
        rem -= chunk;
    }
    return true;
}

bool streamCopyCurrent(FILE* src, uint64_t nBytes, FILE* dst, std::vector<uint8_t>& buf) {
    uint64_t rem = nBytes;
    while (rem > 0) {
        const size_t chunk = static_cast<size_t>(std::min<uint64_t>(rem, buf.size()));
        if (!readExact(src, buf.data(), chunk)) {
            return false;
        }
        if (!writeExact(dst, buf.data(), chunk)) {
            return false;
        }
        rem -= chunk;
    }
    return true;
}

std::string jsonEscape(const std::string& s) {
    std::ostringstream oss;
    for (unsigned char c : s) {
        switch (c) {
            case '\"': oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b"; break;
            case '\f': oss << "\\f"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:
                if (c < 0x20) {
                    oss << "\\u00" << std::hex << std::setw(2) << std::setfill('0')
                        << static_cast<unsigned int>(c) << std::dec;
                } else {
                    oss << static_cast<char>(c);
                }
                break;
        }
    }
    return oss.str();
}

std::string formatPartFilename(size_t partIdx, const char* suffix) {
    std::ostringstream oss;
    oss << "part_" << std::setw(2) << std::setfill('0') << partIdx << suffix;
    return oss.str();
}

struct PartSummary {
    size_t index = 0;
    uint64_t offset = 0;
    uint32_t partSize = 0;
    uint32_t durationTicks = 0;
    double durationSeconds = 0.0;
    uint64_t mdt1Offset = 0;
    uint32_t mdt1BoxSize = 0;
    uint64_t mdt1PayloadOffset = 0;
    uint32_t mdt1PayloadSize = 0;
    double mdt1Entropy = 0.0;
    uint64_t bod1StartOffset = 0;
    uint64_t bod1Count = 0;
    uint64_t bod1PayloadMin = 0;
    uint64_t bod1PayloadMax = 0;
    double bod1PayloadMean = 0.0;
    uint64_t bod1PayloadTotal = 0;
    uint64_t sampledBytes = 0;
    double sampledEntropy = 0.0;
    uint64_t sampled0x1fCount = 0;
    double sampled0x1fPct = 0.0;
};

struct FileAnalysis {
    std::string filePath;
    uint64_t fileSize = 0;
    bool isRra1 = false;
    bool validRra1 = false;
    bool exactEof = false;
    uint64_t orphanBytes = 0;
    uint64_t totalDurationTicks = 0;
    double totalDurationSeconds = 0.0;
    uint64_t totalBod1Boxes = 0;
    uint64_t totalBod1PayloadBytes = 0;
    double rawEntropy = 0.0;
    uint64_t raw0x1fCount = 0;
    double raw0x1fPct = 0.0;
    std::string errorMsg;
    bool ioError = false;
    std::vector<PartSummary> parts;
};

bool analyzeFile(FILE* f, const std::string& displayPath, bool collectStats, FileAnalysis& out) {
    out = FileAnalysis{};
    out.filePath = displayPath;

    if (!queryFileSize64(f, out.fileSize)) {
        out.ioError = true;
        out.errorMsg = "failed to determine file size via 64-bit seek/tell";
        return false;
    }

    std::vector<uint8_t> ioBuf(kIoBufSize);

    if (out.fileSize < 8) {
        out.isRra1 = false;
        out.validRra1 = false;
        out.exactEof = true;
        out.errorMsg = "file smaller than 8 bytes (no RRA1 header)";
        if (collectStats && out.fileSize > 0) {
            std::array<uint64_t, 256> hist{};
            if (!seek64(f, 0) || !accumulateHistCurrent(f, out.fileSize, hist, ioBuf)) {
                out.ioError = true;
                out.errorMsg = "I/O read error";
                return false;
            }
            out.rawEntropy = entropyFromHist(hist, out.fileSize);
            out.raw0x1fCount = hist[0x1F];
            out.raw0x1fPct = 100.0 * static_cast<double>(out.raw0x1fCount) / static_cast<double>(out.fileSize);
        }
        return true;
    }

    uint8_t head8[8]{};
    if (!seek64(f, 0) || !readExact(f, head8, 8)) {
        out.ioError = true;
        out.errorMsg = "I/O error reading file header";
        return false;
    }

    if (std::memcmp(head8 + 4, "RRA1", 4) != 0) {
        out.isRra1 = false;
        out.validRra1 = false;
        out.exactEof = true;
        out.errorMsg = "missing 'RRA1' magic at offset +4";
        if (collectStats) {
            std::array<uint64_t, 256> hist{};
            if (!seek64(f, 0) || !accumulateHistCurrent(f, out.fileSize, hist, ioBuf)) {
                out.ioError = true;
                out.errorMsg = "I/O error scanning non-RRA1 file";
                return false;
            }
            out.rawEntropy = entropyFromHist(hist, out.fileSize);
            out.raw0x1fCount = hist[0x1F];
            out.raw0x1fPct = 100.0 * static_cast<double>(out.raw0x1fCount) / static_cast<double>(out.fileSize);
        }
        return true;
    }

    out.isRra1 = true;

    uint64_t partOffset = 0;
    size_t partIndex = 0;

    while (partOffset < out.fileSize) {
        const uint64_t remFile = out.fileSize - partOffset;
        if (remFile < 20) {
            out.orphanBytes = remFile;
            std::ostringstream oss;
            oss << "truncated RRA1 part #" << partIndex << " header at offset " << partOffset
                << " (" << remFile << " trailing bytes < 20)";
            out.errorMsg = oss.str();
            return false;
        }

        uint8_t ph[20]{};
        if (!seek64(f, partOffset) || !readExact(f, ph, 20)) {
            out.ioError = true;
            out.errorMsg = "I/O error reading RRA1 part header";
            return false;
        }

        const uint32_t partSize = readU32LE(ph + 0);
        const uint32_t durationTicks = readU32LE(ph + 8);
        const uint32_t mdt1BoxSize = readU32LE(ph + 12);

        if (std::memcmp(ph + 4, "RRA1", 4) != 0) {
            std::ostringstream oss;
            oss << "invalid part magic at offset " << (partOffset + 4) << " (expected 'RRA1')";
            out.errorMsg = oss.str();
            return false;
        }
        if (partSize < 20 || static_cast<uint64_t>(partSize) > remFile) {
            std::ostringstream oss;
            oss << "invalid RRA1 part #" << partIndex << " size " << partSize
                << " at offset " << partOffset << " (remaining file bytes: " << remFile << ")";
            out.errorMsg = oss.str();
            return false;
        }
        if (std::memcmp(ph + 16, "MDT1", 4) != 0) {
            std::ostringstream oss;
            oss << "invalid MDT1 magic in part #" << partIndex << " at offset " << (partOffset + 16);
            out.errorMsg = oss.str();
            return false;
        }
        if (mdt1BoxSize < 8 || 12ULL + static_cast<uint64_t>(mdt1BoxSize) > static_cast<uint64_t>(partSize)) {
            std::ostringstream oss;
            oss << "invalid MDT1 box size " << mdt1BoxSize << " in part #" << partIndex
                << " (part_size=" << partSize << ")";
            out.errorMsg = oss.str();
            return false;
        }

        PartSummary ps;
        ps.index = partIndex;
        ps.offset = partOffset;
        ps.partSize = partSize;
        ps.durationTicks = durationTicks;
        ps.durationSeconds = static_cast<double>(durationTicks) / static_cast<double>(kTimebaseHz);
        ps.mdt1Offset = partOffset + 12ULL;
        ps.mdt1BoxSize = mdt1BoxSize;
        ps.mdt1PayloadOffset = partOffset + 20ULL;
        ps.mdt1PayloadSize = mdt1BoxSize - 8u;
        ps.bod1StartOffset = partOffset + 12ULL + static_cast<uint64_t>(mdt1BoxSize);

        if (collectStats && ps.mdt1PayloadSize > 0) {
            std::array<uint64_t, 256> mdtHist{};
            if (!accumulateHistCurrent(f, ps.mdt1PayloadSize, mdtHist, ioBuf)) {
                out.ioError = true;
                out.errorMsg = "I/O error reading MDT1 payload";
                return false;
            }
            ps.mdt1Entropy = entropyFromHist(mdtHist, ps.mdt1PayloadSize);
        }

        const uint64_t partEnd = partOffset + static_cast<uint64_t>(partSize);
        const uint64_t bodRegionBytes = partEnd - ps.bod1StartOffset;
        const bool sampleAll = bodRegionBytes <= kFullSampleThreshold;
        const uint64_t slotStep = (bodRegionBytes > kSampleSlotsPerPart)
                                      ? (bodRegionBytes / kSampleSlotsPerPart)
                                      : 1ULL;
        uint64_t nextSampleOffset = ps.bod1StartOffset;
        std::array<uint64_t, 256> bodHist{};

        uint64_t bodPos = ps.bod1StartOffset;
        while (bodPos < partEnd) {
            const uint64_t remPart = partEnd - bodPos;
            if (remPart < 8) {
                out.orphanBytes = remPart;
                std::ostringstream oss;
                oss << "orphan " << remPart << " bytes at end of part #" << partIndex
                    << " offset " << bodPos;
                out.errorMsg = oss.str();
                return false;
            }

            uint8_t bh[8]{};
            if (!seek64(f, bodPos) || !readExact(f, bh, 8)) {
                out.ioError = true;
                out.errorMsg = "I/O error reading BOD1 header";
                return false;
            }

            const uint32_t bodBoxSize = readU32LE(bh + 0);
            if (std::memcmp(bh + 4, "BOD1", 4) != 0) {
                std::ostringstream oss;
                oss << "invalid BOD1 magic in part #" << partIndex << " box #" << ps.bod1Count
                    << " at offset " << (bodPos + 4);
                out.errorMsg = oss.str();
                return false;
            }
            if (bodBoxSize < 8 || static_cast<uint64_t>(bodBoxSize) > remPart) {
                std::ostringstream oss;
                oss << "invalid BOD1 box size " << bodBoxSize << " in part #" << partIndex
                    << " box #" << ps.bod1Count << " at offset " << bodPos
                    << " (remaining part bytes: " << remPart << ")";
                out.errorMsg = oss.str();
                return false;
            }

            const uint64_t payloadSize = static_cast<uint64_t>(bodBoxSize - 8u);
            if (ps.bod1Count == 0 || payloadSize < ps.bod1PayloadMin) {
                ps.bod1PayloadMin = payloadSize;
            }
            if (payloadSize > ps.bod1PayloadMax) {
                ps.bod1PayloadMax = payloadSize;
            }
            ps.bod1PayloadTotal += payloadSize;
            ps.bod1Count++;

            if (collectStats && payloadSize > 0) {
                const uint64_t boxEnd = bodPos + static_cast<uint64_t>(bodBoxSize);
                if (sampleAll) {
                    if (!accumulateHistCurrent(f, payloadSize, bodHist, ioBuf)) {
                        out.ioError = true;
                        out.errorMsg = "I/O error sampling BOD1 payload";
                        return false;
                    }
                    ps.sampledBytes += payloadSize;
                } else if (boxEnd > nextSampleOffset) {
                    const uint64_t take = std::min<uint64_t>(payloadSize, kSamplePerSlotMax);
                    if (!accumulateHistCurrent(f, take, bodHist, ioBuf)) {
                        out.ioError = true;
                        out.errorMsg = "I/O error sampling BOD1 payload";
                        return false;
                    }
                    ps.sampledBytes += take;
                    while (nextSampleOffset <= boxEnd) {
                        if (nextSampleOffset > std::numeric_limits<uint64_t>::max() - slotStep) {
                            nextSampleOffset = std::numeric_limits<uint64_t>::max();
                            break;
                        }
                        nextSampleOffset += slotStep;
                    }
                }
            }

            bodPos += static_cast<uint64_t>(bodBoxSize);
        }

        if (ps.bod1Count > 0) {
            ps.bod1PayloadMean = static_cast<double>(ps.bod1PayloadTotal) / static_cast<double>(ps.bod1Count);
        }
        if (collectStats && ps.sampledBytes > 0) {
            ps.sampledEntropy = entropyFromHist(bodHist, ps.sampledBytes);
            ps.sampled0x1fCount = bodHist[0x1F];
            ps.sampled0x1fPct = 100.0 * static_cast<double>(ps.sampled0x1fCount) / static_cast<double>(ps.sampledBytes);
        }

        out.totalDurationTicks += static_cast<uint64_t>(ps.durationTicks);
        out.totalBod1Boxes += ps.bod1Count;
        out.totalBod1PayloadBytes += ps.bod1PayloadTotal;
        out.parts.push_back(ps);

        partOffset = partEnd;
        partIndex++;
    }

    if (out.parts.empty() || partOffset != out.fileSize) {
        out.orphanBytes = (out.fileSize >= partOffset) ? (out.fileSize - partOffset) : 0;
        out.errorMsg = "file did not terminate on exact RRA1 part boundary";
        return false;
    }

    out.totalDurationSeconds = static_cast<double>(out.totalDurationTicks) / static_cast<double>(kTimebaseHz);
    out.validRra1 = true;
    out.exactEof = true;
    out.orphanBytes = 0;
    return true;
}

bool extractMdt1(
    FILE* src,
    const FileAnalysis& info,
    const fs::path& outArg,
    const std::string& rawOutArg,
    std::vector<std::string>& writtenPaths,
    std::string& errMsg
) {
    if (!info.isRra1 || !info.validRra1) {
        errMsg = "cannot extract MDT1: file is not a valid RRA1 container";
        return false;
    }

    std::error_code ec;
    const bool trailingSep = !rawOutArg.empty() && (rawOutArg.back() == '/' || rawOutArg.back() == '\\');
    const bool exists = fs::exists(outArg, ec);
    const bool isDirExisting = exists && fs::is_directory(outArg, ec);
    const bool singleFileMode =
        (info.parts.size() == 1) &&
        !isDirExisting &&
        !trailingSep &&
        ((exists && fs::is_regular_file(outArg, ec)) || outArg.has_extension());

    std::vector<uint8_t> ioBuf(kIoBufSize);

    if (singleFileMode) {
        const fs::path parent = outArg.parent_path();
        if (!parent.empty()) {
            fs::create_directories(parent, ec);
            if (ec) {
                errMsg = "failed to create parent directory: " + ec.message();
                return false;
            }
        }
        FileGuard outF(openFile(outArg, "wb"));
        if (!outF.fp) {
            errMsg = "cannot open output file for writing: " + outArg.string();
            return false;
        }
        const PartSummary& p = info.parts[0];
        if (!seek64(src, p.mdt1PayloadOffset) || !streamCopyCurrent(src, p.mdt1PayloadSize, outF.fp, ioBuf)) {
            errMsg = "I/O error writing MDT1 payload";
            return false;
        }
        writtenPaths.push_back(outArg.string());
        return true;
    }

    if (exists && !isDirExisting) {
        errMsg = "output path exists and is not a directory: " + outArg.string();
        return false;
    }
    fs::create_directories(outArg, ec);
    if (ec) {
        errMsg = "failed to create output directory: " + ec.message();
        return false;
    }

    for (const PartSummary& p : info.parts) {
        const fs::path dest = outArg / formatPartFilename(p.index, "_mdt1.bin");
        FileGuard outF(openFile(dest, "wb"));
        if (!outF.fp) {
            errMsg = "cannot open MDT1 output file: " + dest.string();
            return false;
        }
        if (!seek64(src, p.mdt1PayloadOffset) || !streamCopyCurrent(src, p.mdt1PayloadSize, outF.fp, ioBuf)) {
            errMsg = "I/O error writing MDT1 payload for part " + std::to_string(p.index);
            return false;
        }
        writtenPaths.push_back(dest.string());
    }
    return true;
}

bool demuxFile(
    FILE* src,
    const FileAnalysis& info,
    const fs::path& outDir,
    std::vector<std::string>& writtenPaths,
    std::string& errMsg
) {
    if (!info.isRra1 || !info.validRra1) {
        errMsg = "cannot demux: file is not a valid RRA1 container";
        return false;
    }

    std::error_code ec;
    if (fs::exists(outDir, ec) && !fs::is_directory(outDir, ec)) {
        errMsg = "demux output path exists and is not a directory: " + outDir.string();
        return false;
    }
    fs::create_directories(outDir, ec);
    if (ec) {
        errMsg = "failed to create demux directory: " + ec.message();
        return false;
    }

    std::vector<uint8_t> ioBuf(kIoBufSize);

    for (const PartSummary& p : info.parts) {
        const fs::path mdtPath = outDir / formatPartFilename(p.index, "_mdt1.bin");
        const fs::path csvPath = outDir / formatPartFilename(p.index, "_bod1.csv");
        const fs::path binPath = outDir / formatPartFilename(p.index, "_payloads.bin");

        {
            FileGuard mdtF(openFile(mdtPath, "wb"));
            if (!mdtF.fp) {
                errMsg = "cannot open " + mdtPath.string();
                return false;
            }
            if (!seek64(src, p.mdt1PayloadOffset) || !streamCopyCurrent(src, p.mdt1PayloadSize, mdtF.fp, ioBuf)) {
                errMsg = "I/O error writing " + mdtPath.string();
                return false;
            }
        }
        writtenPaths.push_back(mdtPath.string());

        FileGuard csvF(openFile(csvPath, "wb"));
        FileGuard binF(openFile(binPath, "wb"));
        if (!csvF.fp || !binF.fp) {
            errMsg = "cannot open demux outputs in " + outDir.string();
            return false;
        }
        if (std::fprintf(csvF.fp, "box_index,file_offset,box_size,payload_size\n") < 0) {
            errMsg = "I/O error writing CSV header";
            return false;
        }

        if (!seek64(src, p.bod1StartOffset)) {
            errMsg = "I/O error seeking to BOD1 stream";
            return false;
        }

        const uint64_t partEnd = p.offset + static_cast<uint64_t>(p.partSize);
        uint64_t bodPos = p.bod1StartOffset;
        uint64_t boxIdx = 0;

        while (bodPos < partEnd) {
            uint8_t bh[8]{};
            if (!readExact(src, bh, 8)) {
                errMsg = "I/O error reading BOD1 header during demux";
                return false;
            }
            const uint32_t bodBoxSize = readU32LE(bh + 0);
            if (std::memcmp(bh + 4, "BOD1", 4) != 0 || bodBoxSize < 8 ||
                bodPos + static_cast<uint64_t>(bodBoxSize) > partEnd) {
                errMsg = "unexpected BOD1 corruption during demux";
                return false;
            }
            const uint32_t payloadSize = bodBoxSize - 8u;
            if (std::fprintf(csvF.fp, "%llu,%llu,%u,%u\n",
                             static_cast<unsigned long long>(boxIdx),
                             static_cast<unsigned long long>(bodPos),
                             bodBoxSize,
                             payloadSize) < 0) {
                errMsg = "I/O error writing CSV row";
                return false;
            }
            if (!streamCopyCurrent(src, payloadSize, binF.fp, ioBuf)) {
                errMsg = "I/O error streaming BOD1 payload";
                return false;
            }
            bodPos += static_cast<uint64_t>(bodBoxSize);
            boxIdx++;
        }

        writtenPaths.push_back(csvPath.string());
        writtenPaths.push_back(binPath.string());
    }

    return true;
}

void printHumanInfo(const FileAnalysis& info) {
    const double mib = static_cast<double>(info.fileSize) / (1024.0 * 1024.0);
    std::printf("File        : %s\n", info.filePath.c_str());
    std::printf("Size        : %llu bytes (%.2f MiB)\n",
                static_cast<unsigned long long>(info.fileSize), mib);

    if (!info.isRra1) {
        std::printf("Format      : raw encrypted .red (non-RRA1; no RRA1 header at +4)\n");
        if (info.fileSize > 0) {
            std::printf("Entropy     : %.6f bits/byte (full file: %llu bytes)\n",
                        info.rawEntropy, static_cast<unsigned long long>(info.fileSize));
            std::printf("0x1F rate   : %llu bytes (%.4f%%)\n",
                        static_cast<unsigned long long>(info.raw0x1fCount), info.raw0x1fPct);
        }
        std::printf("RRA1 framing: absent (non-RRA1)\n");
        return;
    }

    std::printf("Format      : RRA1 %s container\n",
                info.parts.size() > 1 ? "multi-part" : "single-part");
    std::printf("Parts       : %zu\n", info.parts.size());
    std::printf("Duration    : %llu ticks (%.3f s @ %u Hz)\n",
                static_cast<unsigned long long>(info.totalDurationTicks),
                info.totalDurationSeconds,
                kTimebaseHz);
    std::printf("Total BOD1  : %llu boxes (%llu payload bytes)\n",
                static_cast<unsigned long long>(info.totalBod1Boxes),
                static_cast<unsigned long long>(info.totalBod1PayloadBytes));
    if (info.validRra1 && info.exactEof) {
        std::printf("Integrity   : VALID (exact EOF, 0 orphan bytes)\n");
    } else {
        std::printf("Integrity   : INVALID (%s)\n", info.errorMsg.c_str());
    }

    for (const PartSummary& p : info.parts) {
        std::printf("\nPart %02zu: offset=%llu (0x%llX) size=%u duration=%u ticks (%.3f s)\n",
                    p.index,
                    static_cast<unsigned long long>(p.offset),
                    static_cast<unsigned long long>(p.offset),
                    p.partSize,
                    p.durationTicks,
                    p.durationSeconds);
        std::printf("  MDT1 : offset=%llu box_size=%u payload_size=%u entropy=%.6f bits/byte\n",
                    static_cast<unsigned long long>(p.mdt1Offset),
                    p.mdt1BoxSize,
                    p.mdt1PayloadSize,
                    p.mdt1Entropy);
        std::printf("  BOD1 : start=%llu count=%llu payload=[min=%llu, max=%llu, mean=%.1f] total=%llu\n",
                    static_cast<unsigned long long>(p.bod1StartOffset),
                    static_cast<unsigned long long>(p.bod1Count),
                    static_cast<unsigned long long>(p.bod1PayloadMin),
                    static_cast<unsigned long long>(p.bod1PayloadMax),
                    p.bod1PayloadMean,
                    static_cast<unsigned long long>(p.bod1PayloadTotal));
        std::printf("         sampled=%llu B entropy=%.6f bits/byte 0x1F=%llu (%.4f%%)\n",
                    static_cast<unsigned long long>(p.sampledBytes),
                    p.sampledEntropy,
                    static_cast<unsigned long long>(p.sampled0x1fCount),
                    p.sampled0x1fPct);
    }
}

void printJson(const FileAnalysis& info, const std::vector<std::string>& mdt1Files, const std::vector<std::string>& demuxFiles) {
    std::ostringstream oss;
    oss << std::fixed;
    oss << "{\n";
    oss << "  \"file\": \"" << jsonEscape(info.filePath) << "\",\n";
    oss << "  \"file_size\": " << info.fileSize << ",\n";
    oss << "  \"format\": \"" << (info.isRra1 ? "rra1" : "raw_non_rra1") << "\",\n";
    oss << "  \"is_rra1\": " << (info.isRra1 ? "true" : "false") << ",\n";
    oss << "  \"valid_rra1\": " << (info.validRra1 ? "true" : "false") << ",\n";
    oss << "  \"exact_eof\": " << (info.exactEof ? "true" : "false") << ",\n";
    oss << "  \"orphan_bytes\": " << info.orphanBytes << ",\n";
    oss << "  \"timebase_hz\": " << kTimebaseHz << ",\n";
    oss << "  \"part_count\": " << info.parts.size() << ",\n";
    if (!info.isRra1) {
        oss << "  \"entropy_bpb\": " << std::setprecision(6) << info.rawEntropy << ",\n";
        oss << "  \"byte_0x1f_count\": " << info.raw0x1fCount << ",\n";
        oss << "  \"byte_0x1f_pct\": " << std::setprecision(4) << info.raw0x1fPct << ",\n";
    } else {
        oss << "  \"total_duration_ticks\": " << info.totalDurationTicks << ",\n";
        oss << "  \"total_duration_seconds\": " << std::setprecision(6) << info.totalDurationSeconds << ",\n";
        oss << "  \"total_bod1_boxes\": " << info.totalBod1Boxes << ",\n";
        oss << "  \"total_bod1_payload_bytes\": " << info.totalBod1PayloadBytes << ",\n";
    }
    if (info.errorMsg.empty()) {
        oss << "  \"error\": null,\n";
    } else {
        oss << "  \"error\": \"" << jsonEscape(info.errorMsg) << "\",\n";
    }
    if (!mdt1Files.empty()) {
        oss << "  \"extracted_mdt1\": [";
        for (size_t i = 0; i < mdt1Files.size(); ++i) {
            if (i > 0) oss << ", ";
            oss << "\"" << jsonEscape(mdt1Files[i]) << "\"";
        }
        oss << "],\n";
    }
    if (!demuxFiles.empty()) {
        oss << "  \"demux_files\": [";
        for (size_t i = 0; i < demuxFiles.size(); ++i) {
            if (i > 0) oss << ", ";
            oss << "\"" << jsonEscape(demuxFiles[i]) << "\"";
        }
        oss << "],\n";
    }
    oss << "  \"parts\": [";
    if (!info.parts.empty()) {
        oss << "\n";
        for (size_t i = 0; i < info.parts.size(); ++i) {
            const PartSummary& p = info.parts[i];
            oss << "    {\n";
            oss << "      \"part_index\": " << p.index << ",\n";
            oss << "      \"offset\": " << p.offset << ",\n";
            oss << "      \"part_size\": " << p.partSize << ",\n";
            oss << "      \"duration_ticks\": " << p.durationTicks << ",\n";
            oss << "      \"duration_seconds\": " << std::setprecision(6) << p.durationSeconds << ",\n";
            oss << "      \"mdt1_offset\": " << p.mdt1Offset << ",\n";
            oss << "      \"mdt1_box_size\": " << p.mdt1BoxSize << ",\n";
            oss << "      \"mdt1_payload_offset\": " << p.mdt1PayloadOffset << ",\n";
            oss << "      \"mdt1_payload_size\": " << p.mdt1PayloadSize << ",\n";
            oss << "      \"mdt1_entropy_bpb\": " << std::setprecision(6) << p.mdt1Entropy << ",\n";
            oss << "      \"bod1_start_offset\": " << p.bod1StartOffset << ",\n";
            oss << "      \"bod1_box_count\": " << p.bod1Count << ",\n";
            oss << "      \"bod1_payload_min\": " << p.bod1PayloadMin << ",\n";
            oss << "      \"bod1_payload_max\": " << p.bod1PayloadMax << ",\n";
            oss << "      \"bod1_payload_mean\": " << std::setprecision(2) << p.bod1PayloadMean << ",\n";
            oss << "      \"bod1_payload_total\": " << p.bod1PayloadTotal << ",\n";
            oss << "      \"sampled_payload_bytes\": " << p.sampledBytes << ",\n";
            oss << "      \"sampled_entropy_bpb\": " << std::setprecision(6) << p.sampledEntropy << ",\n";
            oss << "      \"sampled_0x1f_count\": " << p.sampled0x1fCount << ",\n";
            oss << "      \"sampled_0x1f_pct\": " << std::setprecision(4) << p.sampled0x1fPct << "\n";
            oss << "    }" << (i + 1 < info.parts.size() ? "," : "") << "\n";
        }
        oss << "  ";
    }
    oss << "]\n";
    oss << "}\n";
    std::fwrite(oss.str().data(), 1, oss.str().size(), stdout);
}

void printUsage(FILE* stream) {
    std::fprintf(
        stream,
        "Usage: red_decode <file.RED> [--info] [--verify] [--json]\n"
        "                  [--extract-mdt1 <out_dir_or_file>] [--demux <outdir>]\n"
        "\n"
        "Options:\n"
        "  --info                  Print RRA1/MDT1/BOD1 (or raw non-RRA1) summary (default)\n"
        "  --verify                Strictly validate RRA1 parts, MDT1 box, and BOD1 boxes to exact EOF\n"
        "  --json                  Emit machine-readable JSON output to stdout\n"
        "  --extract-mdt1 <path>   Extract MDT1 payload (file for 1 part if file path, else part_XX_mdt1.bin)\n"
        "  --demux <outdir>        Stream part_XX_mdt1.bin, part_XX_bod1.csv, and part_XX_payloads.bin\n"
        "  -h, --help              Show this help message\n"
    );
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        printUsage(stderr);
        return 1;
    }

    bool doInfo = false;
    bool doVerify = false;
    bool doJson = false;
    bool doExtractMdt1 = false;
    bool doDemux = false;
    std::string inputPathStr;
    std::string mdt1OutStr;
    std::string demuxOutStr;

    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];
        if (std::strcmp(arg, "-h") == 0 || std::strcmp(arg, "--help") == 0) {
            printUsage(stdout);
            return 0;
        } else if (std::strcmp(arg, "--info") == 0) {
            doInfo = true;
        } else if (std::strcmp(arg, "--verify") == 0) {
            doVerify = true;
        } else if (std::strcmp(arg, "--json") == 0) {
            doJson = true;
        } else if (std::strcmp(arg, "--extract-mdt1") == 0) {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "red_decode: --extract-mdt1 requires a path argument\n");
                return 1;
            }
            doExtractMdt1 = true;
            mdt1OutStr = argv[++i];
        } else if (std::strcmp(arg, "--demux") == 0) {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "red_decode: --demux requires an output directory argument\n");
                return 1;
            }
            doDemux = true;
            demuxOutStr = argv[++i];
        } else if (arg[0] == '-') {
            std::fprintf(stderr, "red_decode: unknown option '%s'\n", arg);
            return 1;
        } else if (inputPathStr.empty()) {
            inputPathStr = arg;
        } else {
            std::fprintf(stderr, "red_decode: unexpected positional argument '%s'\n", arg);
            return 1;
        }
    }

    if (inputPathStr.empty()) {
        std::fprintf(stderr, "red_decode: missing <file.RED> argument\n");
        printUsage(stderr);
        return 1;
    }

    if (!doInfo && !doVerify && !doJson && !doExtractMdt1 && !doDemux) {
        doInfo = true;
    }

    const fs::path inputPath(inputPathStr);
    FileGuard src(openFile(inputPath, "rb"));
    if (!src.fp) {
        std::fprintf(stderr, "red_decode: cannot open '%s'\n", inputPathStr.c_str());
        return 3;
    }

    const bool needStats = doInfo || doJson;
    FileAnalysis analysis;
    const bool parsedOk = analyzeFile(src.fp, inputPathStr, needStats, analysis);
    if (analysis.ioError) {
        std::fprintf(stderr, "red_decode: I/O error on '%s': %s\n",
                     inputPathStr.c_str(), analysis.errorMsg.c_str());
        return 3;
    }

    std::vector<std::string> mdt1Written;
    std::vector<std::string> demuxWritten;

    if (doExtractMdt1) {
        std::string errMsg;
        if (!extractMdt1(src.fp, analysis, fs::path(mdt1OutStr), mdt1OutStr, mdt1Written, errMsg)) {
            std::fprintf(stderr, "red_decode: %s\n", errMsg.c_str());
            return analysis.validRra1 ? 3 : 2;
        }
    }

    if (doDemux) {
        std::string errMsg;
        if (!demuxFile(src.fp, analysis, fs::path(demuxOutStr), demuxWritten, errMsg)) {
            std::fprintf(stderr, "red_decode: %s\n", errMsg.c_str());
            return analysis.validRra1 ? 3 : 2;
        }
    }

    if (doJson) {
        printJson(analysis, mdt1Written, demuxWritten);
    } else {
        if (doInfo) {
            printHumanInfo(analysis);
        }
        if (doVerify && !doInfo) {
            if (analysis.validRra1) {
                std::printf("VERIFY OK: %s (%llu bytes, %zu part(s), %llu BOD1 box(es), 0 orphan bytes)\n",
                            analysis.filePath.c_str(),
                            static_cast<unsigned long long>(analysis.fileSize),
                            analysis.parts.size(),
                            static_cast<unsigned long long>(analysis.totalBod1Boxes));
            } else {
                std::fprintf(stderr, "VERIFY FAILED: %s (%s)\n",
                             analysis.filePath.c_str(), analysis.errorMsg.c_str());
            }
        }
        if (doExtractMdt1) {
            for (const auto& p : mdt1Written) {
                std::printf("Extracted MDT1 -> %s\n", p.c_str());
            }
        }
        if (doDemux) {
            std::printf("Demuxed %zu part(s) (%llu BOD1 boxes) -> %s\n",
                        analysis.parts.size(),
                        static_cast<unsigned long long>(analysis.totalBod1Boxes),
                        demuxOutStr.c_str());
        }
    }

    if (doVerify) {
        return analysis.validRra1 ? 0 : 2;
    }
    if (analysis.isRra1 && !parsedOk) {
        if (!doInfo && !doJson) {
            std::fprintf(stderr, "red_decode: parse error: %s\n", analysis.errorMsg.c_str());
        }
        return 2;
    }
    return 0;
}
