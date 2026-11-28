/*
 * pbd_fastdec.c - Native x64 FastLZ Level 1 / Level 2 decompressor for EaseUS
 * .pbd (IMGF v0x20000) raw compressed record streams.
 *
 * Compression format & algorithm credit:
 *   FastLZ - lightning-fast lossless compression library
 *   Copyright (C) Ariya Hidayat (https://ariya.github.io/FastLZ/ /
 *   https://github.com/ariya/FastLZ), licensed under the MIT License.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

/*
 * Decompresses a raw FastLZ Level 1 or Level 2 stream.
 * Returns decompressed byte count on success (>= 0), or negative error code.
 */
EXPORT int64_t fastlz_dec(
    const uint8_t* src,
    size_t src_len,
    uint8_t* dst,
    size_t dst_cap
) {
    if (src_len == 0) {
        return 0;
    }
    if (!src || !dst) {
        return -1;
    }

    uint32_t level = (uint32_t)(src[0] >> 5) + 1u;
    if (level != 1u && level != 2u) {
        return -2;
    }

    size_t ip = 0;
    size_t op = 0;
    uint32_t ctrl = (uint32_t)(src[ip++] & 31u);

    for (;;) {
        if (ctrl >= 32u) {
            size_t match_len = (size_t)((ctrl >> 5) - 1u);
            size_t ofs = (size_t)(ctrl & 31u) << 8;
            if (match_len == 6u) {
                if (level == 1u) {
                    if (ip >= src_len) return -3;
                    match_len += src[ip++];
                } else {
                    for (;;) {
                        if (ip >= src_len) return -4;
                        uint8_t code = src[ip++];
                        match_len += code;
                        if (code != 255u) break;
                    }
                }
            }
            if (ip >= src_len) return -5;
            uint8_t code = src[ip++];
            size_t dist;
            if (level == 2u && code == 255u && (ctrl & 31u) == 31u) {
                if (src_len - ip < 2u) return -6;
                size_t far_ofs = ((size_t)src[ip] << 8) | (size_t)src[ip + 1];
                ip += 2u;
                dist = far_ofs + 8192u + 1u;
            } else {
                dist = ofs + (size_t)code + 1u;
            }
            if (dist > op) return -7;
            size_t ref = op - dist;
            size_t total = match_len + 3u;
            if (total > dst_cap - op) return -8;

            if (dist >= total) {
                memcpy(dst + op, dst + ref, total);
                op += total;
            } else {
                for (size_t i = 0; i < total; i++) {
                    dst[op++] = dst[ref++];
                }
            }
        } else {
            size_t lit_len = (size_t)ctrl + 1u;
            if (lit_len > src_len - ip) return -9;
            if (lit_len > dst_cap - op) return -10;
            memcpy(dst + op, src + ip, lit_len);
            ip += lit_len;
            op += lit_len;
        }

        if (ip >= src_len) {
            break;
        }
        ctrl = (uint32_t)src[ip++];
    }

    return (int64_t)op;
}
