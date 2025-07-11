/**
 * @file compression.c
 * @brief Compression and decompression functions for Seclume (zlib and LZMA).
 */

#include "seclume.h"
#include <string.h>

/**
 * @brief Compresses data using the specified algorithm.
 * @param in Input data buffer.
 * @param in_len Size of input data.
 * @param out Output buffer for compressed data.
 * @param out_max Maximum size of output buffer.
 * @param level Compression level (0-9).
 * @param algo Compression algorithm (COMPRESSION_ZLIB or COMPRESSION_LZMA).
 * @return Size of compressed data, or 0 on failure.
 */
size_t compress_data(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max, int level, CompressionAlgo algo) {
    if (!in || !out || in_len == 0 || out_max == 0 || level < 0 || level > 9) {
        fprintf(stderr, "Error: Invalid compression parameters\n");
        return 0;
    }
    if (algo == COMPRESSION_ZLIB) {
        z_stream strm = {0};
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;
        if (deflateInit(&strm, level) != Z_OK) {
            fprintf(stderr, "Error: Failed to initialize zlib compression\n");
            return 0;
        }
        strm.next_in = (uint8_t *)in;
        strm.avail_in = in_len;
        strm.next_out = out;
        strm.avail_out = out_max;
        if (deflate(&strm, Z_FINISH) != Z_STREAM_END) {
            fprintf(stderr, "Error: zlib compression failed\n");
            deflateEnd(&strm);
            return 0;
        }
        size_t out_len = out_max - strm.avail_out;
        deflateEnd(&strm);
        verbose_print(VERBOSE_DEBUG, "Compressed %lu bytes to %lu bytes using zlib level %d", in_len, out_len, level);
        return out_len;
    } else if (algo == COMPRESSION_LZMA) {
        lzma_stream strm = LZMA_STREAM_INIT;
        lzma_ret ret = lzma_easy_encoder(&strm, level, LZMA_CHECK_CRC64);
        if (ret != LZMA_OK) {
            fprintf(stderr, "Error: Failed to initialize LZMA encoder: %d\n", ret);
            lzma_end(&strm);
            return 0;
        }
        strm.next_in = in;
        strm.avail_in = in_len;
        strm.next_out = out;
        strm.avail_out = out_max;
        ret = lzma_code(&strm, LZMA_FINISH);
        if (ret != LZMA_STREAM_END) {
            fprintf(stderr, "Error: LZMA compression failed: %d\n", ret);
            lzma_end(&strm);
            return 0;
        }
        size_t out_len = out_max - strm.avail_out;
        lzma_end(&strm);
        verbose_print(VERBOSE_DEBUG, "Compressed %lu bytes to %lu bytes using LZMA preset %d", in_len, out_len, level);
        return out_len;
    }
    fprintf(stderr, "Error: Unknown compression algorithm\n");
    return 0;
}

/**
 * @brief Decompresses data using the specified algorithm.
 * @param in Input compressed data buffer.
 * @param in_len Size of input compressed data.
 * @param out Output buffer for decompressed data.
 * @param out_max Maximum size of output buffer.
 * @param algo Compression algorithm (COMPRESSION_ZLIB or COMPRESSION_LZMA).
 * @return Size of decompressed data, or 0 on failure.
 */
size_t decompress_data(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max, CompressionAlgo algo) {
    if (!in || !out || in_len == 0 || out_max == 0) {
        fprintf(stderr, "Error: Invalid decompression parameters\n");
        return 0;
    }
    if (algo == COMPRESSION_ZLIB) {
        z_stream strm = {0};
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;
        if (inflateInit(&strm) != Z_OK) {
            fprintf(stderr, "Error: Failed to initialize zlib decompression\n");
            return 0;
        }
        strm.next_in = (uint8_t *)in;
        strm.avail_in = in_len;
        strm.next_out = out;
        strm.avail_out = out_max;
        if (inflate(&strm, Z_FINISH) != Z_STREAM_END) {
            fprintf(stderr, "Error: zlib decompression failed\n");
            inflateEnd(&strm);
            return 0;
        }
        size_t out_len = out_max - strm.avail_out;
        inflateEnd(&strm);
        verbose_print(VERBOSE_DEBUG, "Decompressed %lu bytes to %lu bytes using zlib", in_len, out_len);
        return out_len;
    } else if (algo == COMPRESSION_LZMA) {
        lzma_stream strm = LZMA_STREAM_INIT;
        lzma_ret ret = lzma_stream_decoder(&strm, UINT64_MAX, LZMA_CONCATENATED);
        if (ret != LZMA_OK) {
            fprintf(stderr, "Error: Failed to initialize LZMA decoder: %d\n", ret);
            lzma_end(&strm);
            return 0;
        }
        strm.next_in = in;
        strm.avail_in = in_len;
        strm.next_out = out;
        strm.avail_out = out_max;
        ret = lzma_code(&strm, LZMA_FINISH);
        if (ret != LZMA_STREAM_END) {
            fprintf(stderr, "Error: LZMA decompression failed: %d\n", ret);
            lzma_end(&strm);
            return 0;
        }
        size_t out_len = out_max - strm.avail_out;
        lzma_end(&strm);
        verbose_print(VERBOSE_DEBUG, "Decompressed %lu bytes to %lu bytes using LZMA", in_len, out_len);
        return out_len;
    }
    fprintf(stderr, "Error: Unknown compression algorithm\n");
    return 0;
}