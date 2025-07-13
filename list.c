/**
 * @file list.c
 * @brief List contents of a Seclume archive.
 */

#include "seclume.h"
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>

/**
 * @brief Lists the contents of a .slm archive.
 * @param archive Path to the input archive file (.slm).
 * @param password Password for decryption.
 * @return 0 on success, 1 on failure.
 */
int list_files(const char *archive, const char *password) {
    if (!archive || !password) {
        fprintf(stderr, "Error: Invalid list parameters\n");
        return 1;
    }
    FILE *in = fopen(archive, "rb");
    if (!in) {
        fprintf(stderr, "Error: Cannot open archive file %s: %s\n", archive, strerror(errno));
        return 1;
    }
    ArchiveHeader header;
    if (fread(&header, sizeof(header), 1, in) != 1) {
        fprintf(stderr, "Error: Failed to read archive header\n");
        fclose(in);
        return 1;
    }
    CompressionAlgo algo;
    if (strncmp(header.magic, "SLM", 4) != 0 || header.version < 4 || header.version > 6) {
        fprintf(stderr, "Error: Invalid archive format or version (expected 4-6, got %d)\n", header.version);
        fclose(in);
        return 1;
    }
    if (header.version == 4) {
        algo = COMPRESSION_LZMA;
    } else {
        algo = header.compression_algo;
        if (algo != COMPRESSION_ZLIB && algo != COMPRESSION_LZMA) {
            fprintf(stderr, "Error: Invalid compression algorithm in header (%d)\n", algo);
            fclose(in);
            return 1;
        }
    }
    if (header.file_count > MAX_FILES) {
        fprintf(stderr, "Error: Too many files in archive (%u > %d)\n", header.file_count, MAX_FILES);
        fclose(in);
        return 1;
    }
    verbose_print(VERBOSE_BASIC, "Read archive header, version %d, %u files, compression %s level %d",
                  header.version, header.file_count, algo == COMPRESSION_ZLIB ? "zlib" : "LZMA", header.compression_level);
    uint8_t file_key[AES_KEY_SIZE];
    uint8_t meta_key[AES_KEY_SIZE];
    if (derive_key(password, header.salt, file_key, "file encryption") != 0 ||
        derive_key(password, header.salt, meta_key, "metadata encryption") != 0) {
        fclose(in);
        return 1;
    }
    verbose_print(VERBOSE_DEBUG, "Derived encryption keys");
    size_t hmac_size = offsetof(ArchiveHeader, hmac);
    uint8_t computed_hmac[HMAC_SIZE];
    if (compute_hmac(file_key, (uint8_t *)&header, hmac_size, computed_hmac) != 0) {
        secure_zero(file_key, AES_KEY_SIZE);
        secure_zero(meta_key, AES_KEY_SIZE);
        fclose(in);
        return 1;
    }
    if (memcmp(computed_hmac, header.hmac, HMAC_SIZE) != 0) {
        fprintf(stderr, "Error: Header HMAC verification failed\n");
        secure_zero(file_key, AES_KEY_SIZE);
        secure_zero(meta_key, AES_KEY_SIZE);
        fclose(in);
        return 1;
    }
    verbose_print(VERBOSE_DEBUG, "Verified header HMAC");
    if (header.version >= 6 && header.outdir_len > 0) {
        if (header.outdir_len > MAX_OUTDIR - AES_NONCE_SIZE - AES_TAG_SIZE) {
            fprintf(stderr, "Error: Invalid output directory length (%u)\n", header.outdir_len);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        char *outdir = malloc(header.outdir_len + 1);
        if (!outdir) {
            fprintf(stderr, "Error: Memory allocation failed for output directory\n");
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        size_t enc_outdir_len = header.outdir_len;
        const uint8_t *outdir_nonce = header.outdir + enc_outdir_len;
        const uint8_t *outdir_tag = outdir_nonce + AES_NONCE_SIZE;
        size_t dec_len;
        if (decrypt_aes_gcm(meta_key, outdir_nonce, header.outdir, enc_outdir_len, outdir_tag, (uint8_t *)outdir, &dec_len) != 0) {
            fprintf(stderr, "Error: Failed to decrypt output directory\n");
            free(outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        outdir[dec_len] = '\0';
        if (dec_len != header.outdir_len || has_path_traversal(outdir)) {
            fprintf(stderr, "Error: Invalid or unsafe output directory\n");
            free(outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        printf("Output directory: %s\n", outdir);
        free(outdir);
    }
    printf("Contents of %s:\n", archive);
    printf("%-11s %-12s %s\n", "Permissions", "Size", "Filename");
    printf("%-11s %-12s %s\n", "-----------", "------------", "--------");
    for (uint32_t i = 0; i < header.file_count; i++) {
        FileEntry entry;
        if (fread(&entry, sizeof(entry), 1, in) != 1) {
            fprintf(stderr, "Error: Failed to read file entry %u\n", i);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        FileEntryPlain plain_entry;
        size_t meta_dec_size;
        if (decrypt_aes_gcm(meta_key, entry.nonce, entry.encrypted_data, sizeof(entry.encrypted_data),
                            entry.tag, (uint8_t *)&plain_entry, &meta_dec_size) != 0) {
            fprintf(stderr, "Error: Failed to decrypt metadata for file entry %u\n", i);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        if (meta_dec_size != sizeof(FileEntryPlain) || plain_entry.filename[MAX_FILENAME - 1] != '\0' ||
            has_path_traversal(plain_entry.filename) || plain_entry.compressed_size == 0 ||
            plain_entry.original_size == 0 || plain_entry.original_size > MAX_FILE_SIZE) {
            fprintf(stderr, "Error: Invalid or unsafe metadata in file entry %u\n", i);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        char mode_str[11];
        mode_to_string(plain_entry.mode, mode_str);
        printf("%-11s %12" PRIu64 " %s\n", mode_str, plain_entry.original_size, plain_entry.filename);
        // Skip file data
        size_t skip_size = plain_entry.compressed_size + AES_NONCE_SIZE + AES_TAG_SIZE;
        if (fseek(in, skip_size, SEEK_CUR) != 0) {
            fprintf(stderr, "Error: Failed to skip file data for entry %u: %s\n", i, strerror(errno));
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
    }
    secure_zero(file_key, AES_KEY_SIZE);
    secure_zero(meta_key, AES_KEY_SIZE);
    fclose(in);
    verbose_print(VERBOSE_BASIC, "Listed contents of archive: %s", archive);
    return 0;
}