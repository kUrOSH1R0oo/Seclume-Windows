/**
 * @file archive.c
 * @brief Archiving function for Seclume.
 */

#include "seclume.h"
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/rand.h>

/**
 * @brief Archives and encrypts files into a .slm archive.
 * @param output Path to the output archive file (.slm).
 * @param filenames Array of input file or directory paths.
 * @param file_count Number of input files.
 * @param password Password for encryption.
 * @param force If 1, overwrite existing output file.
 * @param compression_level Compression level (0-9).
 * @param compression_algo Compression algorithm (COMPRESSION_ZLIB or COMPRESSION_LZMA).
 * @param comment Archive comment (NULL if none).
 * @param dry_run If 1, simulate archiving without writing to disk.
 * @param weak_password If 1, allow weak passwords.
 * @param outdir Output directory to store in archive (NULL if none).
 * @param exclude Comma-separated glob patterns to exclude (NULL if none).
 * @return 0 on success, 1 on failure.
 */
int archive_files(const char *output, const char **filenames, int file_count, const char *password,
                 int force, int compression_level, CompressionAlgo compression_algo, const char *comment,
                 int dry_run, int weak_password, const char *outdir, const char *exclude) {
    if (!output || !filenames || !password || file_count <= 0 || file_count > MAX_FILES) {
        fprintf(stderr, "Error: Invalid archive parameters\n");
        return 1;
    }
    if (check_password_strength(password, weak_password) != 0) {
        return 1;
    }
    if (!force && !dry_run && access(output, F_OK) == 0) {
        fprintf(stderr, "Error: Output file %s exists. Use -f to overwrite.\n", output);
        return 1;
    }
    if (outdir && (strlen(outdir) >= MAX_OUTDIR - AES_NONCE_SIZE - AES_TAG_SIZE || has_path_traversal(outdir))) {
        fprintf(stderr, "Error: Invalid or too long output directory: %s\n", outdir);
        return 1;
    }
    FILE *out = NULL;
    if (!dry_run) {
        out = fopen(output, "wb");
        if (!out) {
            fprintf(stderr, "Error: Cannot open output file %s: %s\n", output, strerror(errno));
            return 1;
        }
    }
    uint8_t salt[SALT_SIZE];
    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        fprintf(stderr, "Error: Random number generation failed for salt\n");
        if (out) fclose(out);
        return 1;
    }
    verbose_print(VERBOSE_DEBUG, "Generated random salt");
    uint8_t file_key[AES_KEY_SIZE];
    uint8_t meta_key[AES_KEY_SIZE];
    if (derive_key(password, salt, file_key, "file encryption") != 0 ||
        derive_key(password, salt, meta_key, "metadata encryption") != 0) {
        if (out) fclose(out);
        return 1;
    }
    verbose_print(VERBOSE_DEBUG, "Derived encryption keys");
    size_t comment_len = comment ? strlen(comment) : 0;
    size_t outdir_len = outdir ? strlen(outdir) : 0;
    if (comment_len > MAX_COMMENT - AES_NONCE_SIZE - AES_TAG_SIZE) {
        fprintf(stderr, "Error: Archive comment too long (max %d bytes)\n", MAX_COMMENT - AES_NONCE_SIZE - AES_TAG_SIZE);
        secure_zero(file_key, AES_KEY_SIZE);
        secure_zero(meta_key, AES_KEY_SIZE);
        if (out) fclose(out);
        return 1;
    }
    if (outdir_len > MAX_OUTDIR - AES_NONCE_SIZE - AES_TAG_SIZE) {
        fprintf(stderr, "Error: Output directory too long (max %d bytes)\n", MAX_OUTDIR - AES_NONCE_SIZE - AES_TAG_SIZE);
        secure_zero(file_key, AES_KEY_SIZE);
        secure_zero(meta_key, AES_KEY_SIZE);
        if (out) fclose(out);
        return 1;
    }
    // Filter files based on exclude patterns
    char **filtered_filenames = calloc(file_count, sizeof(char *));
    int filtered_count = 0;
    if (exclude) {
        char *exclude_copy = strdup(exclude);
        if (!exclude_copy) {
            fprintf(stderr, "Error: Memory allocation failed for exclude patterns\n");
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            if (out) fclose(out);
            return 1;
        }
        char *pattern = strtok(exclude_copy, ",");
        while (pattern && filtered_count < file_count) {
            for (int i = 0; i < file_count; i++) {
                if (matches_glob_pattern(filenames[i], pattern)) {
                    verbose_print(VERBOSE_BASIC, "Excluding file: %s (matches pattern %s)", filenames[i], pattern);
                    continue;
                }
                filtered_filenames[filtered_count] = (char *)filenames[i];
                filtered_count++;
            }
            pattern = strtok(NULL, ",");
        }
        free(exclude_copy);
    } else {
        for (int i = 0; i < file_count; i++) {
            filtered_filenames[filtered_count] = (char *)filenames[i];
            filtered_count++;
        }
    }
    if (filtered_count == 0) {
        fprintf(stderr, "Error: No files to archive after applying exclude patterns\n");
        free(filtered_filenames);
        secure_zero(file_key, AES_KEY_SIZE);
        secure_zero(meta_key, AES_KEY_SIZE);
        if (out) fclose(out);
        return 1;
    }
    ArchiveHeader header = { .magic = "SLM", .version = 6, .file_count = filtered_count,
                            .compression_level = compression_level, .compression_algo = compression_algo,
                            .comment_len = comment_len, .outdir_len = outdir_len };
    memset(header.reserved, 0, sizeof(header.reserved));
    memcpy(header.salt, salt, SALT_SIZE);
    if (comment_len > 0) {
        uint8_t comment_nonce[AES_NONCE_SIZE];
        uint8_t comment_tag[AES_TAG_SIZE];
        if (RAND_bytes(comment_nonce, AES_NONCE_SIZE) != 1) {
            fprintf(stderr, "Error: Random number generation failed for comment nonce\n");
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            if (out) fclose(out);
            free(filtered_filenames);
            return 1;
        }
        size_t enc_comment_len;
        if (encrypt_aes_gcm(meta_key, comment_nonce, (uint8_t *)comment, comment_len,
                            header.comment, &enc_comment_len, comment_tag) != 0) {
            fprintf(stderr, "Error: Failed to encrypt archive comment\n");
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            if (out) fclose(out);
            free(filtered_filenames);
            return 1;
        }
        memcpy(header.comment + enc_comment_len, comment_nonce, AES_NONCE_SIZE);
        memcpy(header.comment + enc_comment_len + AES_NONCE_SIZE, comment_tag, AES_TAG_SIZE);
    } else {
        memset(header.comment, 0, MAX_COMMENT);
    }
    if (outdir_len > 0) {
        uint8_t outdir_nonce[AES_NONCE_SIZE];
        uint8_t outdir_tag[AES_TAG_SIZE];
        if (RAND_bytes(outdir_nonce, AES_NONCE_SIZE) != 1) {
            fprintf(stderr, "Error: Random number generation failed for outdir nonce\n");
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            if (out) fclose(out);
            free(filtered_filenames);
            return 1;
        }
        size_t enc_outdir_len;
        if (encrypt_aes_gcm(meta_key, outdir_nonce, (uint8_t *)outdir, outdir_len,
                            header.outdir, &enc_outdir_len, outdir_tag) != 0) {
            fprintf(stderr, "Error: Failed to encrypt output directory\n");
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            if (out) fclose(out);
            free(filtered_filenames);
            return 1;
        }
        memcpy(header.outdir + enc_outdir_len, outdir_nonce, AES_NONCE_SIZE);
        memcpy(header.outdir + enc_outdir_len + AES_NONCE_SIZE, outdir_tag, AES_TAG_SIZE);
    } else {
        memset(header.outdir, 0, MAX_OUTDIR);
    }
    if (compute_hmac(file_key, (uint8_t *)&header, offsetof(ArchiveHeader, hmac), header.hmac) != 0) {
        secure_zero(file_key, AES_KEY_SIZE);
        secure_zero(meta_key, AES_KEY_SIZE);
        if (out) fclose(out);
        free(filtered_filenames);
        return 1;
    }
    if (!dry_run && fwrite(&header, sizeof(header), 1, out) != 1) {
        fprintf(stderr, "Error: Failed to write archive header\n");
        secure_zero(file_key, AES_KEY_SIZE);
        secure_zero(meta_key, AES_KEY_SIZE);
        fclose(out);
        free(filtered_filenames);
        return 1;
    }
    verbose_print(VERBOSE_BASIC, "Wrote archive header (version 6, compression %s level %d, comment len %u, outdir len %u)",
                  compression_algo == COMPRESSION_ZLIB ? "zlib" : "LZMA", compression_level, comment_len, outdir_len);
    for (int i = 0; i < filtered_count; i++) {
        const char *filename = filtered_filenames[i];
        if (!filename || strlen(filename) >= MAX_FILENAME || has_path_traversal(filename)) {
            fprintf(stderr, "Error: Invalid or too long filename: %s\n", filename ? filename : "(null)");
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            if (out) fclose(out);
            free(filtered_filenames);
            return 1;
        }
        verbose_print(VERBOSE_BASIC, "Processing file: %s", filename);
        FILE *in = dry_run ? NULL : fopen(filename, "rb");
        if (!dry_run && !in) {
            fprintf(stderr, "Error: Cannot open input file %s: %s\n", filename, strerror(errno));
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            if (out) fclose(out);
            free(filtered_filenames);
            return 1;
        }
        struct stat st;
        if (dry_run ? stat(filename, &st) != 0 : fstat(fileno(in), &st) != 0) {
            fprintf(stderr, "Error: Cannot stat input file %s: %s\n", filename, strerror(errno));
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            if (in) fclose(in);
            if (out) fclose(out);
            free(filtered_filenames);
            return 1;
        }
        size_t in_size = st.st_size;
        uint32_t file_mode = st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
        if (in_size == 0) {
            fprintf(stderr, "Error: Input file %s is empty\n", filename);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            if (in) fclose(in);
            if (out) fclose(out);
            free(filtered_filenames);
            return 1;
        }
        if (in_size > MAX_FILE_SIZE) {
            fprintf(stderr, "Error: Input file %s exceeds max size (%llu bytes)\n", filename, MAX_FILE_SIZE);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            if (in) fclose(in);
            if (out) fclose(out);
            free(filtered_filenames);
            return 1;
        }
        verbose_print(VERBOSE_DEBUG, "File size: %lu bytes, mode: 0%o", in_size, file_mode);
        uint8_t *in_buf = dry_run ? NULL : malloc(in_size);
        if (!dry_run && !in_buf) {
            fprintf(stderr, "Error: Memory allocation failed for input buffer\n");
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            if (in) fclose(in);
            if (out) fclose(out);
            free(filtered_filenames);
            return 1;
        }
        size_t read_size = 0;
        if (!dry_run) {
            while (read_size < in_size) {
                size_t chunk = fread(in_buf + read_size, 1, in_size - read_size, in);
                if (chunk == 0) {
                    if (feof(in)) {
                        fprintf(stderr, "Error: Unexpected EOF reading input file %s (read %lu of %lu bytes)\n",
                                filename, read_size, in_size);
                    } else {
                        fprintf(stderr, "Error: Failed to read input file %s: %s\n", filename, strerror(errno));
                    }
                    free(in_buf);
                    secure_zero(file_key, AES_KEY_SIZE);
                    secure_zero(meta_key, AES_KEY_SIZE);
                    fclose(in);
                    if (out) fclose(out);
                    free(filtered_filenames);
                    return 1;
                }
                read_size += chunk;
            }
        }
        if (verbosity >= VERBOSE_DEBUG && !dry_run && in_size >= 4) {
            fprintf(stderr, "First 4 bytes of %s: %02x %02x %02x %02x\n",
                    filename, in_buf[0], in_buf[1], in_buf[2], in_buf[3]);
        }
        size_t comp_buf_size = in_size + (in_size / (compression_algo == COMPRESSION_ZLIB ? 100 : 4)) + 1024;
        uint8_t *comp_buf = malloc(comp_buf_size);
        if (!comp_buf) {
            fprintf(stderr, "Error: Memory allocation failed for compression buffer (%lu bytes)\n", comp_buf_size);
            if (in_buf) free(in_buf);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            if (in) fclose(in);
            if (out) fclose(out);
            free(filtered_filenames);
            return 1;
        }
        size_t comp_size = dry_run ? in_size : compress_data(in_buf, in_size, comp_buf, comp_buf_size, compression_level, compression_algo);
        if (comp_size == 0) {
            if (in_buf) free(in_buf);
            free(comp_buf);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            if (in) fclose(in);
            if (out) fclose(out);
            free(filtered_filenames);
            return 1;
        }
        uint8_t file_nonce[AES_NONCE_SIZE];
        if (!dry_run && RAND_bytes(file_nonce, AES_NONCE_SIZE) != 1) {
            fprintf(stderr, "Error: Random number generation failed for file nonce\n");
            if (in_buf) free(in_buf);
            free(comp_buf);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            if (in) fclose(in);
            if (out) fclose(out);
            free(filtered_filenames);
            return 1;
        }
        verbose_print(VERBOSE_DEBUG, "Generated random file nonce");
        uint8_t *enc_buf = dry_run ? NULL : malloc(comp_size);
        if (!dry_run && !enc_buf) {
            fprintf(stderr, "Error: Memory allocation failed for encryption buffer\n");
            if (in_buf) free(in_buf);
            free(comp_buf);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            if (in) fclose(in);
            if (out) fclose(out);
            free(filtered_filenames);
            return 1;
        }
        size_t enc_size;
        uint8_t file_tag[AES_TAG_SIZE];
        if (!dry_run && encrypt_aes_gcm(file_key, file_nonce, comp_buf, comp_size, enc_buf, &enc_size, file_tag) != 0) {
            if (in_buf) free(in_buf);
            free(comp_buf);
            if (enc_buf) free(enc_buf);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            if (in) fclose(in);
            if (out) fclose(out);
            free(filtered_filenames);
            return 1;
        }
        verbose_print(VERBOSE_DEBUG, "Encrypted file to %lu bytes", enc_size);
        FileEntryPlain plain_entry = { .compressed_size = enc_size, .original_size = in_size,
                                      .mode = file_mode, .reserved = 0 };
        strncpy(plain_entry.filename, filename, MAX_FILENAME - 1);
        plain_entry.filename[MAX_FILENAME - 1] = '\0';
        uint8_t meta_nonce[AES_NONCE_SIZE];
        if (!dry_run && RAND_bytes(meta_nonce, AES_NONCE_SIZE) != 1) {
            fprintf(stderr, "Error: Random number generation failed for metadata nonce\n");
            if (in_buf) free(in_buf);
            free(comp_buf);
            if (enc_buf) free(enc_buf);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            if (in) fclose(in);
            if (out) fclose(out);
            free(filtered_filenames);
            return 1;
        }
        verbose_print(VERBOSE_DEBUG, "Generated random metadata nonce");
        FileEntry entry;
        memcpy(entry.nonce, meta_nonce, AES_NONCE_SIZE);
        size_t meta_enc_size;
        if (!dry_run && encrypt_aes_gcm(meta_key, meta_nonce, (uint8_t *)&plain_entry, sizeof(FileEntryPlain),
                                       entry.encrypted_data, &meta_enc_size, entry.tag) != 0) {
            fprintf(stderr, "Error: Failed to encrypt metadata for %s\n", filename);
            if (in_buf) free(in_buf);
            free(comp_buf);
            if (enc_buf) free(enc_buf);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            if (in) fclose(in);
            if (out) fclose(out);
            free(filtered_filenames);
            return 1;
        }
        verbose_print(VERBOSE_DEBUG, "Encrypted metadata");
        if (!dry_run && (fwrite(&entry, sizeof(entry), 1, out) != 1 ||
                         fwrite(file_nonce, AES_NONCE_SIZE, 1, out) != 1 ||
                         fwrite(file_tag, AES_TAG_SIZE, 1, out) != 1 ||
                         fwrite(enc_buf, 1, enc_size, out) != enc_size)) {
            fprintf(stderr, "Error: Failed to write encrypted data for %s\n", filename);
            if (in_buf) free(in_buf);
            free(comp_buf);
            if (enc_buf) free(enc_buf);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            if (out) fclose(out);
            free(filtered_filenames);
            return 1;
        }
        verbose_print(VERBOSE_BASIC, "Archived file: %s (permissions: 0%o)", filename, file_mode);
        if (in_buf) free(in_buf);
        free(comp_buf);
        if (enc_buf) free(enc_buf);
        if (in) fclose(in);
    }
    free(filtered_filenames);
    secure_zero(file_key, AES_KEY_SIZE);
    secure_zero(meta_key, AES_KEY_SIZE);
    if (out) fclose(out);
    verbose_print(VERBOSE_BASIC, dry_run ? "Dry run completed for archive: %s" : "Archive created: %s", output);
    return 0;
}