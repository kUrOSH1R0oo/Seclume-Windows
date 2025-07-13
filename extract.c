/**
 * @file extract.c
 * @brief Extraction function for Seclume.
 */

#include "seclume.h"
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#ifdef _WIN32
#include <io.h>
#endif

/**
 * @brief Constructs the output path for a file.
 * @param archive_outdir Output directory stored in archive (NULL for versions < 6).
 * @param filename Original filename from archive.
 * @param outdir User-specified output directory (NULL to use archive_outdir or current directory).
 * @param version Archive version (4, 5, or 6).
 * @param output_path Buffer to store the constructed path.
 * @param max_len Maximum length of output_path.
 * @return 0 on success, 1 on failure.
 */
static int construct_output_path(const char *archive_outdir, const char *filename, const char *outdir, uint8_t version, char *output_path, size_t max_len) {
    if (!filename || !output_path || max_len < MAX_FILENAME) {
        fprintf(stderr, "Error: Invalid path construction parameters\n");
        return 1;
    }

    // For version 6, check if filename is absolute and contains archive_outdir
    if (version >= 6 && archive_outdir && filename[0] != '\0') {
        size_t archive_outdir_len = strlen(archive_outdir);
        size_t filename_len = strlen(filename);

        // Normalize separators for comparison
        char normalized_filename[MAX_FILENAME * 2];
        strncpy(normalized_filename, filename, sizeof(normalized_filename) - 1);
        normalized_filename[sizeof(normalized_filename) - 1] = '\0';
#ifdef _WIN32
        for (char *p = normalized_filename; *p; p++) {
            if (*p == '/') *p = '\\';
        }
#endif

        // Check if filename starts with archive_outdir
        if (strncmp(normalized_filename, archive_outdir, archive_outdir_len) == 0 &&
            (normalized_filename[archive_outdir_len] == '/' || normalized_filename[archive_outdir_len] == '\\' || normalized_filename[archive_outdir_len] == '\0')) {
            // If user specified an outdir, replace archive_outdir with outdir
            if (outdir) {
                size_t outdir_len = strlen(outdir);
                size_t relative_len = filename_len - archive_outdir_len - (normalized_filename[archive_outdir_len] ? 1 : 0);
                if (outdir_len + relative_len + 2 > max_len) {
                    fprintf(stderr, "Error: Output path too long: %s/%s\n", outdir, filename + archive_outdir_len);
                    return 1;
                }
                snprintf(output_path, max_len, "%s/%s", outdir, normalized_filename + archive_outdir_len + (normalized_filename[archive_outdir_len] ? 1 : 0));
            } else {
                // Use the filename as is (absolute path)
                if (filename_len + 1 > max_len) {
                    fprintf(stderr, "Error: Output path too long: %s\n", filename);
                    return 1;
                }
                strncpy(output_path, filename, max_len - 1);
                output_path[max_len - 1] = '\0';
            }
        } else {
            // Filename doesn't start with archive_outdir, prepend outdir or archive_outdir
            const char *base_dir = outdir ? outdir : archive_outdir;
            if (base_dir) {
                size_t base_dir_len = strlen(base_dir);
                if (base_dir_len + filename_len + 2 > max_len) {
                    fprintf(stderr, "Error: Output path too long: %s/%s\n", base_dir, filename);
                    return 1;
                }
                snprintf(output_path, max_len, "%s/%s", base_dir, filename);
            } else {
                strncpy(output_path, filename, max_len - 1);
                output_path[max_len - 1] = '\0';
            }
        }
    } else {
        // For versions 4 and 5, or if no archive_outdir, prepend outdir or use filename
        if (outdir) {
            size_t outdir_len = strlen(outdir);
            size_t filename_len = strlen(filename);
            if (outdir_len + filename_len + 2 > max_len) {
                fprintf(stderr, "Error: Output path too long: %s/%s\n", outdir, filename);
                return 1;
            }
            snprintf(output_path, max_len, "%s/%s", outdir, filename);
        } else {
            strncpy(output_path, filename, max_len - 1);
            output_path[max_len - 1] = '\0';
        }
    }

#ifdef _WIN32
    // Normalize path separators for Windows
    for (char *p = output_path; *p; p++) {
        if (*p == '/') *p = '\\';
    }
#endif

    // Validate the constructed path
    if (has_path_traversal(output_path)) {
        fprintf(stderr, "Error: Path traversal detected in output path: %s\n", output_path);
        return 1;
    }

    return 0;
}

/**
 * @brief Extracts and decrypts files from a .slm archive.
 * @param archive Path to the input archive file (.slm).
 * @param password Password for decryption.
 * @param force If 1, overwrite existing output files.
 * @param outdir Output directory (NULL to use archive's outdir or current directory).
 * @return 0 on success, 1 on failure.
 */
int extract_files(const char *archive, const char *password, int force, const char *outdir) {
    if (!archive || !password) {
        fprintf(stderr, "Error: Invalid extract parameters\n");
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
    char *archive_outdir = NULL;
    if (header.version >= 6 && header.outdir_len > 0) {
        if (header.outdir_len > MAX_OUTDIR - AES_NONCE_SIZE - AES_TAG_SIZE) {
            fprintf(stderr, "Error: Invalid output directory length (%u)\n", header.outdir_len);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        archive_outdir = malloc(header.outdir_len + 1);
        if (!archive_outdir) {
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
        if (decrypt_aes_gcm(meta_key, outdir_nonce, header.outdir, enc_outdir_len, outdir_tag, (uint8_t *)archive_outdir, &dec_len) != 0) {
            fprintf(stderr, "Error: Failed to decrypt output directory\n");
            free(archive_outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        archive_outdir[dec_len] = '\0';
        if (dec_len != header.outdir_len || has_path_traversal(archive_outdir)) {
            fprintf(stderr, "Error: Invalid or unsafe output directory\n");
            free(archive_outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        verbose_print(VERBOSE_BASIC, "Archive output directory: %s", archive_outdir);
    }
    const char *extract_dir = outdir ? outdir : (archive_outdir ? archive_outdir : ".");
    struct stat st;
    if (stat(extract_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        verbose_print(VERBOSE_BASIC, "Output directory %s does not exist or is not a directory, falling back to current directory", extract_dir);
        extract_dir = ".";
    }
    for (uint32_t i = 0; i < header.file_count; i++) {
        FileEntry entry;
        if (fread(&entry, sizeof(entry), 1, in) != 1) {
            fprintf(stderr, "Error: Failed to read file entry %u\n", i);
            free(archive_outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        FileEntryPlain plain_entry;
        size_t meta_dec_size;
        if (decrypt_aes_gcm(meta_key, entry.nonce, entry.encrypted_data, sizeof(entry.encrypted_data),
                            entry.tag, (uint8_t *)&plain_entry, &meta_dec_size) != 0) {
            free(archive_outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        if (meta_dec_size != sizeof(FileEntryPlain) || plain_entry.filename[MAX_FILENAME - 1] != '\0' ||
            has_path_traversal(plain_entry.filename) || plain_entry.compressed_size == 0 ||
            plain_entry.original_size == 0 || plain_entry.original_size > MAX_FILE_SIZE) {
            fprintf(stderr, "Error: Invalid or unsafe metadata in file entry %u\n", i);
            free(archive_outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        char output_path[MAX_FILENAME * 2];
        if (construct_output_path(archive_outdir, plain_entry.filename, outdir, header.version, output_path, sizeof(output_path)) != 0) {
            free(archive_outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        verbose_print(VERBOSE_BASIC, "Extracting file: %s (permissions: 0%o)", output_path, plain_entry.mode);
        if (!force && access(output_path, F_OK) == 0) {
            fprintf(stderr, "Error: Output file %s exists. Use -f to overwrite.\n", output_path);
            free(archive_outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        if (create_parent_dirs(output_path) != 0) {
            free(archive_outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        uint8_t file_nonce[AES_NONCE_SIZE];
        uint8_t file_tag[AES_TAG_SIZE];
        if (fread(file_nonce, AES_NONCE_SIZE, 1, in) != 1 || fread(file_tag, AES_TAG_SIZE, 1, in) != 1) {
            fprintf(stderr, "Error: Failed to read nonce or tag for file %u\n", i);
            free(archive_outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        uint8_t *enc_buf = malloc(plain_entry.compressed_size);
        if (!enc_buf) {
            fprintf(stderr, "Error: Memory allocation failed for encrypted data\n");
            free(archive_outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        size_t read_size = 0;
        while (read_size < plain_entry.compressed_size) {
            size_t chunk = fread(enc_buf + read_size, 1, plain_entry.compressed_size - read_size, in);
            if (chunk == 0) {
                fprintf(stderr, "Error: Failed to read encrypted data for file %u: %s\n", i, strerror(errno));
                free(enc_buf);
                free(archive_outdir);
                secure_zero(file_key, AES_KEY_SIZE);
                secure_zero(meta_key, AES_KEY_SIZE);
                fclose(in);
                return 1;
            }
            read_size += chunk;
        }
        uint8_t *comp_buf = malloc(plain_entry.compressed_size);
        if (!comp_buf) {
            fprintf(stderr, "Error: Memory allocation failed for compressed data\n");
            free(enc_buf);
            free(archive_outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        size_t comp_size;
        if (decrypt_aes_gcm(file_key, file_nonce, enc_buf, plain_entry.compressed_size, file_tag, comp_buf, &comp_size) != 0) {
            free(enc_buf);
            free(comp_buf);
            free(archive_outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        verbose_print(VERBOSE_DEBUG, "Decrypted %lu bytes", comp_size);
        uint8_t *out_buf = malloc(plain_entry.original_size);
        if (!out_buf) {
            fprintf(stderr, "Error: Memory allocation failed for decompressed data\n");
            free(enc_buf);
            free(comp_buf);
            free(archive_outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        size_t out_size = decompress_data(comp_buf, comp_size, out_buf, plain_entry.original_size, algo);
        if (out_size != plain_entry.original_size) {
            fprintf(stderr, "Error: Decompression failed for file %s (expected %lu bytes, got %lu)\n",
                    output_path, plain_entry.original_size, out_size);
            free(enc_buf);
            free(comp_buf);
            free(out_buf);
            free(archive_outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        verbose_print(VERBOSE_DEBUG, "Decompressed to %lu bytes", out_size);
        FILE *out = fopen(output_path, "wb");
        if (!out) {
            fprintf(stderr, "Error: Cannot open output file %s: %s\n", output_path, strerror(errno));
            free(enc_buf);
            free(comp_buf);
            free(out_buf);
            free(archive_outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        if (fwrite(out_buf, 1, out_size, out) != out_size) {
            fprintf(stderr, "Error: Failed to write output file %s: %s\n", output_path, strerror(errno));
            free(enc_buf);
            free(comp_buf);
            free(out_buf);
            fclose(out);
            free(archive_outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        fclose(out);
#ifdef _WIN32
        int win_mode = (plain_entry.mode & S_IWUSR) ? _S_IWRITE : _S_IREAD;
        if (_chmod(output_path, win_mode) != 0) {
            fprintf(stderr, "Warning: Failed to set permissions on %s: %s\n", output_path, strerror(errno));
        } else {
            verbose_print(VERBOSE_DEBUG, "Set basic permissions on %s: %s", output_path,
                          win_mode == _S_IWRITE ? "read/write" : "read-only");
        }
#else
        if (chmod(output_path, plain_entry.mode) != 0) {
            fprintf(stderr, "Warning: Failed to set permissions on %s: %s\n", output_path, strerror(errno));
        } else {
            verbose_print(VERBOSE_DEBUG, "Restored permissions on %s: 0%o", output_path, plain_entry.mode);
        }
#endif
        verbose_print(VERBOSE_BASIC, "Extracted file: %s", output_path);
        free(enc_buf);
        free(comp_buf);
        free(out_buf);
    }
    free(archive_outdir);
    secure_zero(file_key, AES_KEY_SIZE);
    secure_zero(meta_key, AES_KEY_SIZE);
    fclose(in);
    verbose_print(VERBOSE_BASIC, "Extraction completed: %s", archive);
    return 0;
}