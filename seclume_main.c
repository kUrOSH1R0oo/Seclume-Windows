/**
 * @file seclume_main.c
 * @brief Main program for Seclume: Command-line parsing and mode dispatching.
 */

#include "seclume.h"
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

/**
 * @brief Prints a detailed help message for Seclume.
 * @param prog_name The name of the program (argv[0]).
 */
void print_help(const char *prog_name) {
    printf("Seclume: File Archiving Tool for Paranoidsz\n");
    printf("Version: 1.0.5\n\n");
    printf("Usage: %s [options] <mode> <archive.slm> <password> [files...]\n\n", prog_name);
    printf("Modes:\n");
    printf("  archive       Create an encrypted archive from files or directories\n");
    printf("  extract       Extract files from an encrypted archive\n");
    printf("  list          List contents of an encrypted archive\n\n");
    printf("Options:\n");
    printf("  -h, --help              Display this help message and exit\n");
    printf("  -vv                     Enable debug output (detailed logging)\n");
    printf("  -f                      Force overwrite of existing files\n");
    printf("  -c, --comment <text>    Add a comment to the archive (archive mode only)\n");
    printf("  -d, --dry-run           Simulate archiving without writing to disk (archive mode only)\n");
    printf("  -vc, --view-comment     Display the archive comment before mode execution\n");
    printf("  -cl, --compression-level <0-9>  Set compression level (0 = no compression, 9 = max, default = 1)\n");
    printf("  -ca, --compression-algo <zlib|lzma>  Set compression algorithm (default = lzma)\n");
    printf("  -wk, --weak-password    Allow weak passwords in archive mode (NOT RECOMMENDED)\n");
    printf("  -o, --output-dir <dir>  Set output directory for extraction (archive/extract mode)\n");
    printf("  -x, --exclude <pattern> Comma-separated glob patterns to exclude (archive mode only, e.g., '*.log,*.txt')\n\n");
    printf("Examples:\n");
    printf("  Archive with zlib: %s -ca zlib archive output.slm MyPass123! file1.txt dir/\n", prog_name);
    printf("  High compression: %s -ca lzma -cl 9 archive output.slm MyPass123! dir/\n", prog_name);
    printf("  Add comment:       %s -c 'My archive' archive output.slm MyPass123! dir/\n", prog_name);
    printf("  Weak password:     %s -wk archive output.slm weakpass file1.txt\n", prog_name);
    printf("  Dry run:          %s -d archive output.slm MyPass123! dir/\n", prog_name);
    printf("  View comment:      %s -vc list output.slm MyPass123!\n", prog_name);
    printf("  Extract archive:   %s -o extracted/ extract output.slm MyPass123!\n", prog_name);
    printf("  List contents:     %s list output.slm MyPass123!\n", prog_name);
    printf("  Force overwrite:   %s -f extract output.slm MyPass123!\n", prog_name);
    printf("  Exclude files:     %s -x '*.log,*.txt' archive output.slm MyPass123! dir/\n", prog_name);
    printf("\nSecurity Features:\n");
    printf("  - Encryption: AES-256-GCM for file data, metadata, comments, and output directory\n");
    printf("  - Key Derivation: PBKDF2 with SHA256 and 1,000,000 iterations\n");
    printf("  - Header Protection: HMAC-SHA256 to prevent tampering\n");
    printf("  - Compression: zlib or LZMA with customizable levels (0-9)\n");
    printf("  - Secure Random: Cryptographically secure salt and nonces\n");
    printf("  - Permissions: Preserves and restores POSIX file permissions (Unix-like systems) or basic read/write (Windows)\n");
    printf("\nNotes:\n");
    printf("  - Basic progress output is enabled by default\n");
    printf("  - Supports recursive directory archiving\n");
    printf("  - Maximum file size: 10GB per file\n");
    printf("  - Maximum files: %d per archive\n", MAX_FILES);
    printf("  - Maximum comment length: %d bytes\n", MAX_COMMENT - AES_NONCE_SIZE - AES_TAG_SIZE);
    printf("  - Maximum output directory length: %d bytes\n", MAX_OUTDIR - AES_NONCE_SIZE - AES_TAG_SIZE);
    printf("  - Archiving or extracting large files requires significant memory (e.g., 11GB+ for a 10GB file)\n");
    printf("  - Passwords must be strong (8+ characters, mixed case, digits, symbols) unless -wk/--weak-password is used\n");
    printf("  - Using -wk/--weak-password is not recommended for security\n");
    printf("\nReport bugs to: lone_kuroshiro@protonmail.com\n");
}

/**
 * @brief Main function for the Seclume tool.
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line arguments.
 * @return 0 on success, 1 on failure.
 */
int main(int argc, char *argv[]) {
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
    int optind = 1;
    int force = 0;
    const char *comment = NULL;
    int dry_run = 0;
    int view_comment_flag = 0;
    int compression_level = 1;
    CompressionAlgo compression_algo = COMPRESSION_LZMA;
    int weak_password = 0;
    const char *outdir = NULL;
    const char *exclude = NULL;
    while (optind < argc && argv[optind][0] == '-') {
        if (strcmp(argv[optind], "-h") == 0 || strcmp(argv[optind], "--help") == 0) {
            print_help(argv[0]);
            return 0;
        } else if (strcmp(argv[optind], "-vv") == 0) {
            verbosity = VERBOSE_DEBUG;
        } else if (strcmp(argv[optind], "-f") == 0) {
            force = 1;
        } else if (strcmp(argv[optind], "-c") == 0 || strcmp(argv[optind], "--comment") == 0) {
            if (optind + 1 >= argc) {
                fprintf(stderr, "Error: -c/--comment requires a comment string\n");
                print_help(argv[0]);
                return 1;
            }
            comment = argv[++optind];
        } else if (strcmp(argv[optind], "-d") == 0 || strcmp(argv[optind], "--dry-run") == 0) {
            dry_run = 1;
        } else if (strcmp(argv[optind], "-vc") == 0 || strcmp(argv[optind], "--view-comment") == 0) {
            view_comment_flag = 1;
        } else if (strcmp(argv[optind], "-cl") == 0 || strcmp(argv[optind], "--compression-level") == 0) {
            if (optind + 1 >= argc) {
                fprintf(stderr, "Error: -cl/--compression-level requires a value (0-9)\n");
                print_help(argv[0]);
                return 1;
            }
            char *endptr;
            compression_level = strtol(argv[++optind], &endptr, 10);
            if (*endptr != '\0' || compression_level < 0 || compression_level > 9) {
                fprintf(stderr, "Error: Invalid compression level (must be 0-9)\n");
                print_help(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[optind], "-ca") == 0 || strcmp(argv[optind], "--compression-algo") == 0) {
            if (optind + 1 >= argc) {
                fprintf(stderr, "Error: -ca/--compression-algo requires a value (zlib or lzma)\n");
                print_help(argv[0]);
                return 1;
            }
            optind++;
            if (strcmp(argv[optind], "zlib") == 0) {
                compression_algo = COMPRESSION_ZLIB;
            } else if (strcmp(argv[optind], "lzma") == 0) {
                compression_algo = COMPRESSION_LZMA;
            } else {
                fprintf(stderr, "Error: Invalid compression algorithm (must be zlib or lzma)\n");
                print_help(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[optind], "-wk") == 0 || strcmp(argv[optind], "--weak-password") == 0) {
            weak_password = 1;
        } else if (strcmp(argv[optind], "-o") == 0 || strcmp(argv[optind], "--output-dir") == 0) {
            if (optind + 1 >= argc) {
                fprintf(stderr, "Error: -o/--output-dir requires a directory path\n");
                print_help(argv[0]);
                return 1;
            }
            outdir = argv[++optind];
        } else if (strcmp(argv[optind], "-x") == 0 || strcmp(argv[optind], "--exclude") == 0) {
            if (optind + 1 >= argc) {
                fprintf(stderr, "Error: -x/--exclude requires a comma-separated list of glob patterns\n");
                print_help(argv[0]);
                return 1;
            }
            exclude = argv[++optind];
        } else {
            fprintf(stderr, "Error: Unknown option %s\n", argv[optind]);
            print_help(argv[0]);
            return 1;
        }
        optind++;
    }
    if (argc - optind < 3) {
        fprintf(stderr, "Error: Insufficient arguments\n");
        print_help(argv[0]);
        return 1;
    }
    const char *mode = argv[optind];
    const char *archive = argv[optind + 1];
    const char *password = argv[optind + 2];
    if (strcmp(mode, "archive") != 0 && strcmp(mode, "extract") != 0 && strcmp(mode, "list") != 0) {
        fprintf(stderr, "Error: Invalid mode. Use 'archive', 'extract', or 'list'\n");
        print_help(argv[0]);
        return 1;
    }
    if (strcmp(mode, "archive") == 0 && dry_run && view_comment_flag) {
        fprintf(stderr, "Error: -vc/--view-comment cannot be used with -d/--dry-run in archive mode\n");
        print_help(argv[0]);
        return 1;
    }
    if (strcmp(mode, "archive") != 0 && comment) {
        fprintf(stderr, "Error: -c/--comment is only valid in archive mode\n");
        print_help(argv[0]);
        return 1;
    }
    if (strcmp(mode, "archive") != 0 && dry_run) {
        fprintf(stderr, "Error: -d/--dry-run is only valid in archive mode\n");
        print_help(argv[0]);
        return 1;
    }
    if (strcmp(mode, "archive") != 0 && compression_algo != COMPRESSION_LZMA) {
        fprintf(stderr, "Error: -ca/--compression-algo is only valid in archive mode\n");
        print_help(argv[0]);
        return 1;
    }
    if (strcmp(mode, "archive") != 0 && weak_password) {
        fprintf(stderr, "Error: -wk/--weak-password is only valid in archive mode\n");
        print_help(argv[0]);
        return 1;
    }
    if (strcmp(mode, "archive") != 0 && exclude) {
        fprintf(stderr, "Error: -x/--exclude is only valid in archive mode\n");
        print_help(argv[0]);
        return 1;
    }
    if (strcmp(mode, "list") == 0 && outdir) {
        fprintf(stderr, "Error: -o/--output-dir is not valid in list mode\n");
        print_help(argv[0]);
        return 1;
    }
    if (strcmp(mode, "archive") == 0) {
        if (argc - optind < 4) {
            fprintf(stderr, "Error: Need at least one file or directory to archive\n");
            return 1;
        }
        char **file_list = calloc(MAX_FILES, sizeof(char *));
        if (!file_list) {
            fprintf(stderr, "Error: Memory allocation failed for file list\n");
            return 1;
        }
        int file_count = 0;
        // Parse exclude patterns
        const char **exclude_patterns = NULL;
        int exclude_pattern_count = 0;
        char *exclude_copy = NULL;
        if (exclude) {
            exclude_copy = strdup(exclude);
            if (!exclude_copy) {
                fprintf(stderr, "Error: Memory allocation failed for exclude patterns\n");
                for (int j = 0; j < file_count; j++) free(file_list[j]);
                free(file_list);
                return 1;
            }
            exclude_pattern_count = 1;
            for (char *p = exclude_copy; *p; p++) {
                if (*p == ',') exclude_pattern_count++;
            }
            exclude_patterns = malloc(exclude_pattern_count * sizeof(char *));
            if (!exclude_patterns) {
                fprintf(stderr, "Error: Memory allocation failed for exclude patterns array\n");
                free(exclude_copy);
                for (int j = 0; j < file_count; j++) free(file_list[j]);
                free(file_list);
                return 1;
            }
            int i = 0;
            char *pattern = strtok(exclude_copy, ",");
            while (pattern) {
                exclude_patterns[i++] = pattern;
                pattern = strtok(NULL, ",");
            }
        }
        for (int i = optind + 3; i < argc; i++) {
            struct stat st;
            if (stat(argv[i], &st) != 0) {
                fprintf(stderr, "Error: Cannot stat %s: %s\n", argv[i], strerror(errno));
                for (int j = 0; j < file_count; j++) free(file_list[j]);
                free(file_list);
                if (exclude_patterns) {
                    free((char *)exclude_patterns[0]); // Free exclude_copy
                    free(exclude_patterns);
                }
                return 1;
            }
            if (S_ISDIR(st.st_mode)) {
                if (collect_files(argv[i], &file_list, &file_count, MAX_FILES, exclude_patterns, exclude_pattern_count) != 0) {
                    for (int j = 0; j < file_count; j++) free(file_list[j]);
                    free(file_list);
                    if (exclude_patterns) {
                        free((char *)exclude_patterns[0]); // Free exclude_copy
                        free(exclude_patterns);
                    }
                    return 1;
                }
            } else if (S_ISREG(st.st_mode)) {
                const char *filename = strrchr(argv[i], '/');
#ifdef _WIN32
                if (!filename) filename = strrchr(argv[i], '\\');
#endif
                filename = filename ? filename + 1 : argv[i];
                int exclude = 0;
                for (int j = 0; j < exclude_pattern_count; j++) {
                    if (matches_glob_pattern(filename, exclude_patterns[j])) {
                        verbose_print(VERBOSE_BASIC, "Excluding file: %s (matches pattern %s)", argv[i], exclude_patterns[j]);
                        exclude = 1;
                        break;
                    }
                }
                if (exclude) continue;
                if (file_count >= MAX_FILES) {
                    fprintf(stderr, "Error: Too many files (max %d)\n", MAX_FILES);
                    for (int j = 0; j < file_count; j++) free(file_list[j]);
                    free(file_list);
                    if (exclude_patterns) {
                        free((char *)exclude_patterns[0]); // Free exclude_copy
                        free(exclude_patterns);
                    }
                    return 1;
                }
                file_list[file_count] = strdup(argv[i]);
                if (!file_list[file_count]) {
                    fprintf(stderr, "Error: Memory allocation failed for file path\n");
                    for (int j = 0; j < file_count; j++) free(file_list[j]);
                    free(file_list);
                    if (exclude_patterns) {
                        free((char *)exclude_patterns[0]); // Free exclude_copy
                        free(exclude_patterns);
                    }
                    return 1;
                }
                file_count++;
                verbose_print(VERBOSE_DEBUG, "Added file: %s", argv[i]);
            } else {
                fprintf(stderr, "Error: %s is not a regular file or directory\n", argv[i]);
                for (int j = 0; j < file_count; j++) free(file_list[j]);
                free(file_list);
                if (exclude_patterns) {
                    free((char *)exclude_patterns[0]); // Free exclude_copy
                    free(exclude_patterns);
                }
                return 1;
            }
        }
        if (exclude_patterns) {
            free((char *)exclude_patterns[0]); // Free exclude_copy
            free(exclude_patterns);
        }
        verbose_print(VERBOSE_DEBUG, "Total files to archive: %d", file_count);
        for (int i = 0; i < file_count; i++) {
            verbose_print(VERBOSE_DEBUG, "File %d: %s", i, file_list[i]);
        }
        if (file_count == 0) {
            fprintf(stderr, "Error: No files to archive after applying exclusions\n");
            free(file_list);
            return 1;
        }
        int result = archive_files(archive, (const char **)file_list, file_count, password, force,
                                  compression_level, compression_algo, comment, dry_run, weak_password,
                                  outdir, exclude);
        for (int i = 0; i < file_count; i++) free(file_list[i]);
        free(file_list);
        return result;
    } else if (strcmp(mode, "extract") == 0) {
        if (view_comment_flag && view_comment(archive, password) != 0) {
            return 1;
        }
        return extract_files(archive, password, force, outdir);
    } else if (strcmp(mode, "list") == 0) {
        if (view_comment_flag && view_comment(archive, password) != 0) {
            return 1;
        }
        return list_files(archive, password);
    }
    return 1;
}