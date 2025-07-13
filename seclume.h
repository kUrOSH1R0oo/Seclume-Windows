/**
 * @file seclume.h
 * @brief Header file for Seclume: File Archiving Tool with AES-256-GCM encryption and zlib/LZMA compression.
 *
 * Defines common structures, constants, and function prototypes for the Seclume program.
 */

#ifndef SECLUME_H
#define SECLUME_H

#include <stdio.h>
#include <stdint.h>
#include <zlib.h>
#include <lzma.h>
#include <openssl/evp.h>
#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#include <io.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#endif

/** @brief Maximum number of files in an archive */
#define MAX_FILES 1000
/** @brief Maximum length of a filename (including null terminator) */
#define MAX_FILENAME 256
/** @brief Maximum file size (10GB) */
#define MAX_FILE_SIZE (10ULL << 30)
/** @brief AES-256 key size (32 bytes) */
#define AES_KEY_SIZE 32
/** @brief AES-GCM nonce size (12 bytes) */
#define AES_NONCE_SIZE 12
/** @brief AES-GCM authentication tag size (16 bytes) */
#define AES_TAG_SIZE 16
/** @brief PBKDF2 salt size (16 bytes) */
#define SALT_SIZE 16
/** @brief HMAC-SHA256 size (32 bytes) */
#define HMAC_SIZE 32
/** @brief Maximum length of archive comment (including encryption overhead) */
#define MAX_COMMENT 512
/** @brief Maximum length of output directory (including encryption overhead) */
#define MAX_OUTDIR 512

/**
 * @brief Compression algorithm types.
 */
typedef enum {
    COMPRESSION_ZLIB = 0, /**< zlib compression */
    COMPRESSION_LZMA = 1  /**< LZMA compression */
} CompressionAlgo;

/**
 * @brief Archive header structure stored at the beginning of a .slm file.
 */
typedef struct {
    char magic[8];           /**< Magic string "SLM" identifying the archive format */
    uint8_t version;         /**< Archive format version (4 for LZMA, 5 for zlib/LZMA, 6 for output dir) */
    uint32_t file_count;     /**< Number of files in the archive */
    uint8_t compression_level; /**< Compression level (0-9) */
    uint8_t compression_algo; /**< Compression algorithm (0 = zlib, 1 = LZMA) */
    uint8_t reserved[2];     /**< Reserved for future use (zeroed) */
    uint32_t comment_len;    /**< Length of encrypted comment */
    uint32_t outdir_len;     /**< Length of encrypted output directory (version 6) */
    uint8_t salt[SALT_SIZE]; /**< Random salt for PBKDF2 key derivation */
    uint8_t comment[MAX_COMMENT]; /**< Encrypted comment (includes nonce and tag) */
    uint8_t outdir[MAX_OUTDIR];  /**< Encrypted output directory (includes nonce and tag, version 6) */
    uint8_t hmac[HMAC_SIZE]; /**< HMAC-SHA256 of header (excluding this field) */
} ArchiveHeader;

/**
 * @brief Plaintext file entry structure (before encryption).
 */
typedef struct {
    char filename[MAX_FILENAME]; /**< Filename (null-terminated) */
    uint64_t compressed_size;   /**< Size of compressed and encrypted file data */
    uint64_t original_size;     /**< Original file size before compression */
    uint32_t mode;              /**< File permissions (POSIX st_mode) */
    uint32_t reserved;          /**< Reserved for future use (zeroed) */
} FileEntryPlain;

/**
 * @brief Encrypted file entry structure as stored in the archive.
 */
typedef struct {
    uint8_t nonce[AES_NONCE_SIZE];        /**< Nonce for metadata encryption */
    uint8_t tag[AES_TAG_SIZE];            /**< Authentication tag for metadata */
    uint8_t encrypted_data[sizeof(FileEntryPlain)]; /**< Encrypted filename and sizes */
} FileEntry;

/**
 * @brief Verbosity levels for logging.
 */
typedef enum {
    VERBOSE_NONE = 0,  /**< No output except errors */
    VERBOSE_BASIC = 1, /**< Basic progress output (default) */
    VERBOSE_DEBUG = 2  /**< Detailed debug output */
} VerbosityLevel;

/* Function prototypes from utils.c */
extern VerbosityLevel verbosity;
void mode_to_string(uint32_t mode, char *str);
void verbose_print(VerbosityLevel level, const char *fmt, ...);
void secure_zero(void *ptr, size_t len);
int derive_key(const char *password, const uint8_t *salt, uint8_t *key, const char *context);
int compute_hmac(const uint8_t *key, const uint8_t *data, size_t data_len, uint8_t *hmac);
int has_path_traversal(const char *path);
int check_password_strength(const char *password, int weak_password);
int matches_glob_pattern(const char *filename, const char *pattern);

/* Function prototypes from compression.c */
size_t compress_data(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max, int level, CompressionAlgo algo);
size_t decompress_data(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max, CompressionAlgo algo);

/* Function prototypes from encryption.c */
int encrypt_aes_gcm(const uint8_t *key, const uint8_t *nonce, const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t *out_len, uint8_t *tag);
int decrypt_aes_gcm(const uint8_t *key, const uint8_t *nonce, const uint8_t *in, size_t in_len,
                    const uint8_t *tag, uint8_t *out, size_t *out_len);

/* Function prototypes from file_ops.c */
int create_parent_dirs(const char *filepath);
int collect_files(const char *path, char ***file_list, int *file_count, int max_files);

/* Function prototypes from archive.c */
int archive_files(const char *output, const char **filenames, int file_count, const char *password,
                 int force, int compression_level, CompressionAlgo compression_algo, const char *comment,
                 int dry_run, int weak_password, const char *outdir, const char *exclude);

/* Function prototypes from extract.c */
int extract_files(const char *archive, const char *password, int force, const char *outdir);

/* Function prototypes from list.c */
int list_files(const char *archive, const char *password);

/* Function prototypes from view_comment.c */
int view_comment(const char *archive, const char *password);

/* Function prototypes from seclume_main.c */
void print_help(const char *prog_name);

#endif /* SECLUME_H */