/**
 * @file utils.c
 * @brief Utility functions for Seclume.
 */

#include "seclume.h"
#include <string.h>
#include <stdarg.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <ctype.h>
#include <sys/stat.h>

/** @brief Global verbosity level */
VerbosityLevel verbosity = VERBOSE_BASIC;

/**
 * @brief Converts POSIX file mode to a string representation (e.g., "drw-r--r--").
 * @param mode POSIX file mode (st_mode).
 * @param str Output buffer (must be at least 11 bytes for "drwxrwxrwx\0").
 */
void mode_to_string(uint32_t mode, char *str) {
    str[0] = (S_ISDIR(mode)) ? 'd' : '-';
    str[1] = (mode & S_IRUSR) ? 'r' : '-';
    str[2] = (mode & S_IWUSR) ? 'w' : '-';
    str[3] = (mode & S_IXUSR) ? 'x' : '-';
    str[4] = (mode & S_IRGRP) ? 'r' : '-';
    str[5] = (mode & S_IWGRP) ? 'w' : '-';
    str[6] = (mode & S_IXGRP) ? 'x' : '-';
    str[7] = (mode & S_IROTH) ? 'r' : '-';
    str[8] = (mode & S_IWOTH) ? 'w' : '-';
    str[9] = (mode & S_IXOTH) ? 'x' : '-';
    str[10] = '\0';
}

/**
 * @brief Prints a message based on verbosity level.
 * @param level Required verbosity level for the message.
 * @param fmt Format string.
 * @param ... Arguments for the format string.
 */
void verbose_print(VerbosityLevel level, const char *fmt, ...) {
    if (verbosity < level) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

/**
 * @brief Securely zeros a memory region.
 * @param ptr Pointer to the memory.
 * @param len Length of the memory region.
 */
void secure_zero(void *ptr, size_t len) {
    if (!ptr) return;
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

/**
 * @brief Derives a key using PBKDF2 with SHA256.
 * @param password Input password.
 * @param salt Salt for PBKDF2.
 * @param key Output buffer for the derived key (AES_KEY_SIZE bytes).
 * @param context Context string for PBKDF2.
 * @return 0 on success, 1 on failure.
 */
int derive_key(const char *password, const uint8_t *salt, uint8_t *key, const char *context) {
    char info[256];
    snprintf(info, sizeof(info), "seclume:%s", context);
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, 1000000,
                            EVP_sha256(), AES_KEY_SIZE, key)) {
        fprintf(stderr, "Error: Key derivation failed for %s\n", context);
        return 1;
    }
    return 0;
}

/**
 * @brief Computes HMAC-SHA256 of data.
 * @param key Key for HMAC.
 * @param data Input data.
 * @param data_len Length of input data.
 * @param hmac Output buffer for HMAC (HMAC_SIZE bytes).
 * @return 0 on success, 1 on failure.
 */
int compute_hmac(const uint8_t *key, const uint8_t *data, size_t data_len, uint8_t *hmac) {
    unsigned int len = HMAC_SIZE;
    if (!HMAC(EVP_sha256(), key, AES_KEY_SIZE, data, data_len, hmac, &len) || len != HMAC_SIZE) {
        fprintf(stderr, "Error: HMAC computation failed\n");
        return 1;
    }
    return 0;
}

/**
 * @brief Checks for path traversal in a filename.
 * @param path Filename to check.
 * @return 1 if path traversal is detected, 0 otherwise.
 */
int has_path_traversal(const char *path) {
    if (!path) return 1;
    const char *p = path;
    while (*p) {
        if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\\' || p[2] == '\0')) {
            return 1;
        }
        p++;
    }
    return 0;
}

/**
 * @brief Checks password strength.
 * @param password Password to check.
 * @param weak_password If 1, allow weak passwords (archive mode only).
 * @return 0 if strong or weak_password is 1, 1 if weak and weak_password is 0.
 */
int check_password_strength(const char *password, int weak_password) {
    if (!password || strlen(password) < 8) {
        if (!weak_password) {
            fprintf(stderr, "Error: Password is too short (minimum 8 characters)\n");
            return 1;
        }
        verbose_print(VERBOSE_BASIC, "Warning: Password is too short (minimum 8 characters)");
        return 0;
    }
    int has_lower = 0, has_upper = 0, has_digit = 0, has_special = 0;
    for (const char *p = password; *p; p++) {
        if (islower(*p)) has_lower = 1;
        else if (isupper(*p)) has_upper = 1;
        else if (isdigit(*p)) has_digit = 1;
        else if (*p >= 33 && *p <= 126) has_special = 1;
    }
    if (has_lower && has_upper && has_digit && has_special) {
        return 0;
    }
    if (!weak_password) {
        fprintf(stderr, "Error: Password is weak (must include lowercase, uppercase, digits, and special characters)\n");
        return 1;
    }
    verbose_print(VERBOSE_BASIC, "Warning: Password is weak (lacks variety). Include lowercase, uppercase, digits, and special characters.");
    return 0;
}

/**
 * @brief Checks if a filename matches a glob pattern (Windows-compatible).
 * @param filename Filename to check.
 * @param pattern Glob pattern (e.g., "*.log").
 * @return 1 if the filename matches the pattern, 0 otherwise.
 */
int matches_glob_pattern(const char *filename, const char *pattern) {
    if (!filename || !pattern) return 0;
    const char *f = filename;
    const char *p = pattern;
    while (*f && *p) {
        if (*p == '*') {
            p++;
            if (!*p) return 1; // * at end matches rest
            while (*f) {
                if (matches_glob_pattern(f, p)) return 1;
                f++;
            }
            return 0;
        } else if (*p == '?') {
            f++;
            p++;
        } else if (*f == *p || (*f == '\\' && *p == '/')) {
            f++;
            p++;
        } else {
            return 0;
        }
    }
    return *f == '\0' && *p == '\0';
}