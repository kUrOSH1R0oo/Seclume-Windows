/**
 * @file file_ops.c
 * @brief File and directory operations for Seclume.
 */

#include "seclume.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#include <sys/stat.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#endif

/** @brief Maximum allowed path length (including null terminator) */
#define MAX_PATH_LENGTH 4096
/** @brief Maximum allowed filename component length (including null terminator) */
#define MAX_NAME_LENGTH 256

/**
 * @brief Normalizes path separators to the platform's convention.
 * @param path Input path to modify.
 * @param normalized Output buffer for normalized path.
 * @param max_len Maximum length of the output buffer.
 */
#ifdef _WIN32
static void normalize_path(const char *path, char *normalized, size_t max_len) {
    if (!path || !normalized) return;
    size_t i;
    for (i = 0; i < max_len - 1 && path[i]; i++) {
        normalized[i] = (path[i] == '/') ? '\\' : path[i];
    }
    normalized[i] = '\0';
}
#else
static void normalize_path(const char *path, char *normalized, size_t max_len) {
    if (!path || !normalized) return;
    strncpy(normalized, path, max_len - 1);
    normalized[max_len - 1] = '\0';
}
#endif

/**
 * @brief Creates parent directories for a given filepath.
 * @param filepath File path whose parent directories need to be created.
 * @return 0 on success, 1 on failure.
 */
int create_parent_dirs(const char *filepath) {
    if (!filepath) return 1;

    size_t filepath_len = strlen(filepath) + 1;
    if (filepath_len > MAX_PATH_LENGTH) {
        fprintf(stderr, "Error: Filepath too long: %s (max %d bytes)\n", filepath, MAX_PATH_LENGTH - 1);
        return 1;
    }

    char *path = malloc(filepath_len);
    if (!path) {
        fprintf(stderr, "Error: Memory allocation failed for path\n");
        return 1;
    }

    normalize_path(filepath, path, filepath_len);
    char *p = path;

#ifdef _WIN32
    if (strlen(path) >= 2 && path[1] == ':') p += 2;
#endif
    while (*p == '/' || *p == '\\') p++;
    while (*p) {
        if (*p == '/' || *p == '\\') {
            *p = '\0';
#ifdef _WIN32
            if (_mkdir(path) != 0 && errno != EEXIST) {
#else
            if (mkdir(path, 0700) != 0 && errno != EEXIST) {
#endif
                fprintf(stderr, "Error: Failed to create directory %s: %s\n", path, strerror(errno));
                free(path);
                return 1;
            }
            *p = '/'; // Use forward slash for consistency; normalize_path handles Windows
        }
        p++;
    }
    free(path);
    return 0;
}

/**
 * @brief Recursively collects files from a directory or adds a single file, excluding specified patterns.
 * @param path File or directory path to process.
 * @param file_list Pointer to array of file paths (allocated and filled).
 * @param file_count Pointer to the number of files collected.
 * @param max_files Maximum number of files allowed.
 * @param exclude_patterns Array of exclusion patterns (e.g., "*.log").
 * @param exclude_pattern_count Number of exclusion patterns.
 * @return 0 on success, 1 on failure.
 */
int collect_files(const char *path, char ***file_list, int *file_count, int max_files, const char **exclude_patterns, int exclude_pattern_count) {
    if (!path || !file_list || !file_count || max_files <= 0) {
        fprintf(stderr, "Error: Invalid collect_files parameters\n");
        return 1;
    }
    *file_count = 0;
    *file_list = NULL;

    size_t path_len = strlen(path);
    if (path_len >= MAX_PATH_LENGTH - MAX_NAME_LENGTH - 1) { // Reserve space for max filename + separator
        fprintf(stderr, "Error: Path too long: %s (max %d bytes, accounting for filename)\n",
                path, MAX_PATH_LENGTH - MAX_NAME_LENGTH - 2);
        return 1;
    }

    char *normalized_path = malloc(path_len + 1);
    if (!normalized_path) {
        fprintf(stderr, "Error: Memory allocation failed for normalized path\n");
        return 1;
    }
    normalize_path(path, normalized_path, path_len + 1);

#ifdef _WIN32
    struct _stat64 st;
    if (_stat64(normalized_path, &st) != 0) {
        fprintf(stderr, "Error: Cannot stat path %s: %s\n", normalized_path, strerror(errno));
        free(normalized_path);
        return 1;
    }
    if (!(st.st_mode & _S_IFDIR)) {
        const char *filename = strrchr(normalized_path, '\\');
        filename = filename ? filename + 1 : normalized_path;
        for (int i = 0; i < exclude_pattern_count; i++) {
            if (matches_glob_pattern(filename, exclude_patterns[i])) {
                verbose_print(VERBOSE_BASIC, "Excluding file: %s (matches pattern %s)", normalized_path, exclude_patterns[i]);
                free(normalized_path);
                return 0;
            }
        }
        *file_list = malloc(sizeof(char *));
        if (!*file_list) {
            fprintf(stderr, "Error: Memory allocation failed for file list\n");
            free(normalized_path);
            return 1;
        }
        (*file_list)[0] = strdup(normalized_path);
        if (!(*file_list)[0]) {
            fprintf(stderr, "Error: Memory allocation failed for file path\n");
            free(*file_list);
            *file_list = NULL;
            free(normalized_path);
            return 1;
        }
        *file_count = 1;
        verbose_print(VERBOSE_DEBUG, "Collected file: %s", normalized_path);
        free(normalized_path);
        return 0;
    }
    // Directory: use FindFirstFile/FindNextFile
    WIN32_FIND_DATA ffd;
    size_t search_path_len = path_len + 3; // +3 for "\*" and null terminator
    char *search_path = malloc(search_path_len);
    if (!search_path) {
        fprintf(stderr, "Error: Memory allocation failed for search path\n");
        free(normalized_path);
        return 1;
    }
    snprintf(search_path, search_path_len, "%s\\*", normalized_path);
    verbose_print(VERBOSE_DEBUG, "Searching directory: %s", search_path);
    HANDLE hFind = FindFirstFile(search_path, &ffd);
    free(search_path);
    if (hFind == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error: Cannot open directory %s: %lu\n", normalized_path, GetLastError());
        free(normalized_path);
        return 1;
    }
    *file_list = malloc(max_files * sizeof(char *));
    if (!*file_list) {
        fprintf(stderr, "Error: Memory allocation failed for file list\n");
        FindClose(hFind);
        free(normalized_path);
        return 1;
    }
    do {
        if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) continue;

        size_t name_len = strlen(ffd.cFileName);
        if (name_len >= MAX_NAME_LENGTH) {
            fprintf(stderr, "Error: Filename component too long: %s (max %d bytes)\n",
                    ffd.cFileName, MAX_NAME_LENGTH - 1);
            for (int i = 0; i < *file_count; i++) free((*file_list)[i]);
            free(*file_list);
            *file_list = NULL;
            FindClose(hFind);
            free(normalized_path);
            return 1;
        }

        size_t full_path_len = path_len + name_len + 2; // +2 for '\\' and null terminator
        if (full_path_len >= MAX_PATH_LENGTH) {
            fprintf(stderr, "Error: Path too long: %s\\%s (max %d bytes)\n",
                    normalized_path, ffd.cFileName, MAX_PATH_LENGTH - 1);
            for (int i = 0; i < *file_count; i++) free((*file_list)[i]);
            free(*file_list);
            *file_list = NULL;
            FindClose(hFind);
            free(normalized_path);
            return 1;
        }

        char *full_path = malloc(full_path_len);
        if (!full_path) {
            fprintf(stderr, "Error: Memory allocation failed for file path\n");
            for (int i = 0; i < *file_count; i++) free((*file_list)[i]);
            free(*file_list);
            *file_list = NULL;
            FindClose(hFind);
            free(normalized_path);
            return 1;
        }
        snprintf(full_path, full_path_len, "%s\\%s", normalized_path, ffd.cFileName);
        verbose_print(VERBOSE_DEBUG, "Processing path: %s", full_path);

        if (has_path_traversal(full_path)) {
            fprintf(stderr, "Error: Path traversal detected in %s\n", full_path);
            free(full_path);
            for (int i = 0; i < *file_count; i++) free((*file_list)[i]);
            free(*file_list);
            *file_list = NULL;
            FindClose(hFind);
            free(normalized_path);
            return 1;
        }

        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            char **subdir_list = NULL;
            int subdir_count = 0;
            verbose_print(VERBOSE_DEBUG, "Entering subdirectory: %s", full_path);
            if (collect_files(full_path, &subdir_list, &subdir_count, max_files - *file_count, exclude_patterns, exclude_pattern_count) != 0) {
                free(full_path);
                for (int i = 0; i < *file_count; i++) free((*file_list)[i]);
                free(*file_list);
                *file_list = NULL;
                FindClose(hFind);
                free(normalized_path);
                return 1;
            }
            for (int i = 0; i < subdir_count; i++) {
                if (*file_count >= max_files) {
                    fprintf(stderr, "Error: Too many files (max %d)\n", max_files);
                    for (int j = 0; j < subdir_count; j++) free(subdir_list[j]);
                    free(subdir_list);
                    for (int j = 0; j < *file_count; j++) free((*file_list)[j]);
                    free(*file_list);
                    *file_list = NULL;
                    free(full_path);
                    FindClose(hFind);
                    free(normalized_path);
                    return 1;
                }
                (*file_list)[*file_count] = subdir_list[i];
                (*file_count)++;
            }
            free(subdir_list);
            free(full_path);
        } else {
            int exclude = 0;
            for (int i = 0; i < exclude_pattern_count; i++) {
                if (matches_glob_pattern(ffd.cFileName, exclude_patterns[i])) {
                    verbose_print(VERBOSE_BASIC, "Excluding file: %s (matches pattern %s)", full_path, exclude_patterns[i]);
                    exclude = 1;
                    break;
                }
            }
            if (!exclude) {
                if (*file_count >= max_files) {
                    fprintf(stderr, "Error: Too many files (max %d)\n", max_files);
                    free(full_path);
                    for (int i = 0; i < *file_count; i++) free((*file_list)[i]);
                    free(*file_list);
                    *file_list = NULL;
                    FindClose(hFind);
                    free(normalized_path);
                    return 1;
                }
                (*file_list)[*file_count] = strdup(full_path);
                if (!(*file_list)[*file_count]) {
                    fprintf(stderr, "Error: Memory allocation failed for file path\n");
                    free(full_path);
                    for (int i = 0; i < *file_count; i++) free((*file_list)[i]);
                    free(*file_list);
                    *file_list = NULL;
                    FindClose(hFind);
                    free(normalized_path);
                    return 1;
                }
                verbose_print(VERBOSE_DEBUG, "Collected file: %s", full_path);
                (*file_count)++;
            }
            free(full_path);
        }
    } while (FindNextFile(hFind, &ffd) != 0);
    FindClose(hFind);
    free(normalized_path);
#else
    struct stat st;
    if (stat(normalized_path, &st) != 0) {
        fprintf(stderr, "Error: Cannot stat path %s: %s\n", normalized_path, strerror(errno));
        free(normalized_path);
        return 1;
    }
    if (!S_ISDIR(st.st_mode)) {
        const char *filename = strrchr(normalized_path, '/');
        filename = filename ? filename + 1 : normalized_path;
        for (int i = 0; i < exclude_pattern_count; i++) {
            if (matches_glob_pattern(filename, exclude_patterns[i])) {
                verbose_print(VERBOSE_BASIC, "Excluding file: %s (matches pattern %s)", normalized_path, exclude_patterns[i]);
                free(normalized_path);
                return 0;
            }
        }
        *file_list = malloc(sizeof(char *));
        if (!*file_list) {
            fprintf(stderr, "Error: Memory allocation failed for file list\n");
            free(normalized_path);
            return 1;
        }
        (*file_list)[0] = strdup(normalized_path);
        if (!(*file_list)[0]) {
            fprintf(stderr, "Error: Memory allocation failed for file path\n");
            free(*file_list);
            *file_list = NULL;
            free(normalized_path);
            return 1;
        }
        *file_count = 1;
        verbose_print(VERBOSE_DEBUG, "Collected file: %s", normalized_path);
        free(normalized_path);
        return 0;
    }
    // Directory: use opendir/readdir
    DIR *dir = opendir(normalized_path);
    if (!dir) {
        fprintf(stderr, "Error: Cannot open directory %s: %s\n", normalized_path, strerror(errno));
        free(normalized_path);
        return 1;
    }
    verbose_print(VERBOSE_DEBUG, "Searching directory: %s", normalized_path);
    *file_list = malloc(max_files * sizeof(char *));
    if (!*file_list) {
        fprintf(stderr, "Error: Memory allocation failed for file list\n");
        closedir(dir);
        free(normalized_path);
        return 1;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        size_t name_len = strlen(entry->d_name);
        if (name_len >= MAX_NAME_LENGTH) {
            fprintf(stderr, "Error: Filename component too long: %s (max %d bytes)\n",
                    entry->d_name, MAX_NAME_LENGTH - 1);
            for (int i = 0; i < *file_count; i++) free((*file_list)[i]);
            free(*file_list);
            *file_list = NULL;
            closedir(dir);
            free(normalized_path);
            return 1;
        }

        // Calculate full path length
        size_t full_path_len = path_len + name_len + 2; // +2 for '/' and null terminator
        if (full_path_len >= MAX_PATH_LENGTH) {
            fprintf(stderr, "Error: Path too long: %s/%s (max %d bytes)\n",
                    normalized_path, entry->d_name, MAX_PATH_LENGTH - 1);
            for (int i = 0; i < *file_count; i++) free((*file_list)[i]);
            free(*file_list);
            *file_list = NULL;
            closedir(dir);
            free(normalized_path);
            return 1;
        }

        char *full_path = malloc(full_path_len);
        if (!full_path) {
            fprintf(stderr, "Error: Memory allocation failed for file path\n");
            for (int i = 0; i < *file_count; i++) free((*file_list)[i]);
            free(*file_list);
            *file_list = NULL;
            closedir(dir);
            free(normalized_path);
            return 1;
        }
        snprintf(full_path, full_path_len, "%s/%s", normalized_path, entry->d_name);
        verbose_print(VERBOSE_DEBUG, "Processing path: %s", full_path);

        if (has_path_traversal(full_path)) {
            fprintf(stderr, "Error: Path traversal detected in %s\n", full_path);
            free(full_path);
            for (int i = 0; i < *file_count; i++) free((*file_list)[i]);
            free(*file_list);
            *file_list = NULL;
            closedir(dir);
            free(normalized_path);
            return 1;
        }

        struct stat entry_st;
        if (stat(full_path, &entry_st) != 0) {
            fprintf(stderr, "Error: Cannot stat %s: %s\n", full_path, strerror(errno));
            free(full_path);
            for (int i = 0; i < *file_count; i++) free((*file_list)[i]);
            free(*file_list);
            *file_list = NULL;
            closedir(dir);
            free(normalized_path);
            return 1;
        }

        if (S_ISDIR(entry_st.st_mode)) {
            char **subdir_list = NULL;
            int subdir_count = 0;
            verbose_print(VERBOSE_DEBUG, "Entering subdirectory: %s", full_path);
            if (collect_files(full_path, &subdir_list, &subdir_count, max_files - *file_count, exclude_patterns, exclude_pattern_count) != 0) {
                free(full_path);
                for (int i = 0; i < *file_count; i++) free((*file_list)[i]);
                free(*file_list);
                *file_list = NULL;
                closedir(dir);
                free(normalized_path);
                return 1;
            }
            for (int i = 0; i < subdir_count; i++) {
                if (*file_count >= max_files) {
                    fprintf(stderr, "Error: Too many files (max %d)\n", max_files);
                    for (int j = 0; j < subdir_count; j++) free(subdir_list[j]);
                    free(subdir_list);
                    for (int j = 0; j < *file_count; j++) free((*file_list)[j]);
                    free(*file_list);
                    *file_list = NULL;
                    free(full_path);
                    closedir(dir);
                    free(normalized_path);
                    return 1;
                }
                (*file_list)[*file_count] = subdir_list[i];
                (*file_count)++;
            }
            free(subdir_list);
            free(full_path);
        } else {
            int exclude = 0;
            for (int i = 0; i < exclude_pattern_count; i++) {
                if (matches_glob_pattern(entry->d_name, exclude_patterns[i])) {
                    verbose_print(VERBOSE_BASIC, "Excluding file: %s (matches pattern %s)", full_path, exclude_patterns[i]);
                    exclude = 1;
                    break;
                }
            }
            if (!exclude) {
                if (*file_count >= max_files) {
                    fprintf(stderr, "Error: Too many files (max %d)\n", max_files);
                    free(full_path);
                    for (int i = 0; i < *file_count; i++) free((*file_list)[i]);
                    free(*file_list);
                    *file_list = NULL;
                    closedir(dir);
                    free(normalized_path);
                    return 1;
                }
                (*file_list)[*file_count] = strdup(full_path);
                if (!(*file_list)[*file_count]) {
                    fprintf(stderr, "Error: Memory allocation failed for file path\n");
                    free(full_path);
                    for (int i = 0; i < *file_count; i++) free((*file_list)[i]);
                    free(*file_list);
                    *file_list = NULL;
                    closedir(dir);
                    free(normalized_path);
                    return 1;
                }
                verbose_print(VERBOSE_DEBUG, "Collected file: %s", full_path);
                (*file_count)++;
            }
            free(full_path);
        }
    }
    closedir(dir);
    free(normalized_path);
#endif
    verbose_print(VERBOSE_DEBUG, "Total files collected from %s: %d", path, *file_count);
    return 0;
}