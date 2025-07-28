/**
 * @file view_comment.c
 * @brief View the comment in a Seclume archive.
 */

#include "seclume.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>

/**
 * @brief Displays the comment stored in a .slm archive.
 * @param archive Path to the input archive file (.slm).
 * @param password Password for decryption.
 * @return 0 on success, 1 on failure.
 */
int view_comment(const char *archive, const char *password) {
    if (!archive || !password) {
        fprintf(stderr, "Error: Invalid view comment parameters\n");
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
    if (strncmp(header.magic, "SLM", 4) != 0 || header.version < 4 || header.version > 6) {
        fprintf(stderr, "Error: Invalid archive format or version (expected 4-6, got %d)\n", header.version);
        fclose(in);
        return 1;
    }
    if (header.version >= 5 && header.compression_algo != COMPRESSION_ZLIB && header.compression_algo != COMPRESSION_LZMA) {
        fprintf(stderr, "Error: Invalid compression algorithm in header (%d)\n", header.compression_algo);
        fclose(in);
        return 1;
    }
    uint8_t meta_key[AES_KEY_SIZE];
    if (derive_key(password, header.salt, meta_key, "metadata encryption") != 0) {
        fclose(in);
        return 1;
    }
    verbose_print(VERBOSE_DEBUG, "Derived metadata encryption key");
    size_t hmac_size = offsetof(ArchiveHeader, hmac);
    uint8_t computed_hmac[HMAC_SIZE];
    uint8_t file_key[AES_KEY_SIZE];
    if (derive_key(password, header.salt, file_key, "file encryption") != 0) {
        secure_zero(meta_key, AES_KEY_SIZE);
        fclose(in);
        return 1;
    }
    if (compute_hmac(file_key, (uint8_t *)&header, hmac_size, computed_hmac) != 0) {
        secure_zero(file_key, AES_KEY_SIZE);
        secure_zero(meta_key, AES_KEY_SIZE);
        fclose(in);
        return 1;
    }
    secure_zero(file_key, AES_KEY_SIZE);
    if (memcmp(computed_hmac, header.hmac, HMAC_SIZE) != 0) {
        fprintf(stderr, "Error: Header HMAC verification failed\n");
        secure_zero(meta_key, AES_KEY_SIZE);
        fclose(in);
        return 1;
    }
    verbose_print(VERBOSE_DEBUG, "Verified header HMAC");
    if (header.comment_len == 0) {
        printf("Archive %s has no comment.\n", archive);
        secure_zero(meta_key, AES_KEY_SIZE);
        fclose(in);
        return 0;
    }
    if (header.comment_len > MAX_COMMENT - AES_NONCE_SIZE - AES_TAG_SIZE) {
        fprintf(stderr, "Error: Invalid comment length (%u)\n", header.comment_len);
        secure_zero(meta_key, AES_KEY_SIZE);
        fclose(in);
        return 1;
    }
    uint8_t *dec_comment = malloc(header.comment_len + 1);
    if (!dec_comment) {
        fprintf(stderr, "Error: Memory allocation failed for comment\n");
        secure_zero(meta_key, AES_KEY_SIZE);
        fclose(in);
        return 1;
    }
    size_t enc_comment_len = header.comment_len;
    const uint8_t *comment_nonce = header.comment + enc_comment_len;
    const uint8_t *comment_tag = comment_nonce + AES_NONCE_SIZE;
    size_t dec_len;
    if (decrypt_aes_gcm(meta_key, comment_nonce, header.comment, enc_comment_len, comment_tag, dec_comment, &dec_len) != 0) {
        fprintf(stderr, "Error: Failed to decrypt comment (possibly incorrect password)\n");
        free(dec_comment);
        secure_zero(meta_key, AES_KEY_SIZE);
        fclose(in);
        return 1;
    }
    if (dec_len != header.comment_len) {
        fprintf(stderr, "Error: Decrypted comment length mismatch (expected %u, got %lu)\n", header.comment_len, dec_len);
        free(dec_comment);
        secure_zero(meta_key, AES_KEY_SIZE);
        fclose(in);
        return 1;
    }
    dec_comment[dec_len] = '\0';
    for (size_t i = 0; i < dec_len; i++) {
        if (dec_comment[i] < 32 || dec_comment[i] > 126) {
            fprintf(stderr, "Error: Decrypted comment contains non-printable characters\n");
            free(dec_comment);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
    }
    printf("Comment in %s: %s\n", archive, (char *)dec_comment);
    free(dec_comment);
    secure_zero(meta_key, AES_KEY_SIZE);
    fclose(in);
    return 0;
}
