/**
 * @file encryption.c
 * @brief AES-256-GCM encryption and decryption functions for Seclume.
 */

#include "seclume.h"

/**
 * @brief Encrypts data using AES-256-GCM.
 * @param key AES-256 key (32 bytes).
 * @param nonce Nonce for GCM (12 bytes).
 * @param in Input data to encrypt.
 * @param in_len Length of input data.
 * @param out Output buffer for encrypted data.
 * @param out_len Pointer to store the length of encrypted data.
 * @param tag Output buffer for the authentication tag (16 bytes).
 * @return 0 on success, 1 on failure.
 */
int encrypt_aes_gcm(const uint8_t *key, const uint8_t *nonce, const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t *out_len, uint8_t *tag) {
    if (!key || !nonce || !in || !out || !out_len || !tag) {
        fprintf(stderr, "Error: Invalid encryption parameters\n");
        return 1;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: EVP_CIPHER_CTX_new failed\n");
        return 1;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        fprintf(stderr, "Error: AES-GCM encryption init failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    int len;
    if (EVP_EncryptUpdate(ctx, out, &len, in, in_len) != 1) {
        fprintf(stderr, "Error: AES-GCM encryption update failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    *out_len = len;
    if (EVP_EncryptFinal_ex(ctx, out + len, &len) != 1) {
        fprintf(stderr, "Error: AES-GCM encryption final failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    *out_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tag) != 1) {
        fprintf(stderr, "Error: AES-GCM tag retrieval failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/**
 * @brief Decrypts data using AES-256-GCM.
 * @param key AES-256 key (32 bytes).
 * @param nonce Nonce for GCM (12 bytes).
 * @param in Encrypted input data.
 * @param in_len Length of input data.
 * @param tag Authentication tag (16 bytes).
 * @param out Output buffer for decrypted data.
 * @param out_len Pointer to store the length of decrypted data.
 * @return 0 on success, 1 on failure.
 */
int decrypt_aes_gcm(const uint8_t *key, const uint8_t *nonce, const uint8_t *in, size_t in_len,
                    const uint8_t *tag, uint8_t *out, size_t *out_len) {
    if (!key || !nonce || !in || !tag || !out || !out_len) {
        fprintf(stderr, "Error: Invalid decryption parameters\n");
        return 1;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: EVP_CIPHER_CTX_new failed\n");
        return 1;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        fprintf(stderr, "Error: AES-GCM decryption init failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    int len;
    if (EVP_DecryptUpdate(ctx, out, &len, in, in_len) != 1) {
        fprintf(stderr, "Error: AES-GCM decryption update failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    *out_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE, (void *)tag) != 1) {
        fprintf(stderr, "Error: AES-GCM tag setting failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    if (EVP_DecryptFinal_ex(ctx, out + len, &len) <= 0) {
        fprintf(stderr, "Error: AES-GCM decryption final failed (wrong password or corrupted data?)\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    *out_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
