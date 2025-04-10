#include "aes.h"
#include <openssl/evp.h> // For AES encryption
#include <openssl/rand.h> // For IV generation
#include <string.h>

void aesEncrypt(unsigned char *data, int dataLen, unsigned char *key, unsigned char *output) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        // Handle error
        return;
    }

    // Generate a random 128-bit IV
    unsigned char iv[16];
    RAND_bytes(iv, 16);

    // Initialize encryption operation with AES-256-CBC
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // Provide the message to be encrypted
    if (1 != EVP_EncryptUpdate(ctx, output + 16, &len, data, dataLen)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len = len;

    // Finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, output + 16 + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len += len;

    // Prepend the IV to the ciphertext (first 16 bytes)
    memcpy(output, iv, 16);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
}

int aesDecrypt(unsigned char *data, int dataLen, unsigned char *key, unsigned char *output) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // Extract the IV (first 16 bytes)
    unsigned char iv[16];
    memcpy(iv, data, 16);

    // Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1; // error
    }

    // Initialize decryption operation with AES-256-CBC
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1; // error
    }

    // Provide the message to be decrypted (skip IV)
    if (1 != EVP_DecryptUpdate(ctx, output, &len, data + 16, dataLen - 16)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1; // error
    }
    plaintext_len = len;

    // Finalize the decryption
    if (1 != EVP_DecryptFinal_ex(ctx, output + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1; // error (e.g., padding mismatch)
    }
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
