#include "B24EE1007_B24CS1023_B24CM1031_B24CM1050_B24CH1047_aes.h"
#include <openssl/evp.h> 
#include <openssl/rand.h> 
#include <string.h>

void aesEncrypt(unsigned char *data, int dataLen, unsigned char *key, unsigned char *output) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return;
    }

    unsigned char iv[16];
    RAND_bytes(iv, 16);

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (1 != EVP_EncryptUpdate(ctx, output + 16, &len, data, dataLen)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, output + 16 + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len += len;

    memcpy(output, iv, 16);

    EVP_CIPHER_CTX_free(ctx);
}

int aesDecrypt(unsigned char *data, int dataLen, unsigned char *key, unsigned char *output) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    unsigned char iv[16];
    memcpy(iv, data, 16);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_DecryptUpdate(ctx, output, &len, data + 16, dataLen - 16)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, output + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
