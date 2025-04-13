#include "B24EE1007_B24CS1023_B24CM1031_B24CM1050_B24CH1047_aes.h"
#include <openssl/evp.h> 
#include <openssl/rand.h> 
#include <string.h>

void aesEncrypt(unsigned char *data, int dataLen, unsigned char *key, unsigned char *output) {
    EVP_CIPHER_CTX *ctx; //Encryption context
    int len;
    int ciphertext_len;

    //Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return;
    }

    //Generate a random 16-byte IV (Initialization Vector)
    unsigned char iv[16];
    RAND_bytes(iv, 16);

    //Initialize encryption operation with AES-256-CBC, key, and IV
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    //Encrypt the data. Output is placed after the first 16 bytes i.e. the IV
    if (1 != EVP_EncryptUpdate(ctx, output + 16, &len, data, dataLen)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len = len;

    //Finalize encryption and write all remaining bytes
    if (1 != EVP_EncryptFinal_ex(ctx, output + 16 + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len += len;

    //Prepend the IV to the beginning of the output buffer
    memcpy(output, iv, 16);

    //Clean up the context
    EVP_CIPHER_CTX_free(ctx);
}

int aesDecrypt(unsigned char *data, int dataLen, unsigned char *key, unsigned char *output) {
    EVP_CIPHER_CTX *ctx; // Decryption context
    int len;
    int plaintext_len;

    unsigned char iv[16];

    //Extract the IV from the first 16 bytes of input
    memcpy(iv, data, 16);

    //Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }

    //Initialize decryption operation with AES-256-CBC, key, and IV
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    //Decrypt the ciphertext (excluding the first 16 IV bytes)
    if (1 != EVP_DecryptUpdate(ctx, output, &len, data + 16, dataLen - 16)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    //Finalize decryption and handle padding
    if (1 != EVP_DecryptFinal_ex(ctx, output + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    //Clean up the context
    EVP_CIPHER_CTX_free(ctx);

    //Return total plaintext length
    return plaintext_len;
}
