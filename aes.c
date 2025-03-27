#include "aes.h"
#include <string.h>

// This is a simplified implementation for demonstration
// In production, use a proper AES library like OpenSSL

void aesEncrypt(unsigned char *data, int dataLen, unsigned char *key, unsigned char *output) {
    // Simple XOR encryption for demonstration
    for (int i = 0; i < dataLen; i++) {
        output[i] = data[i] ^ key[i % 16];
    }
}

void aesDecrypt(unsigned char *data, int dataLen, unsigned char *key, unsigned char *output) {
    // For our simple XOR encryption, encryption and decryption are the same
    aesEncrypt(data, dataLen, key, output);
}
