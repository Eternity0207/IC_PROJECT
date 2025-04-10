#ifndef AES_H
#define AES_H

#include <stddef.h>

// Encrypt data using AES
void aesEncrypt(unsigned char *data, int dataLen, unsigned char *key, unsigned char *output);

// Decrypt data using AES
int aesDecrypt(unsigned char *data, int dataLen, unsigned char *key, unsigned char *output);

#endif
