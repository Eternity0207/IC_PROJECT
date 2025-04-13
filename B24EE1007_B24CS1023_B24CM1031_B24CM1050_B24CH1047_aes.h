#ifndef B24EE1007_B24CS1023_B24CM1031_B24CM1050_B24CH1047_AES_H
#define B24EE1007_B24CS1023_B24CM1031_B24CM1050_B24CH1047_AES_H

#include <stddef.h>

void aesEncrypt(unsigned char *data, int dataLen, unsigned char *key, unsigned char *output);

int aesDecrypt(unsigned char *data, int dataLen, unsigned char *key, unsigned char *output);

#endif
