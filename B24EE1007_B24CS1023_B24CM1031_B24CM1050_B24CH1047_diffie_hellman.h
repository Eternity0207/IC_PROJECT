#ifndef B24EE1007_B24CS1023_B24CM1031_B24CM1050_B24CH1047_DIFFIE_HELLMAN_H
#define B24EE1007_B24CS1023_B24CM1031_B24CM1050_B24CH1047_DIFFIE_HELLMAN_H

#define DH_KEY_SIZE 16

void generateDHKeyPair(unsigned char *privateKey, unsigned char *publicKey);

void generateSharedSecret(unsigned char *sharedSecret, 
                         unsigned char *privateKey, 
                         unsigned char *otherPublicKey);

#endif
