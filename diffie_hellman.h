#ifndef DIFFIE_HELLMAN_H
#define DIFFIE_HELLMAN_H

#define DH_KEY_SIZE 16

// Generate a random private key and calculate the corresponding public key
void generateDHKeyPair(unsigned char *privateKey, unsigned char *publicKey);

// Generate the shared secret using your private key and the other party's public key
void generateSharedSecret(unsigned char *sharedSecret, 
                         unsigned char *privateKey, 
                         unsigned char *otherPublicKey);

#endif
