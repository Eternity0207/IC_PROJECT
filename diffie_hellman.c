#include "diffie_hellman.h"
#include <stdlib.h>
#include <time.h>
#include <windows.h>

// Simple prime number for demonstration
const unsigned char prime[DH_KEY_SIZE] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd
};

// Primitive root
const unsigned char generator[DH_KEY_SIZE] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Generate random private key and compute public key
void generateDHKeyPair(unsigned char *privateKey, unsigned char *publicKey) {
    srand((unsigned int)time(NULL) + GetTickCount());
    
    // Generate random private key
    for (int i = 0; i < DH_KEY_SIZE; i++) {
        privateKey[i] = rand() % 256;
    }
    
    // Simple modular exponentiation for demonstration
    // In production, use a proper big integer library
    for (int i = 0; i < DH_KEY_SIZE; i++) {
        publicKey[i] = (generator[i] ^ privateKey[i]) % prime[i];
        if (publicKey[i] == 0) publicKey[i] = 1; // Avoid zeros
    }
}

// Generate shared secret using private key and other's public key
void generateSharedSecret(unsigned char *sharedSecret, 
                         unsigned char *privateKey, 
                         unsigned char *otherPublicKey) {
    // Simple modular exponentiation for demonstration
    for (int i = 0; i < DH_KEY_SIZE; i++) {
        sharedSecret[i] = (otherPublicKey[i] ^ privateKey[i]) % prime[i];
        if (sharedSecret[i] == 0) sharedSecret[i] = 1; // Avoid zeros
    }
}
