#include "diffie_hellman.h"
#include <openssl/dh.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>

// We'll use standard DH parameters from OpenSSL
#define DH_KEY_SIZE 256 // We want 256-byte (2048-bit) shared secret

// Global DH parameters to be used by both key generation and shared secret computation
static DH *global_dh = NULL;
static BIGNUM *p = NULL;
static BIGNUM *g = NULL;

// Initialize DH parameters once
void initDHParameters() {
    if (global_dh != NULL) {
        return; // Already initialized
    }
    
    // Create DH parameters - using 2048 bits for strong security
    global_dh = DH_new();
    if (global_dh == NULL) {
        // Handle error
        return;
    }
    
    // Generate 2048-bit DH parameters
    if (!DH_generate_parameters_ex(global_dh, 2048, DH_GENERATOR_2, NULL)) {
        DH_free(global_dh);
        global_dh = NULL;
        return;
    }
    
    // Check the parameters
    int codes = 0;
    if (!DH_check(global_dh, &codes)) {
        DH_free(global_dh);
        global_dh = NULL;
        return;
    }
    
    // Store p and g parameters for later use
    DH_get0_pqg(global_dh, (const BIGNUM **)&p, NULL, (const BIGNUM **)&g);
    // Make copies to ensure they don't get freed
    p = BN_dup(p);
    g = BN_dup(g);
}

// Clean up resources
void cleanupDHParameters() {
    if (global_dh) {
        DH_free(global_dh);
        global_dh = NULL;
    }
    if (p) {
        BN_free(p);
        p = NULL;
    }
    if (g) {
        BN_free(g);
        g = NULL;
    }
}

// Generate random private key and compute public key
void generateDHKeyPair(unsigned char *privateKey, unsigned char *publicKey) {
    // Make sure parameters are initialized
    initDHParameters();
    if (global_dh == NULL) {
        return;
    }
    
    // Create a new DH instance using the same parameters
    DH *dh = DH_new();
    if (dh == NULL) {
        return;
    }
    
    // Set the same parameters
    if (!DH_set0_pqg(dh, BN_dup(p), NULL, BN_dup(g))) {
        DH_free(dh);
        return;
    }
    
    // Generate the key pair
    if (!DH_generate_key(dh)) {
        DH_free(dh);
        return;
    }
    
    // Extract the private and public keys
    const BIGNUM *priv_key = DH_get0_priv_key(dh);
    const BIGNUM *pub_key = DH_get0_pub_key(dh);
    
    // Convert to byte arrays
    int priv_len = BN_bn2bin(priv_key, privateKey);
    int pub_len = BN_bn2bin(pub_key, publicKey);
    
    // Pad with zeros if necessary to ensure full DH_KEY_SIZE
    if (priv_len < DH_KEY_SIZE) {
        memmove(privateKey + (DH_KEY_SIZE - priv_len), privateKey, priv_len);
        memset(privateKey, 0, DH_KEY_SIZE - priv_len);
    }
    
    if (pub_len < DH_KEY_SIZE) {
        memmove(publicKey + (DH_KEY_SIZE - pub_len), publicKey, pub_len);
        memset(publicKey, 0, DH_KEY_SIZE - pub_len);
    }
    
    DH_free(dh);
}

// Generate shared secret using private key and other's public key
void generateSharedSecret(unsigned char *sharedSecret, 
                         unsigned char *privateKey, 
                         unsigned char *otherPublicKey) {
    // Make sure parameters are initialized
    initDHParameters();
    if (global_dh == NULL) {
        return;
    }
    
    DH *dh = DH_new();
    BIGNUM *priv_key = NULL;
    BIGNUM *pub_key = NULL;
    int secret_len;
    
    if (dh == NULL) {
        return;
    }
    
    // Set the same parameters
    if (!DH_set0_pqg(dh, BN_dup(p), NULL, BN_dup(g))) {
        DH_free(dh);
        return;
    }
    
    // Convert input keys to BIGNUM format
    priv_key = BN_bin2bn(privateKey, DH_KEY_SIZE, NULL);
    pub_key = BN_bin2bn(otherPublicKey, DH_KEY_SIZE, NULL);
    
    if (!priv_key || !pub_key) {
        if (priv_key) BN_free(priv_key);
        if (pub_key) BN_free(pub_key);
        DH_free(dh);
        return;
    }
    
    // Set the private key
    if (!DH_set0_key(dh, BN_dup(priv_key), NULL)) {
        BN_free(priv_key);
        BN_free(pub_key);
        DH_free(dh);
        return;
    }
    
    // Compute the shared secret
    secret_len = DH_compute_key(sharedSecret, pub_key, dh);
    
    if (secret_len <= 0) {
        BN_free(priv_key);
        BN_free(pub_key);
        DH_free(dh);
        return;
    }
    
    // If the secret is shorter than DH_KEY_SIZE, pad with zeros
    if (secret_len < DH_KEY_SIZE) {
        memmove(sharedSecret + (DH_KEY_SIZE - secret_len), sharedSecret, secret_len);
        memset(sharedSecret, 0, DH_KEY_SIZE - secret_len);
    }
    
    // Hash the shared secret to get a consistent key material
    // Using SHA-512 and proper KDF techniques
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(sharedSecret, secret_len, hash);
    
    // For 256 bytes, we use HKDF-like approach
    // This is a simplified version - in production use a proper KDF
    unsigned char expanded[DH_KEY_SIZE];
    unsigned char counter = 1;
    size_t pos = 0;
    
    while (pos < DH_KEY_SIZE) {
        unsigned char hmac_input[SHA512_DIGEST_LENGTH + 1];
        memcpy(hmac_input, hash, SHA512_DIGEST_LENGTH);
        hmac_input[SHA512_DIGEST_LENGTH] = counter;
        
        unsigned char round_hash[SHA512_DIGEST_LENGTH];
        SHA512(hmac_input, SHA512_DIGEST_LENGTH + 1, round_hash);
        
        size_t to_copy = (DH_KEY_SIZE - pos < SHA512_DIGEST_LENGTH) ? 
                          DH_KEY_SIZE - pos : SHA512_DIGEST_LENGTH;
        memcpy(expanded + pos, round_hash, to_copy);
        
        pos += to_copy;
        counter++;
    }
    
    // Copy the expanded key material to the output
    memcpy(sharedSecret, expanded, DH_KEY_SIZE);
    
    BN_free(priv_key);
    BN_free(pub_key);
    DH_free(dh);
}