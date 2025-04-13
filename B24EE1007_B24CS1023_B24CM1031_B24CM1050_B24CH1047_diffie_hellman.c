#include "B24EE1007_B24CS1023_B24CM1031_B24CM1050_B24CH1047_diffie_hellman.h"
#include <openssl/dh.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>

//Key size in bytes (2048 bits)
//Higher key size = More secure(rquires more computational power to brute force)
#define DH_KEY_SIZE 256  

//DHKE Parameters
static DH *global_dh = NULL;
static BIGNUM *p = NULL;  // Prime modulus
static BIGNUM *g = NULL;  // Generator

//Initializing DHKE parameters (2048-bit prime and generator)
//Using OpenSSL to generate secure parameters only once
void initDHParameters() {
    if (global_dh != NULL) {
        return;  // Already initialized
    }
    global_dh = DH_new();  // Allocate new DH structure
    if (global_dh == NULL) {
        return;
    }

    //Generate DHKE parameters: 2048-bit prime and generator 2
    if (!DH_generate_parameters_ex(global_dh, 2048, DH_GENERATOR_2, NULL)) {
        DH_free(global_dh);
        global_dh = NULL;
        return;
    }

    //Check if the parameter is valid
    int codes = 0;
    if (!DH_check(global_dh, &codes)) {
        DH_free(global_dh);
        global_dh = NULL;
        return;
    }

    //Extract and store p and g for reuse
    DH_get0_pqg(global_dh, (const BIGNUM **)&p, NULL, (const BIGNUM **)&g);
    p = BN_dup(p);
    g = BN_dup(g);
}

//Clean up DHKE parameters to avoid memory leaks
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

//Generates a DHKE key pair: private and public keys
void generateDHKeyPair(unsigned char *privateKey, unsigned char *publicKey) {
    initDHParameters();
    if (global_dh == NULL) {
        return;
    }

    DH *dh = DH_new();  //Create new DH object for this key pair
    if (dh == NULL) {
        return;
    }

    //Set prime (p) and generator (g) in the DH object
    if (!DH_set0_pqg(dh, BN_dup(p), NULL, BN_dup(g))) {
        DH_free(dh);
        return;
    }

    //Generate the private and public keys
    if (!DH_generate_key(dh)) {
        DH_free(dh);
        return;
    }

    //Get the private and public BIGNUMs
    const BIGNUM *priv_key = DH_get0_priv_key(dh);
    const BIGNUM *pub_key = DH_get0_pub_key(dh);

    //Convert BIGNUMs to byte arrays
    int priv_len = BN_bn2bin(priv_key, privateKey);
    int pub_len = BN_bn2bin(pub_key, publicKey);

    //Pad private key to ensure fixed size (256 bytes)
    if (priv_len < DH_KEY_SIZE) {
        memmove(privateKey + (DH_KEY_SIZE - priv_len), privateKey, priv_len);
        memset(privateKey, 0, DH_KEY_SIZE - priv_len);
    }

    //Pad public key similarly
    if (pub_len < DH_KEY_SIZE) {
        memmove(publicKey + (DH_KEY_SIZE - pub_len), publicKey, pub_len);
        memset(publicKey, 0, DH_KEY_SIZE - pub_len);
    }

    DH_free(dh);  //Free temporary DHKE object
}

//Computes shared secret using local private key and other public key
void generateSharedSecret(unsigned char *sharedSecret, 
                          unsigned char *privateKey, 
                          unsigned char *otherPublicKey) {
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

    //Set DHKE parameters (p and g)
    if (!DH_set0_pqg(dh, BN_dup(p), NULL, BN_dup(g))) {
        DH_free(dh);
        return;
    }

    //Convert byte arrays back to BIGNUMs
    priv_key = BN_bin2bn(privateKey, DH_KEY_SIZE, NULL);
    pub_key = BN_bin2bn(otherPublicKey, DH_KEY_SIZE, NULL);
    if (!priv_key || !pub_key) {
        if (priv_key) BN_free(priv_key);
        if (pub_key) BN_free(pub_key);
        DH_free(dh);
        return;
    }

    //Set our private key
    if (!DH_set0_key(dh, BN_dup(priv_key), NULL)) {
        BN_free(priv_key);
        BN_free(pub_key);
        DH_free(dh);
        return;
    }

    //Compute the shared secret from other public key
    secret_len = DH_compute_key(sharedSecret, pub_key, dh);
    if (secret_len <= 0) {
        BN_free(priv_key);
        BN_free(pub_key);
        DH_free(dh);
        return;
    }

    //Pad shared secret to 256 bytes
    if (secret_len < DH_KEY_SIZE) {
        memmove(sharedSecret + (DH_KEY_SIZE - secret_len), sharedSecret, secret_len);
        memset(sharedSecret, 0, DH_KEY_SIZE - secret_len);
    }

    //Derive a secure 256-byte key using SHA-512 in HKDF-like expansion
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(sharedSecret, secret_len, hash);  //Initial hash of the secret

    unsigned char expanded[DH_KEY_SIZE];
    unsigned char counter = 1;
    size_t pos = 0;

    //Expand hash using SHA-512 in a loop until we have 256 bytes
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

    //Final shared key
    memcpy(sharedSecret, expanded, DH_KEY_SIZE);

    //Free temporary BIGNUMs and DH
    BN_free(priv_key);
    BN_free(pub_key);
    DH_free(dh);
}
