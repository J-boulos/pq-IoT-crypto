#ifndef KEM_ENCAPSULATION_H
#define KEM_ENCAPSULATION_H

#include <stdint.h>
#include <stdio.h>

#include "ml-kem-512.h"


#define KEM_PK_LEN            CRYPTO_PUBLICKEYBYTES
#define KEM_SK_LEN            CRYPTO_SECRETKEYBYTES
#define KEM_CIPHERTEXT_LEN    CRYPTO_CIPHERTEXTBYTES
#define KEM_SHAREDSECRET_LEN  CRYPTO_BYTES

/**
 * Generates the static KEM key pair and stores internally.
 */
void generate_kem_keys(void);

/**
 * Returns the stored public key.
 */
void get_own_kem_public_key(uint8_t *out_pk);

/**
 * Returns the stored secret key.
 */
void get_own_kem_secret_key(uint8_t *out_sk);

/**
 * Perform encapsulation using recipient's public key.
 */
int encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *recipient_pk);

/**
 * Perform decapsulation using internal secret key.
 */
int decapsulate(uint8_t *ss, const uint8_t *ct);

#endif
