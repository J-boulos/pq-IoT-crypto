#ifndef DSA_SIGNING_H
#define DSA_SIGNING_H

#include <stdint.h>
#include <stddef.h>

#include "ml-dsa-44.h"

#define MLDSA_PK_LEN      PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES
#define MLDSA_SK_LEN      PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES
#define MLDSA_SIG_MAX_LEN PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES

void generate_dsa_keys(void);
void get_own_dsa_public_key(uint8_t *out_pk);

int sign_message(uint8_t *sig, size_t *siglen,
                 const uint8_t *msg, size_t msglen);

int verify_signature(const uint8_t *sig, size_t siglen,
                     const uint8_t *msg, size_t msglen,
                     const uint8_t *pubkey);

#endif // DSA_SIGNING_H
