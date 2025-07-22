#include <string.h>
#include "signing.h"

static uint8_t dsa_pk[MLDSA_PK_LEN];
static uint8_t dsa_sk[MLDSA_SK_LEN];

void generate_dsa_keys(void) {
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(dsa_pk, dsa_sk);
}

void get_own_dsa_public_key(uint8_t *out_pk) {
    memcpy(out_pk, dsa_pk, MLDSA_PK_LEN);
}

int sign_message(uint8_t *sig, size_t *siglen,
                 const uint8_t *msg, size_t msglen) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, siglen, msg, msglen, dsa_sk);
}

int verify_signature(const uint8_t *sig, size_t siglen,
                     const uint8_t *msg, size_t msglen,
                     const uint8_t *pubkey) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, msg, msglen, pubkey);
}

