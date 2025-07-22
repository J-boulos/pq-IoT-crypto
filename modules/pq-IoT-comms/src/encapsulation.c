#include <string.h>
#include "encapsulation.h"

static uint8_t kem_pk[KEM_PK_LEN];
static uint8_t kem_sk[KEM_SK_LEN];

void generate_kem_keys(void) {
    crypto_kem_keypair(kem_pk, kem_sk);
}

void get_own_kem_public_key(uint8_t *out_pk) {
    memcpy(out_pk, kem_pk, KEM_PK_LEN);
}

void get_own_kem_secret_key(uint8_t *out_sk) {
    memcpy(out_sk, kem_sk, KEM_SK_LEN);
}

int encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *recipient_pk) {
    return crypto_kem_enc(ct, ss, recipient_pk);
}

int decapsulate(uint8_t *ss, const uint8_t *ct) {
    return crypto_kem_dec(ss, ct, kem_sk);
}
