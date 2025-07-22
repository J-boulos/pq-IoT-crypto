#ifndef PROTOCOL_HANDLER_H
#define PROTOCOL_HANDLER_H

#include <stdint.h>
#include <stddef.h>

#include "crypto/ciphers.h"
#include "crypto/aes.h"
#include "fips202.h"

#include "encapsulation.h"
#include "signing.h"

#define AES_BLOCK_LEN 16

#ifdef SIDE_CAR_MODE
#include "uart_driver.h"
void protocol_handle(uart_t uart, const uint8_t *data, size_t len);
#endif

#else
int crypto_generate_keys(void);
int crypto_get_public_keys(uint8_t *out_kem_pk, uint8_t *out_dsa_pk);
int crypto_encrypt(const uint8_t *peer_kem_pk,const uint8_t *plaintext,uint8_t *out_kem_ct,uint8_t *out_aes_ct);
int crypto_decrypt(const uint8_t *kem_ct,const uint8_t *aes_ct,uint8_t *out_plaintext);
#endif // PROTOCOL_HANDLER_H
