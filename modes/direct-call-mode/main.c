#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "pq-IoT-comms.h"


void print_ascii(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        char c = (data[i] >= 32 && data[i] <= 126) ? data[i] : '.';
        putchar(c);
    }
    puts("");
}

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    puts("");
}

int main(void) {

    crypto_generate_keys();

    uint8_t bob_kem_pk[KEM_PK_LEN];
    uint8_t alice_dsa_pk[MLDSA_PK_LEN];
    
    crypto_get_public_keys(bob_kem_pk, alice_dsa_pk);

    const uint8_t message[AES_BLOCK_LEN] = "Hello,Quantum!";
    printf("\nOriginal plaintext:\n");

    print_ascii("Plaintext", message, AES_BLOCK_LEN);

    uint8_t kem_ct[KEM_CIPHERTEXT_LEN];
    uint8_t aes_ct[AES_BLOCK_LEN];

    uint8_t signature[MLDSA_SIG_MAX_LEN];
    size_t siglen = 0;

    crypto_encrypt(bob_kem_pk, message, kem_ct, aes_ct);
    sign_message(signature, &siglen, message, AES_BLOCK_LEN);


    printf("\n=== BOB: Decrypting and verifying sig ===\n");

    uint8_t decrypted[AES_BLOCK_LEN];

    crypto_decrypt(kem_ct, aes_ct, decrypted);

    if (verify_signature(signature, siglen, decrypted, AES_BLOCK_LEN, alice_dsa_pk) != 0 ) {
        printf("Failed to verify message authenticity via digital sig");
        return 0;
    };

    printf("Sig verified\n");
    print_ascii("Decrypted Plaintext", decrypted, AES_BLOCK_LEN);

    return 0;
}
