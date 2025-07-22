#include "crypto_backend.h"
#include "periph/uart.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define SHA3_256_DIGEST_LEN 32
#define AES_KEY_LEN         16
#define AES_BLOCK_LEN       16

/*
Helper function for debugging
*/
void print_sha256_digest(const char *label, const uint8_t *data, size_t len) {
    
    uint8_t digest[SHA3_256_DIGEST_LEN];
    sha3_256(digest, data, len);

    printf("%s: ", label);
    for (size_t i = 0; i < SHA3_256_DIGEST_LEN; i++) {
        printf("%02X", digest[i]);
    }
    puts("");
}

#ifdef SIDE_CAR_MODE

//KEM buffers
static uint8_t kem_ciphertext_buf[KEM_CIPHERTEXT_LEN];
static uint8_t shared_secret_buf[KEM_SHAREDSECRET_LEN];
static uint8_t decrypted_secret[KEM_SHAREDSECRET_LEN];

//AES buffers
static uint8_t aes_ciphertext_buf[AES_BLOCK_LEN];
static uint8_t aes_decrypted_buf[AES_BLOCK_LEN];


static void _generate_keys(uart_t uart) {

    generate_kem_keys();
    generate_dsa_keys();
    puts("[DEBUG UART] Keys generated successfully.");

}


void send_public_keys(uart_t uart) {

    puts("[DEBUG UART] Sending public keys...");

    uint8_t kem_pk[KEM_PK_LEN];
    get_own_kem_public_key(kem_pk);

    uint8_t dsa_pk[MLDSA_PK_LEN];
    get_own_dsa_public_key(dsa_pk);

    uint16_t kem_len = KEM_PK_LEN;
    uint16_t dsa_len = MLDSA_PK_LEN;

    uint8_t header[6];
    header[0] = START_BYTE;
    header[1] = MSG_TYPE_PUBKEY;
    header[2] = (kem_len >> 8) & 0xFF;
    header[3] = kem_len & 0xFF;
    header[4] = (dsa_len >> 8) & 0xFF;
    header[5] = dsa_len & 0xFF;


    uart_write(uart, header, sizeof(header));
    uart_write(uart, kem_pk, kem_len);
    uart_write(uart, dsa_pk, dsa_len);

}

static void handle_encrypt(uart_t uart, const uint8_t *data, size_t len) {

    if (len < 2 + KEM_PK_LEN + AES_BLOCK_LEN) {
        puts("[ERROR] ENCRYPT: Packet too short.");
        return;
    }

    const uint8_t *peer_pk = &data[2];
    const uint8_t *plaintext = &data[2 + KEM_PK_LEN];
    
    //DEBUG SECTION
    print_sha256_digest("Received KEM PK for Encapsulation", peer_pk, KEM_PK_LEN);
    //
    
    encapsulate(kem_ciphertext_buf, shared_secret_buf, peer_pk);

    cipher_context_t aes_ctx;
    aes_init(&aes_ctx, shared_secret_buf , AES_KEY_LEN);
    aes_encrypt(&aes_ctx, plaintext, aes_ciphertext_buf);
    
    print_sha256_digest("SK generated from encapsulation digest",shared_secret_buf ,KEM_SHAREDSECRET_LEN);

    //buffer preparation
    uint16_t kem_ct_len = KEM_CIPHERTEXT_LEN;
    uint16_t aes_block_len = AES_BLOCK_LEN;
    uint8_t header[6];

    //header population
    header[0] = START_BYTE;
    header[1] = MSG_TYPE_ENCRYPT;
    header[2] = (kem_ct_len >> 8) & 0xFF;
    header[3] = kem_ct_len & 0xFF;
    header[4] = (aes_block_len >> 8) & 0xFF;
    header[5] = aes_block_len & 0xFF;

    //transport
    uart_write(uart, header, sizeof(header));
    uart_write(uart, kem_ciphertext_buf, kem_ct_len);
    uart_write(uart, aes_ciphertext_buf, aes_block_len);
}


static void handle_decrypt(uart_t uart, const uint8_t *data, size_t len) {
    
    const uint8_t *ct = &data[2];
    const uint8_t *ciphertext = &data[2 + KEM_CIPHERTEXT_LEN];

    if (decapsulate(decrypted_secret, ct) != 0) {
        puts("[ERROR] DECRYPT: Decapsulation failed.");
        return;
    }

    //DEBUG SECTION (specific to using the priv key of the pub key used for encapsualtion)
    print_sha256_digest("SK retrieved from decapsulation digest", decrypted_secret ,KEM_SHAREDSECRET_LEN);


    cipher_context_t aes_ctx;
    aes_init(&aes_ctx, decrypted_secret , AES_KEY_LEN);
    aes_decrypt(&aes_ctx, ciphertext, aes_decrypted_buf);


    //DEBUG SECTION
    printf("[DEBUG] DECRYPT: Decrypted data: ");
    for (int i = 0; i < AES_BLOCK_LEN; i++) {
        printf("%02X ", aes_decrypted_buf[i]);
    }
    puts("");
    //


    //HARDCODED DEBUG SECTION
    const uint8_t expected[AES_BLOCK_LEN] = "Hello,postquant";
    if (memcmp(aes_decrypted_buf, expected, AES_BLOCK_LEN) == 0) {
        puts("[VALIDATION] Decryption matches expected plaintext.");
    } else {
        puts("[VALIDATION] Decryption FAILED — does NOT match expected.");
    }
    //


    //buffer preparation
    uint16_t pt_len = AES_BLOCK_LEN;
    uint8_t header[4];

    //header population
    header[0] = START_BYTE;
    header[1] = MSG_TYPE_DECRYPT;
    header[2] = (pt_len >> 8) & 0xFF;
    header[3] = pt_len & 0xFF;

    //transport
    uart_write(uart, header, sizeof(header));
    uart_write(uart, aes_decrypted_buf, pt_len);
}




//ENTRY POINT TO CRYPTOGRAPHIC BACKEND VIA UART
void protocol_handle(uart_t uart, const uint8_t *data, size_t len) {

    if (!data || len < 2 || data[0] != START_BYTE) {
        puts("[ERROR] Invalid or malformed binary message.");
        return;
    }

    uint8_t msg_type = data[1];

    switch (msg_type) {
        case MSG_TYPE_KEY_GEN:
            puts("[DEBUG UART] Received: KEY_GEN");
            _generate_keys(uart);
            break;

        case MSG_TYPE_PUBKEY:
            puts("[DEBUG UART] Received: KEY_REQUEST");
            send_public_keys(uart);
            break;

        case MSG_TYPE_ENCRYPT:
            puts("[DEBUG UART] Received: ENCRYPT");
            handle_encrypt(uart, data, len);
            break;

        case MSG_TYPE_DECRYPT:
            puts("[DEBUG UART] Received: DECRYPT");
            handle_decrypt(uart, data, len);
            break;

        default:
            printf("[WARN] Unknown binary message type: 0x%02X\n", msg_type);
            break;
    }

}

#endif


//Direct API calls 
int crypto_generate_keys(void) {

    generate_kem_keys();
    generate_dsa_keys();

    uint8_t kem_pk[KEM_PK_LEN];
    get_own_kem_public_key(kem_pk);
    print_sha256_digest("Generated KEM PK digest", kem_pk, KEM_PK_LEN);

    return 0;
}

int crypto_get_public_keys(uint8_t *out_kem_pk, uint8_t *out_dsa_pk)
{
    if (!out_kem_pk || !out_dsa_pk)
        return -1;

    get_own_kem_public_key(out_kem_pk);
    print_sha256_digest("Retrieved KEM PK digest", out_kem_pk, KEM_PK_LEN);
    get_own_dsa_public_key(out_dsa_pk);

    return 0;
}


int crypto_encrypt(const uint8_t *peer_kem_pk,
                   const uint8_t *plaintext,
                   uint8_t *out_kem_ct,
                   uint8_t *out_aes_ct)
{
    if (!peer_kem_pk || !plaintext || !out_kem_ct || !out_aes_ct)
        return -1;

    uint8_t shared_secret[KEM_SHAREDSECRET_LEN];
    encapsulate(out_kem_ct, shared_secret, peer_kem_pk);

    cipher_context_t aes_ctx;
    aes_init(&aes_ctx, shared_secret, AES_KEY_LEN);
    aes_encrypt(&aes_ctx, plaintext, out_aes_ct);

    return 0;
}

int crypto_verify(const uint8_t *kem_ct,
                   const uint8_t *aes_ct,
                   uint8_t *out_plaintext)
{
    if (!kem_ct || !aes_ct || !out_plaintext)
        return -1;

    uint8_t shared_secret[KEM_SHAREDSECRET_LEN];

    if (decapsulate(shared_secret, kem_ct) != 0)
        return -2;

    cipher_context_t aes_ctx;
    aes_init(&aes_ctx, shared_secret, AES_KEY_LEN);
    aes_decrypt(&aes_ctx, aes_ct, out_plaintext);

    return 0;
}







