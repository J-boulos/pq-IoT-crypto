#include "uart_driver.h"
#include "crypto_backend.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static kernel_pid_t _main_pid;

static void _uart_rx_cb(void *arg, uint8_t byte) {

    static uint8_t buf[MAX_UART_BUF];
    static size_t pos = 0;
    static size_t expected_len = 0;

    (void)arg;

    if (pos == 0 && byte != START_BYTE) return;

    buf[pos++] = byte;

    if (pos == 2) {
        
        switch (buf[1]) {
            case MSG_TYPE_KEY_GEN:
            case MSG_TYPE_PUBKEY:
                expected_len = 2;
                break;
            case MSG_TYPE_ENCRYPT:
                expected_len = 2 + KEM_PK_LEN + AES_BLOCK_LEN;
                break;
            case MSG_TYPE_DECRYPT:
                expected_len = 2 + KEM_CIPHERTEXT_LEN + AES_BLOCK_LEN;
                break;
            default:
                printf("[WARN] Unknown UART msg type: 0x%02X\n", buf[1]);
                pos = 0;
                expected_len = 0;
                return;
        }
    }

    if (expected_len > 0 && pos >= expected_len) {
        uart_message_t *wrapped = malloc(sizeof(uart_message_t) + expected_len);
        if (!wrapped) {
            puts("[ERROR] malloc failed.");
            pos = 0;
            expected_len = 0;
            return;
        }

        wrapped->len = expected_len;
        memcpy(wrapped->data, buf, expected_len);

        msg_t msg;
        msg.type = UART_MSG_TYPE;
        msg.content.ptr = wrapped;

        if (msg_send(&msg, _main_pid) <= 0) {
            puts("[WARN] Failed to send UART msg.");
            free(wrapped);
        }

        pos = 0;
        expected_len = 0;
    }
}


/*
Init the uart and sets the above callback function , here it's a parser 
that checks for the protocol's start byte and type byte then allocates a buffer for the byte
stream to be sent to the thread running the handler's entry point
*/

int uart_comm_init(uart_t debug_uart, uart_t out_uart, kernel_pid_t main_pid) {
    _main_pid = main_pid;

    if (uart_init(debug_uart, BAUDRATE, _uart_rx_cb, (void *)debug_uart) != 0) {
        puts("[ERROR] Failed to initialize DEBUG UART.");
        return -1;
    }
    puts("DEBUG UART initialized.");

    if (uart_init(out_uart, BAUDRATE, _uart_rx_cb, (void *)out_uart) != 0) {
        puts("[ERROR] Failed to initialize OUT UART.");
        return -1;
    }
    puts("OUT UART initialized.");

    return 0;
}
