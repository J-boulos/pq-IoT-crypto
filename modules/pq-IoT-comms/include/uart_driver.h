#ifndef UART_DRIVER_H
#define UART_DRIVER_H

#include "msg.h"
#include "thread.h"
#include "periph/uart.h"

#define DEBUG_UART       UART_DEV(0)
#define OUT_UART      UART_DEV(1)
#define BAUDRATE (115200U)

#define UART_MSG_TYPE 0x01234
#define MAX_UART_BUF 4000

#define START_BYTE          0xAA
#define MSG_TYPE_KEY_GEN    0x01
#define MSG_TYPE_PUBKEY     0x02
#define MSG_TYPE_DECRYPT    0x03
#define MSG_TYPE_ENCRYPT    0x04

/**
 * Initialize UART communication system.
 *
 * @param debug_uart The UART device for debugging (prints).
 * @param out_uart The UART device for outgoing communication.
 * @param main_pid The PID of the main thread (to deliver parsed messages).
 * @return 0 on success, -1 on failure.
 */
typedef struct {
    size_t len;
    uint8_t data[];
} uart_message_t;

int uart_comm_init(uart_t debug_uart, uart_t out_uart, kernel_pid_t main_pid);

#endif // UART_COMM_H
