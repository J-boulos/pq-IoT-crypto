#define SIDE_CAR_MODE 1
#define MSG_QUEUE_SIZE (8)

#include "thread.h"
#include "msg.h"
#include "pq-IoT-comms.h"


int main(void) {

    kernel_pid_t main_pid = thread_getpid();

    if (uart_comm_init(DEBUG_UART, OUT_UART, main_pid) != 0) {
        return 1;
    }

    static msg_t msg_queue[MSG_QUEUE_SIZE];
    msg_init_queue(msg_queue, MSG_QUEUE_SIZE);

    msg_t msg;

    while (1) {
        
        if (msg_receive(&msg) == 1 && msg.type == UART_MSG_TYPE) {
            uart_message_t *received = (uart_message_t *)msg.content.ptr;

            printf("[DEBUG UART]: Received message: 0x%02X 0x%02X\n", received->data[0], received->data[1]);

            printf("[DEBUG CRYPTO] Handling protocol message...\n");

            //entry point
            protocol_handle(OUT_UART, received->data, received->len);
            //

            printf("[DEBUG CRYPTO] Done handling protocol message.\n");

            free(received);
        }
    }

    return 0;

}
