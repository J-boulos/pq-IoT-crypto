#include <stdio.h>
#include <string.h>
#include "xtimer.h"
#include "thread.h"
#include "ml-kem-512.h"


#define WORKER_PRIO       (THREAD_PRIORITY_MAIN - 1)
#define WORKER_STACKSIZE  (70 * 1024)    

static char worker_stack[WORKER_STACKSIZE];
static volatile bool worker_done;
static uint32_t start_usec, stop_usec;
static size_t worker_stack_use;


static void *_kem_worker(void *arg)
{
    (void)arg;

    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss_enc[CRYPTO_BYTES];
    uint8_t ss_dec[CRYPTO_BYTES];

    start_usec = xtimer_now_usec();

    if (crypto_kem_keypair(pk, sk) != 0) {
        puts("Key pair generation failed!");
        worker_done = true;
        return NULL;
    }

    if (crypto_kem_enc(ct, ss_enc, pk) != 0) {
        puts("Encapsulation failed!");
        worker_done = true;
        return NULL;
    }

    if (crypto_kem_dec(ss_dec, ct, sk) != 0) {
        puts("Decapsulation failed!");
        worker_done = true;
        return NULL;
    }

    stop_usec = xtimer_now_usec();

    if (memcmp(ss_enc, ss_dec, CRYPTO_BYTES) == 0) {
        puts("SUCCESS: shared secrets match.");
    } else {
        puts("FAILURE: shared secrets do not match!");
    }

    worker_stack_use = WORKER_STACKSIZE - thread_measure_stack_free(thread_get_active());
    worker_done = true;
    return NULL;
}

int main(void)
{
    puts(" profiling starting...");

    worker_done = false;
    kernel_pid_t pid = thread_create(
        worker_stack, sizeof(worker_stack),
        WORKER_PRIO,
        THREAD_CREATE_STACKTEST,
        _kem_worker, NULL, "kem_worker");       

    if (pid <= KERNEL_PID_UNDEF) {
        puts("thread_create failed!");
        return 1;
    }

    while (!worker_done) {
        thread_yield();
    }

    uint32_t kem_time = stop_usec - start_usec;

    printf("{ \"kem_total\": %" PRIu32 "ms, "
           "\"kem_stack\": %" PRIu32 "B }\n",
           (uint32_t)(kem_time / US_PER_MS),
           (uint32_t)worker_stack_use);

    return 0;
}