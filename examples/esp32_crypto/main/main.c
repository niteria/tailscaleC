#include "bootloader_random.h"
#include "esp_timer.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

int tsc_crypto_vectors_main(void);

void app_main(void)
{
    int64_t start;
    /* This standalone test owns the ADC entropy source and uses no radios.
     * QEMU validates the firmware's arithmetic and APIs, not physical entropy. */
    bootloader_random_enable();
    puts("Running the shared crypto vector suite on ESP32-S3 (1000 X25519 iterations)");
    start = esp_timer_get_time();
    if (tsc_crypto_vectors_main() != 0)
        abort();
    bootloader_random_disable();
    printf("Crypto vectors elapsed: %" PRId64 " ms\n",
           (esp_timer_get_time() - start) / 1000);
    puts("TSC_QEMU_CRYPTO_OK");
}
