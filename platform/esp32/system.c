#include "tailscalec/tsc.h"
#include "tailscalec/socket.h"
#include "../system.h"
#include "esp_random.h"
#include "esp_timer.h"
#include <sys/time.h>

uint64_t tsc_system_monotonic_ms(void *user)
{
    (void)user;
    return (uint64_t)esp_timer_get_time() / 1000;
}

int tsc_socket_tai64n_now(void *user, uint8_t output[12])
{
    struct timeval now;
    uint64_t seconds;
    uint32_t nanoseconds;
    (void)user;
    if (!output)
        return TSC_ERR_ARGUMENT;
    if (gettimeofday(&now, NULL) != 0 || now.tv_sec < 1577836800)
        return TSC_ERR_IO;
    seconds = (uint64_t)now.tv_sec + UINT64_C(0x400000000000000a);
    nanoseconds = (uint32_t)now.tv_usec * 1000;
    for (unsigned i = 0; i < 8; ++i)
        output[i] = (uint8_t)(seconds >> (56 - 8 * i));
    for (unsigned i = 0; i < 4; ++i)
        output[8 + i] = (uint8_t)(nanoseconds >> (24 - 8 * i));
    return TSC_OK;
}

int tsc_system_random_bytes(void *user, void *buffer, size_t length)
{
    (void)user;
    if (!buffer && length)
        return TSC_ERR_ARGUMENT;
    /* The app must enable Wi-Fi/Bluetooth or an ESP-IDF entropy source.
     * This adapter never starts radios or changes their configuration. */
    if (length)
        esp_fill_random(buffer, length);
    return TSC_OK;
}
