#define _POSIX_C_SOURCE 200809L
#include "tailscalec/tsc.h"
#include "tailscalec/socket.h"
#include "../system.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/random.h>
#endif

uint64_t tsc_system_monotonic_ms(void *user)
{
    struct timespec now;
    int result;
    (void)user;
    /* Coordinator key-expiry deadlines must advance while Linux is suspended.
     * Older kernels and other POSIX systems fall back to CLOCK_MONOTONIC,
     * whose suspend behavior is platform-specific. On a clock that pauses,
     * refresh the control map before resuming tailnet traffic after wake. */
#if defined(__linux__) && defined(CLOCK_BOOTTIME)
    result = clock_gettime(CLOCK_BOOTTIME, &now);
    if (result != 0)
        result = clock_gettime(CLOCK_MONOTONIC, &now);
#else
    result = clock_gettime(CLOCK_MONOTONIC, &now);
#endif
    if (result != 0)
        return 0;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

int tsc_socket_tai64n_now(void *user, uint8_t output[12])
{
    struct timespec now;
    uint64_t seconds;
    uint32_t nanoseconds;
    (void)user;
    if (!output)
        return TSC_ERR_ARGUMENT;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec < 1577836800)
        return TSC_ERR_IO;
    /* WireGuard uses the same fixed TAI64N epoch offset as its upstream
     * implementations, without applying a separate leap-second table. */
    seconds = (uint64_t)now.tv_sec + UINT64_C(0x400000000000000a);
    nanoseconds = (uint32_t)now.tv_nsec;
    for (unsigned i = 0; i < 8; ++i)
        output[i] = (uint8_t)(seconds >> (56 - 8 * i));
    for (unsigned i = 0; i < 4; ++i)
        output[8 + i] = (uint8_t)(nanoseconds >> (24 - 8 * i));
    return TSC_OK;
}

int tsc_system_random_bytes(void *user, void *buffer, size_t length)
{
    uint8_t *out = buffer;
    size_t at = 0;
#ifndef __linux__
    int fd;
#endif
    (void)user;
    if (!buffer && length)
        return TSC_ERR_ARGUMENT;
    if (!length)
        return TSC_OK;
#ifndef __linux__
    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return TSC_ERR_IO;
#endif
    while (at < length) {
        /* Bounded syscall lengths work on 32-bit platforms as well. */
        size_t count = length - at > 256 ? 256 : length - at;
#ifdef __linux__
        ssize_t n = getrandom(out + at, count, 0);
#else
        ssize_t n = read(fd, out + at, count);
#endif
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
#ifndef __linux__
            close(fd);
#endif
            memset(buffer, 0, length);
            return TSC_ERR_IO;
        }
        at += (size_t)n;
    }
#ifndef __linux__
    close(fd);
#endif
    return TSC_OK;
}
