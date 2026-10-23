#ifndef TAILSCALEC_SYSTEM_H
#define TAILSCALEC_SYSTEM_H
#include <stddef.h>
#include <stdint.h>
uint64_t tsc_system_monotonic_ms(void *user);
int tsc_system_random_bytes(void *user, void *buffer, size_t length);
#endif
