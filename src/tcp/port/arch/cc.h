#ifndef TSC_LWIP_CC_H
#define TSC_LWIP_CC_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "tailscalec/config.h"
#if defined(ESP_PLATFORM) && defined(TSC_TCP_EXTERNAL_RAM) && TSC_TCP_EXTERNAL_RAM
#include "esp_attr.h"
#if !CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY
#error "TSC_TCP_EXTERNAL_RAM requires CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY=y"
#endif
/* These pools need byte-addressable memory, not DMA memory. Placement is
 * opt-in so boards without PSRAM retain the portable defaults. */
#define LWIP_DECLARE_MEMORY_ALIGNED(variable, size) \
    EXT_RAM_BSS_ATTR uint8_t variable[LWIP_MEM_ALIGN_BUFFER(size)]
#endif
#ifndef BYTE_ORDER
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BYTE_ORDER BIG_ENDIAN
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define BYTE_ORDER LITTLE_ENDIAN
#elif defined(_WIN32) || defined(__XTENSA__) || defined(__riscv)
#define BYTE_ORDER LITTLE_ENDIAN
#else
#error "Set BYTE_ORDER in the TCP port for this compiler/target"
#endif
#endif
#define LWIP_PLATFORM_DIAG(message) do { } while (0)
#define LWIP_PLATFORM_ASSERT(message) do { (void)(message); abort(); } while (0)
uint32_t tsc_tcp_random_word(void);
#endif
