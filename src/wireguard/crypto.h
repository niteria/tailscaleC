#ifndef TSC_WG_CRYPTO_H
#define TSC_WG_CRYPTO_H
#include "tailscalec/crypto.h"
#include "crypto/refc/blake2s.h"
#include <stdbool.h>
#define tsc_wgi_blake2s_ctx blake2s_ctx
#define tsc_wgi_blake2s_init blake2s_init
#define tsc_wgi_blake2s_update blake2s_update
#define tsc_wgi_blake2s_final blake2s_final
#define tsc_wgi_blake2s blake2s
#define tsc_wgi_x25519 tsc_crypto_x25519
#define crypto_zero tsc_crypto_zero
#define crypto_equal tsc_crypto_equal
bool tsc_wgi_aead_encrypt(uint8_t *dst, const uint8_t *src, size_t length,
    const uint8_t *aad, size_t aad_length, uint64_t counter, const uint8_t key[32]);
bool tsc_wgi_aead_decrypt(uint8_t *dst, const uint8_t *src, size_t length,
    const uint8_t *aad, size_t aad_length, uint64_t counter, const uint8_t key[32]);
bool tsc_wgi_xaead_encrypt(uint8_t *dst, const uint8_t *src, size_t length,
    const uint8_t *aad, size_t aad_length, const uint8_t nonce[24], const uint8_t key[32]);
bool tsc_wgi_xaead_decrypt(uint8_t *dst, const uint8_t *src, size_t length,
    const uint8_t *aad, size_t aad_length, const uint8_t nonce[24], const uint8_t key[32]);
// Endian / unaligned helper macros
#define U8C(v) (v##U)
#define U32C(v) (v##U)

#define U8V(v) ((uint8_t)(v) & U8C(0xFF))
#define U32V(v) ((uint32_t)(v) & U32C(0xFFFFFFFF))

#define U8TO32_LITTLE(p) \
  (((uint32_t)((p)[0])      ) | \
   ((uint32_t)((p)[1]) <<  8) | \
   ((uint32_t)((p)[2]) << 16) | \
   ((uint32_t)((p)[3]) << 24))

#define U8TO64_LITTLE(p) \
  (((uint64_t)((p)[0])      ) | \
   ((uint64_t)((p)[1]) <<  8) | \
   ((uint64_t)((p)[2]) << 16) | \
   ((uint64_t)((p)[3]) << 24) | \
   ((uint64_t)((p)[4]) << 32) | \
   ((uint64_t)((p)[5]) << 40) | \
   ((uint64_t)((p)[6]) << 48) | \
   ((uint64_t)((p)[7]) << 56))

#define U16TO8_BIG(p, v) \
  do { \
    (p)[1] = U8V((v)      ); \
    (p)[0] = U8V((v) >>  8); \
  } while (0)

static inline void tsc_wgi_store32_le(uint8_t p[4], uint32_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}
#define U32TO8_LITTLE(p, v) tsc_wgi_store32_le((p), (v))

#define U32TO8_BIG(p, v) \
  do { \
    (p)[3] = U8V((v)      ); \
    (p)[2] = U8V((v) >>  8); \
    (p)[1] = U8V((v) >> 16); \
    (p)[0] = U8V((v) >> 24); \
  } while (0)

#define U64TO8_LITTLE(p, v) \
  do { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
    (p)[4] = U8V((v) >> 32); \
    (p)[5] = U8V((v) >> 40); \
    (p)[6] = U8V((v) >> 48); \
    (p)[7] = U8V((v) >> 56); \
} while (0)

#define U64TO8_BIG(p, v) \
  do { \
    (p)[7] = U8V((v)      ); \
    (p)[6] = U8V((v) >>  8); \
    (p)[5] = U8V((v) >> 16); \
    (p)[4] = U8V((v) >> 24); \
    (p)[3] = U8V((v) >> 32); \
    (p)[2] = U8V((v) >> 40); \
    (p)[1] = U8V((v) >> 48); \
    (p)[0] = U8V((v) >> 56); \
} while (0)



#endif
