#ifndef TAILSCALEC_NACL_H
#define TAILSCALEC_NACL_H

#include "tailscalec/tsc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TSC_NACL_BOX_NONCEBYTES 24
#define TSC_NACL_BOX_MACBYTES 16
#define TSC_NACL_BOX_PUBLICKEYBYTES 32
#define TSC_NACL_BOX_SECRETKEYBYTES 32

#if TSC_ENABLE_DISCO || TSC_ENABLE_DERP
/* NaCl box: X25519 + HSalsa20 + XSalsa20-Poly1305. Ciphertext layout is
 * 16-byte MAC || encrypted message. Nonces must never repeat under a key.
 * Caller provides output of plaintext_len + 16 for encryption, or
 * ciphertext_len - 16 for decryption. Encryption requires disjoint buffers.
 * Decryption output may start at or before ciphertext (in-place supported).
 * Returns TSC_OK on success, negative error otherwise. Failed authentication
 * clears the plaintext output. Public low-order keys are rejected. */
int tsc_nacl_box_beforenm(uint8_t shared_key[32],
                          const uint8_t recipient_pk[32],
                          const uint8_t sender_sk[32]);
int tsc_nacl_box_afternm(uint8_t *ciphertext, const uint8_t *plaintext,
                         size_t plaintext_len, const uint8_t nonce[24],
                         const uint8_t shared_key[32]);
int tsc_nacl_box_open_afternm(uint8_t *plaintext, const uint8_t *ciphertext,
                              size_t ciphertext_len, const uint8_t nonce[24],
                              const uint8_t shared_key[32]);
int tsc_nacl_box(uint8_t *ciphertext, const uint8_t *plaintext,
                  size_t plaintext_len, const uint8_t nonce[24],
                  const uint8_t recipient_pk[32], const uint8_t sender_sk[32]);
int tsc_nacl_box_open(uint8_t *plaintext, const uint8_t *ciphertext,
                       size_t ciphertext_len, const uint8_t nonce[24],
                       const uint8_t sender_pk[32], const uint8_t recipient_sk[32]);
#endif

#ifdef __cplusplus
}
#endif
#endif
