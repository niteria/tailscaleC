#ifndef TAILSCALEC_CRYPTO_H
#define TAILSCALEC_CRYPTO_H

#include "tailscalec/tsc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Provider-backed primitives: OpenSSL on POSIX, mbedTLS on ESP32.
 * No global initialization is required. NULL byte buffers are permitted only
 * when their corresponding length is zero. Outputs must have the stated size.
 * Each operation is independent and thread-safe. Backend allocations are freed
 * before return. TSC_ERR_PROTOCOL denotes an invalid peer key or failed tag.
 * The ESP32 application must enable Wi-Fi/Bluetooth or another ESP-IDF secure
 * entropy source before generating keys. */
int tsc_crypto_random(void *output, size_t length);
int tsc_crypto_x25519_public(uint8_t output[32], const uint8_t private_key[32]);
int tsc_crypto_x25519(uint8_t output[32], const uint8_t private_key[32],
                      const uint8_t peer_public_key[32]);
int tsc_crypto_sha256(const void *data, size_t length, uint8_t output[32]);
int tsc_crypto_hmac_sha256(const void *key, size_t key_length,
                           const void *data, size_t length, uint8_t output[32]);
/* RFC 5869 extract-and-expand. output_length may not exceed 255 * 32. */
int tsc_crypto_hkdf_sha256(const void *salt, size_t salt_length,
                           const void *key, size_t key_length,
                           const void *info, size_t info_length,
                           void *output, size_t output_length);

/* RFC 8439 IETF ChaCha20-Poly1305: 32-byte key, 12-byte nonce, 16-byte tag.
 * A key/nonce pair must never be reused for different plaintexts. Exact in-place
 * input/output is allowed; other overlapping buffers are unsupported.
 * Lengths are bounded to INT_MAX on both platforms for consistent semantics;
 * decryption failures clear the plaintext buffer when length is in that range.
 * Oversized requests are rejected without accessing input/output buffers. */
int tsc_crypto_chacha20poly1305_encrypt(
    const uint8_t key[32], const uint8_t nonce[12],
    const void *aad, size_t aad_length, const void *plaintext, size_t length,
    void *ciphertext, uint8_t tag[16]);
int tsc_crypto_chacha20poly1305_decrypt(
    const uint8_t key[32], const uint8_t nonce[12],
    const void *aad, size_t aad_length, const void *ciphertext, size_t length,
    const uint8_t tag[16], void *plaintext);

/* Secure erasure and constant-time equality (1 equal, 0 unequal/invalid).
 * These functions accept NULL for zero length. */
void tsc_crypto_zero(void *buffer, size_t length);
int tsc_crypto_equal(const void *a, const void *b, size_t length);

#ifdef __cplusplus
}
#endif
#endif
