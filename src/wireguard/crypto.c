#include "crypto.h"
#include "crypto/refc/chacha20.h"
#include <string.h>

static void make_nonce(uint8_t nonce[12], uint64_t counter) {
    size_t i;
    memset(nonce, 0, 4);
    for (i = 0; i < 8; ++i) nonce[4 + i] = (uint8_t)(counter >> (8 * i));
}

bool tsc_wgi_aead_encrypt(uint8_t *dst, const uint8_t *src, size_t length,
        const uint8_t *aad, size_t aad_length, uint64_t counter,
        const uint8_t key[32]) {
    uint8_t nonce[12];
    make_nonce(nonce, counter);
    return tsc_crypto_chacha20poly1305_encrypt(key, nonce, aad, aad_length,
                    src, length, dst, dst + length) == TSC_OK;
}

bool tsc_wgi_aead_decrypt(uint8_t *dst, const uint8_t *src, size_t length,
        const uint8_t *aad, size_t aad_length, uint64_t counter,
        const uint8_t key[32]) {
    uint8_t nonce[12];
    if (length < 16) return false;
    make_nonce(nonce, counter);
    return tsc_crypto_chacha20poly1305_decrypt(key, nonce, aad, aad_length,
                    src, length - 16, src + length - 16, dst) == TSC_OK;
}

bool tsc_wgi_xaead_encrypt(uint8_t *dst, const uint8_t *src, size_t length,
        const uint8_t *aad, size_t aad_length, const uint8_t nonce[24],
        const uint8_t key[32]) {
    uint8_t subkey[32], subnonce[12] = {0};
    int result;
    hchacha20(subkey, nonce, key);
    memcpy(subnonce + 4, nonce + 16, 8);
    result = tsc_crypto_chacha20poly1305_encrypt(subkey, subnonce, aad, aad_length,
                    src, length, dst, dst + length);
    tsc_crypto_zero(subkey, sizeof(subkey));
    return result == TSC_OK;
}

bool tsc_wgi_xaead_decrypt(uint8_t *dst, const uint8_t *src, size_t length,
        const uint8_t *aad, size_t aad_length, const uint8_t nonce[24],
        const uint8_t key[32]) {
    uint8_t subkey[32], subnonce[12] = {0};
    int result;
    if (length < 16) return false;
    hchacha20(subkey, nonce, key);
    memcpy(subnonce + 4, nonce + 16, 8);
    result = tsc_crypto_chacha20poly1305_decrypt(subkey, subnonce, aad, aad_length,
                    src, length - 16, src + length - 16, dst);
    tsc_crypto_zero(subkey, sizeof(subkey));
    return result == TSC_OK;
}
