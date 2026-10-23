#include "tailscalec/crypto.h"
#include "../system.h"
#include <limits.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <string.h>

void tsc_crypto_zero(void *buffer, size_t length)
{
    if (buffer && length)
        OPENSSL_cleanse(buffer, length);
}

int tsc_crypto_equal(const void *a, const void *b, size_t length)
{
    if (!length)
        return 1;
    return a && b && CRYPTO_memcmp(a, b, length) == 0;
}

int tsc_crypto_random(void *output, size_t length)
{
    return tsc_system_random_bytes(NULL, output, length);
}

int tsc_crypto_x25519_public(uint8_t output[32], const uint8_t private_key[32])
{
    EVP_PKEY *key;
    size_t length = 32;
    int result = TSC_ERR_IO;
    if (!output || !private_key)
        return TSC_ERR_ARGUMENT;
    key = EVP_PKEY_new_raw_private_key_ex(NULL, "X25519", NULL, private_key, 32);
    if (key && EVP_PKEY_get_raw_public_key(key, output, &length) == 1 && length == 32)
        result = TSC_OK;
    EVP_PKEY_free(key);
    if (result != TSC_OK)
        tsc_crypto_zero(output, 32);
    return result;
}

int tsc_crypto_x25519(uint8_t output[32], const uint8_t private_key[32],
                      const uint8_t peer_public_key[32])
{
    EVP_PKEY *key = NULL, *peer = NULL;
    EVP_PKEY_CTX *context = NULL;
    size_t length = 32;
    int result = TSC_ERR_IO;
    if (!output || !private_key || !peer_public_key)
        return TSC_ERR_ARGUMENT;
    key = EVP_PKEY_new_raw_private_key_ex(NULL, "X25519", NULL, private_key, 32);
    peer = EVP_PKEY_new_raw_public_key_ex(NULL, "X25519", NULL, peer_public_key, 32);
    if (!key || !peer)
        goto done;
    context = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (!context || EVP_PKEY_derive_init(context) != 1)
        goto done;
    if (EVP_PKEY_derive_set_peer(context, peer) != 1 ||
        EVP_PKEY_derive(context, output, &length) != 1 || length != 32) {
        result = TSC_ERR_PROTOCOL;
        goto done;
    }
    result = TSC_OK;
done:
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(key);
    if (result != TSC_OK)
        tsc_crypto_zero(output, 32);
    return result;
}

int tsc_crypto_sha256(const void *data, size_t length, uint8_t output[32])
{
    size_t output_length = 0;
    if ((!data && length) || !output)
        return TSC_ERR_ARGUMENT;
    if (!EVP_Q_digest(NULL, "SHA256", NULL, data, length, output, &output_length) ||
        output_length != 32) {
        tsc_crypto_zero(output, 32);
        return TSC_ERR_IO;
    }
    return TSC_OK;
}

int tsc_crypto_hmac_sha256(const void *key, size_t key_length,
                           const void *data, size_t length, uint8_t output[32])
{
    static const uint8_t empty = 0;
    size_t output_length = 0;
    if ((!key && key_length) || (!data && length) || !output)
        return TSC_ERR_ARGUMENT;
    if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL,
                   key ? key : &empty, key_length, data, length,
                   output, 32, &output_length) || output_length != 32) {
        tsc_crypto_zero(output, 32);
        return TSC_ERR_IO;
    }
    return TSC_OK;
}

int tsc_crypto_hkdf_sha256(const void *salt, size_t salt_length,
                           const void *key, size_t key_length,
                           const void *info, size_t info_length,
                           void *output, size_t output_length)
{
    static uint8_t empty;
    EVP_KDF *kdf;
    EVP_KDF_CTX *context;
    OSSL_PARAM params[5];
    int result;
    if ((!salt && salt_length) || (!key && key_length) || (!info && info_length) ||
        (!output && output_length) || output_length > 255 * 32)
        return TSC_ERR_ARGUMENT;
    if (!output_length)
        return TSC_OK;
    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    context = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!context) {
        tsc_crypto_zero(output, output_length);
        return TSC_ERR_IO;
    }
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
        (void *)(key ? key : &empty), key_length);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
        (void *)(salt ? salt : &empty), salt_length);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
        (void *)(info ? info : &empty), info_length);
    params[4] = OSSL_PARAM_construct_end();
    result = EVP_KDF_derive(context, output, output_length, params) == 1
        ? TSC_OK : TSC_ERR_IO;
    EVP_KDF_CTX_free(context);
    if (result != TSC_OK)
        tsc_crypto_zero(output, output_length);
    return result;
}

static int aead_arguments(const uint8_t *key, const uint8_t *nonce,
                          const void *aad, size_t aad_length,
                          const void *input, size_t length,
                          const void *output, const uint8_t *tag)
{
    return key && nonce && tag && (aad || !aad_length) &&
        (input || !length) && (output || !length) &&
        aad_length <= INT_MAX && length <= INT_MAX;
}

int tsc_crypto_chacha20poly1305_encrypt(
    const uint8_t key[32], const uint8_t nonce[12],
    const void *aad, size_t aad_length, const void *plaintext, size_t length,
    void *ciphertext, uint8_t tag[16])
{
    EVP_CIPHER_CTX *context;
    uint8_t dummy[16];
    int n = 0, final = 0, result = TSC_ERR_IO;
    if (!aead_arguments(key, nonce, aad, aad_length, plaintext, length, ciphertext, tag))
        return TSC_ERR_ARGUMENT;
    context = EVP_CIPHER_CTX_new();
    if (!context)
        goto done;
    if (EVP_EncryptInit_ex(context, EVP_chacha20_poly1305(), NULL, key, nonce) != 1 ||
        (aad_length && EVP_EncryptUpdate(context, NULL, &n, aad, (int)aad_length) != 1) ||
        (length && EVP_EncryptUpdate(context, ciphertext, &n, plaintext, (int)length) != 1) ||
        EVP_EncryptFinal_ex(context, dummy, &final) != 1 || final != 0 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1)
        goto done;
    result = TSC_OK;
done:
    EVP_CIPHER_CTX_free(context);
    if (result != TSC_OK) {
        tsc_crypto_zero(ciphertext, length);
        tsc_crypto_zero(tag, 16);
    }
    return result;
}

int tsc_crypto_chacha20poly1305_decrypt(
    const uint8_t key[32], const uint8_t nonce[12],
    const void *aad, size_t aad_length, const void *ciphertext, size_t length,
    const uint8_t tag[16], void *plaintext)
{
    EVP_CIPHER_CTX *context;
    uint8_t dummy[16];
    int n = 0, final = 0, result = TSC_ERR_IO;
    if (!aead_arguments(key, nonce, aad, aad_length, ciphertext, length, plaintext, tag)) {
        /* Do not dereference an impossible length supplied with invalid input. */
        if (length <= INT_MAX)
            tsc_crypto_zero(plaintext, length);
        return TSC_ERR_ARGUMENT;
    }
    context = EVP_CIPHER_CTX_new();
    if (!context)
        goto done;
    if (EVP_DecryptInit_ex(context, EVP_chacha20_poly1305(), NULL, key, nonce) != 1 ||
        (aad_length && EVP_DecryptUpdate(context, NULL, &n, aad, (int)aad_length) != 1) ||
        (length && EVP_DecryptUpdate(context, plaintext, &n, ciphertext, (int)length) != 1) ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, 16, (void *)tag) != 1)
        goto done;
    result = EVP_DecryptFinal_ex(context, dummy, &final) == 1 && final == 0
        ? TSC_OK : TSC_ERR_PROTOCOL;
done:
    EVP_CIPHER_CTX_free(context);
    if (result != TSC_OK)
        tsc_crypto_zero(plaintext, length);
    return result;
}
