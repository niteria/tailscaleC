#include "tailscalec/crypto.h"
#include "../system.h"
#include <limits.h>
#include <mbedtls/build_info.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/constant_time.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>

#if !defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED) || !defined(MBEDTLS_ECDH_C)
#error "tailscaleC requires CONFIG_MBEDTLS_ECP_DP_CURVE25519_ENABLED=y and CONFIG_MBEDTLS_ECDH_C=y"
#endif
#if !defined(MBEDTLS_CHACHAPOLY_C)
#error "tailscaleC requires CONFIG_MBEDTLS_CHACHA20_C=y, CONFIG_MBEDTLS_POLY1305_C=y, CONFIG_MBEDTLS_CHACHAPOLY_C=y"
#endif
#if !defined(MBEDTLS_HKDF_C)
#error "tailscaleC requires CONFIG_MBEDTLS_HKDF_C=y"
#endif

void tsc_crypto_zero(void *buffer, size_t length)
{
    if (buffer && length)
        mbedtls_platform_zeroize(buffer, length);
}

int tsc_crypto_equal(const void *a, const void *b, size_t length)
{
    if (!length)
        return 1;
    return a && b && mbedtls_ct_memcmp(a, b, length) == 0;
}

int tsc_crypto_random(void *output, size_t length)
{
    return tsc_system_random_bytes(NULL, output, length);
}

static int crypto_rng(void *context, unsigned char *output, size_t length)
{
    (void)context;
    return tsc_crypto_random(output, length) == TSC_OK ? 0 : MBEDTLS_ERR_ECP_RANDOM_FAILED;
}

int tsc_crypto_x25519_public(uint8_t output[32], const uint8_t private_key[32])
{
    mbedtls_ecp_keypair key;
    size_t length = 0;
    int result = TSC_ERR_IO;
    if (!output || !private_key)
        return TSC_ERR_ARGUMENT;
    mbedtls_ecp_keypair_init(&key);
    if (mbedtls_ecp_read_key(MBEDTLS_ECP_DP_CURVE25519, &key, private_key, 32) == 0 &&
        mbedtls_ecp_keypair_calc_public(&key, crypto_rng, NULL) == 0 &&
        mbedtls_ecp_write_public_key(&key, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                      &length, output, 32) == 0 && length == 32)
        result = TSC_OK;
    mbedtls_ecp_keypair_free(&key);
    if (result != TSC_OK)
        tsc_crypto_zero(output, 32);
    return result;
}

int tsc_crypto_x25519(uint8_t output[32], const uint8_t private_key[32],
                      const uint8_t peer_public_key[32])
{
    mbedtls_ecp_keypair key;
    mbedtls_ecp_group group;
    mbedtls_ecp_point peer;
    mbedtls_mpi secret, scalar;
    int result = TSC_ERR_IO;
    if (!output || !private_key || !peer_public_key)
        return TSC_ERR_ARGUMENT;
    mbedtls_ecp_keypair_init(&key);
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_point_init(&peer);
    mbedtls_mpi_init(&secret);
    mbedtls_mpi_init(&scalar);
    if (mbedtls_ecp_read_key(MBEDTLS_ECP_DP_CURVE25519, &key, private_key, 32) != 0 ||
        mbedtls_ecp_export(&key, &group, &scalar, NULL) != 0)
        goto done;
    if (mbedtls_ecp_point_read_binary(&group, &peer, peer_public_key, 32) != 0 ||
        mbedtls_ecdh_compute_shared(&group, &secret, &peer, &scalar,
                                     crypto_rng, NULL) != 0 ||
        mbedtls_mpi_cmp_int(&secret, 0) == 0) {
        result = TSC_ERR_PROTOCOL;
        goto done;
    }
    if (mbedtls_mpi_write_binary_le(&secret, output, 32) == 0)
        result = TSC_OK;
done:
    mbedtls_mpi_free(&scalar);
    mbedtls_mpi_free(&secret);
    mbedtls_ecp_point_free(&peer);
    mbedtls_ecp_group_free(&group);
    mbedtls_ecp_keypair_free(&key);
    if (result != TSC_OK)
        tsc_crypto_zero(output, 32);
    return result;
}

int tsc_crypto_sha256(const void *data, size_t length, uint8_t output[32])
{
    if ((!data && length) || !output)
        return TSC_ERR_ARGUMENT;
    if (mbedtls_sha256(data, length, output, 0) != 0) {
        tsc_crypto_zero(output, 32);
        return TSC_ERR_IO;
    }
    return TSC_OK;
}

int tsc_crypto_hmac_sha256(const void *key, size_t key_length,
                           const void *data, size_t length, uint8_t output[32])
{
    const mbedtls_md_info_t *info;
    if ((!key && key_length) || (!data && length) || !output)
        return TSC_ERR_ARGUMENT;
    info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info || mbedtls_md_hmac(info, key, key_length, data, length, output) != 0) {
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
    const mbedtls_md_info_t *md;
    if ((!salt && salt_length) || (!key && key_length) || (!info && info_length) ||
        (!output && output_length) || output_length > 255 * 32)
        return TSC_ERR_ARGUMENT;
    if (!output_length)
        return TSC_OK;
    md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md || mbedtls_hkdf(md, salt, salt_length, key, key_length,
                            info, info_length, output, output_length) != 0) {
        tsc_crypto_zero(output, output_length);
        return TSC_ERR_IO;
    }
    return TSC_OK;
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
    mbedtls_chachapoly_context context;
    int result = TSC_ERR_IO;
    if (!aead_arguments(key, nonce, aad, aad_length, plaintext, length, ciphertext, tag))
        return TSC_ERR_ARGUMENT;
    mbedtls_chachapoly_init(&context);
    if (mbedtls_chachapoly_setkey(&context, key) == 0 &&
        mbedtls_chachapoly_encrypt_and_tag(&context, length, nonce, aad, aad_length,
                                           plaintext, ciphertext, tag) == 0)
        result = TSC_OK;
    mbedtls_chachapoly_free(&context);
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
    mbedtls_chachapoly_context context;
    int status, result = TSC_ERR_IO;
    if (!aead_arguments(key, nonce, aad, aad_length, ciphertext, length, plaintext, tag)) {
        if (length <= INT_MAX)
            tsc_crypto_zero(plaintext, length);
        return TSC_ERR_ARGUMENT;
    }
    mbedtls_chachapoly_init(&context);
    if (mbedtls_chachapoly_setkey(&context, key) == 0) {
        status = mbedtls_chachapoly_auth_decrypt(&context, length, nonce, aad,
                                                aad_length, tag, ciphertext, plaintext);
        result = status == 0 ? TSC_OK :
            status == MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED ? TSC_ERR_PROTOCOL : TSC_ERR_IO;
    }
    mbedtls_chachapoly_free(&context);
    if (result != TSC_OK)
        tsc_crypto_zero(plaintext, length);
    return result;
}
