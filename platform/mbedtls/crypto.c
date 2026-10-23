/* mbedTLS 2.28 provider for small RTOS targets. */
#include "tailscalec/crypto.h"
#include "../system.h"
#include <limits.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>

void tsc_crypto_zero(void *p, size_t n)
{
    if (p && n) mbedtls_platform_zeroize(p, n);
}

int tsc_crypto_equal(const void *a, const void *b, size_t n)
{
    const unsigned char *x = a, *y = b;
    volatile unsigned char difference = 0;
    if ((!a || !b) && n) return 0;
    for (size_t i = 0; i < n; ++i) difference |= x[i] ^ y[i];
    return difference == 0;
}

int tsc_crypto_random(void *p, size_t n)
{
    return tsc_system_random_bytes(NULL, p, n);
}

static int rng(void *user, unsigned char *p, size_t n)
{
    (void)user;
    return tsc_crypto_random(p, n) == TSC_OK ? 0 : MBEDTLS_ERR_ECP_RANDOM_FAILED;
}

int tsc_crypto_x25519_public(uint8_t out[32], const uint8_t private_key[32])
{
    mbedtls_ecp_keypair key;
    size_t n = 0;
    int result = TSC_ERR_IO;
    if (!out || !private_key) return TSC_ERR_ARGUMENT;
    mbedtls_ecp_keypair_init(&key);
    if (!mbedtls_ecp_read_key(MBEDTLS_ECP_DP_CURVE25519, &key, private_key, 32) &&
        !mbedtls_ecp_mul(&key.grp, &key.Q, &key.d, &key.grp.G, rng, NULL) &&
        !mbedtls_ecp_point_write_binary(&key.grp, &key.Q,
            MBEDTLS_ECP_PF_UNCOMPRESSED, &n, out, 32) && n == 32)
        result = TSC_OK;
    mbedtls_ecp_keypair_free(&key);
    if (result) tsc_crypto_zero(out, 32);
    return result;
}

int tsc_crypto_x25519(uint8_t out[32], const uint8_t private_key[32],
                      const uint8_t public_key[32])
{
    mbedtls_ecp_keypair key;
    mbedtls_ecp_point peer;
    mbedtls_mpi secret;
    int result = TSC_ERR_PROTOCOL;
    if (!out || !private_key || !public_key) return TSC_ERR_ARGUMENT;
    mbedtls_ecp_keypair_init(&key);
    mbedtls_ecp_point_init(&peer);
    mbedtls_mpi_init(&secret);
    if (!mbedtls_ecp_read_key(MBEDTLS_ECP_DP_CURVE25519, &key, private_key, 32) &&
        !mbedtls_ecp_point_read_binary(&key.grp, &peer, public_key, 32) &&
        !mbedtls_ecdh_compute_shared(&key.grp, &secret, &peer, &key.d, rng, NULL) &&
        mbedtls_mpi_cmp_int(&secret, 0) != 0 &&
        !mbedtls_mpi_write_binary_le(&secret, out, 32))
        result = TSC_OK;
    mbedtls_mpi_free(&secret);
    mbedtls_ecp_point_free(&peer);
    mbedtls_ecp_keypair_free(&key);
    if (result) tsc_crypto_zero(out, 32);
    return result;
}

int tsc_crypto_sha256(const void *p, size_t n, uint8_t out[32])
{
    if ((!p && n) || !out) return TSC_ERR_ARGUMENT;
    if (!mbedtls_sha256_ret(p, n, out, 0)) return TSC_OK;
    tsc_crypto_zero(out, 32);
    return TSC_ERR_IO;
}

int tsc_crypto_hmac_sha256(const void *key, size_t key_n,
                          const void *p, size_t n, uint8_t out[32])
{
    if ((!key && key_n) || (!p && n) || !out) return TSC_ERR_ARGUMENT;
    if (!mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                         key, key_n, p, n, out)) return TSC_OK;
    tsc_crypto_zero(out, 32);
    return TSC_ERR_IO;
}

int tsc_crypto_hkdf_sha256(const void *salt, size_t salt_n,
                          const void *key, size_t key_n,
                          const void *info, size_t info_n,
                          void *out, size_t out_n)
{
    if ((!salt && salt_n) || (!key && key_n) || (!info && info_n) ||
        (!out && out_n) || out_n > 255 * 32) return TSC_ERR_ARGUMENT;
    if (!out_n) return TSC_OK;
    if (!mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                      salt, salt_n, key, key_n, info, info_n, out, out_n))
        return TSC_OK;
    tsc_crypto_zero(out, out_n);
    return TSC_ERR_IO;
}

int tsc_crypto_chacha20poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
    const void *aad, size_t aad_n, const void *in, size_t n, void *out, uint8_t tag[16])
{
    mbedtls_chachapoly_context ctx;
    int rc;
    if (!key || !nonce || (!aad && aad_n) || (!in && n) || (!out && n) || !tag ||
        n > INT_MAX || aad_n > INT_MAX)
        return TSC_ERR_ARGUMENT;
    mbedtls_chachapoly_init(&ctx);
    rc = mbedtls_chachapoly_setkey(&ctx, key);
    if (!rc) rc = mbedtls_chachapoly_encrypt_and_tag(&ctx, n, nonce,
                                                    aad, aad_n, in, out, tag);
    mbedtls_chachapoly_free(&ctx);
    if (!rc) return TSC_OK;
    tsc_crypto_zero(out, n);
    tsc_crypto_zero(tag, 16);
    return TSC_ERR_IO;
}

int tsc_crypto_chacha20poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
    const void *aad, size_t aad_n, const void *in, size_t n,
    const uint8_t tag[16], void *out)
{
    mbedtls_chachapoly_context ctx;
    int rc;
    if (!key || !nonce || (!aad && aad_n) || (!in && n) || (!out && n) || !tag ||
        n > INT_MAX || aad_n > INT_MAX) {
        if (n <= INT_MAX) tsc_crypto_zero(out, n);
        return TSC_ERR_ARGUMENT;
    }
    mbedtls_chachapoly_init(&ctx);
    rc = mbedtls_chachapoly_setkey(&ctx, key);
    if (!rc) rc = mbedtls_chachapoly_auth_decrypt(&ctx, n, nonce,
                                                 aad, aad_n, tag, in, out);
    mbedtls_chachapoly_free(&ctx);
    if (!rc) return TSC_OK;
    tsc_crypto_zero(out, n);
    return rc == MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED ? TSC_ERR_PROTOCOL : TSC_ERR_IO;
}
