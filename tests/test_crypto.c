#include "tailscalec/crypto.h"
#include "check.h"
#include <limits.h>
#include <string.h>

static size_t unhex(const char *hex, uint8_t *output)
{
    size_t i, length = strlen(hex);
    CHECK((length & 1) == 0);
    for (i = 0; i < length / 2; ++i) {
        unsigned value;
        CHECK(sscanf(hex + 2 * i, "%2x", &value) == 1);
        output[i] = (uint8_t)value;
    }
    return length / 2;
}

static void check_hex(const void *actual, size_t length, const char *expected)
{
    uint8_t bytes[256];
    CHECK(strlen(expected) / 2 <= sizeof(bytes));
    CHECK(unhex(expected, bytes) == length);
    CHECK(tsc_crypto_equal(actual, bytes, length));
}

static void test_hashes(void)
{
    uint8_t digest[32], key[32], output[42], ikm[22], salt[13], info[10];
    size_t i;
    CHECK(tsc_crypto_sha256(NULL, 0, digest) == TSC_OK);
    check_hex(digest, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(tsc_crypto_sha256("abc", 3, digest) == TSC_OK);
    check_hex(digest, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    memset(key, 0x0b, 20);
    CHECK(tsc_crypto_hmac_sha256(key, 20, "Hi There", 8, digest) == TSC_OK);
    check_hex(digest, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    CHECK(tsc_crypto_hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28, digest) == TSC_OK);
    check_hex(digest, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    CHECK(tsc_crypto_hmac_sha256(NULL, 0, NULL, 0, digest) == TSC_OK);
    check_hex(digest, 32, "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
    memset(ikm, 0x0b, sizeof(ikm));
    for (i = 0; i < sizeof(salt); ++i)
        salt[i] = (uint8_t)i;
    for (i = 0; i < sizeof(info); ++i)
        info[i] = (uint8_t)(0xf0 + i);
    /* RFC 5869 Appendix A.1 and A.3. */
    CHECK(tsc_crypto_hkdf_sha256(salt, sizeof(salt), ikm, sizeof(ikm),
                                 info, sizeof(info), output, sizeof(output)) == TSC_OK);
    check_hex(output, sizeof(output), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    CHECK(tsc_crypto_hkdf_sha256(NULL, 0, ikm, sizeof(ikm), NULL, 0,
                                 output, sizeof(output)) == TSC_OK);
    check_hex(output, sizeof(output), "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
    CHECK(tsc_crypto_sha256(NULL, 1, digest) == TSC_ERR_ARGUMENT);
    CHECK(tsc_crypto_sha256("a", 1, NULL) == TSC_ERR_ARGUMENT);
    CHECK(tsc_crypto_hmac_sha256(NULL, 1, NULL, 0, digest) == TSC_ERR_ARGUMENT);
    CHECK(tsc_crypto_hmac_sha256(key, 1, NULL, 1, digest) == TSC_ERR_ARGUMENT);
    CHECK(tsc_crypto_hkdf_sha256(NULL, 0, NULL, 0, NULL, 0, NULL, 0) == TSC_OK);
    CHECK(tsc_crypto_hkdf_sha256(NULL, 0, NULL, 0, NULL, 0, output, 8161) == TSC_ERR_ARGUMENT);
}

static void test_x25519(void)
{
    uint8_t alice[32], bob[32], apub[32], bpub[32], ab[32], ba[32], zero[32] = {0};
    uint8_t scalar[32] = {9}, point[32] = {9}, previous[32];
    size_t iteration;
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", alice);
    unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", bob);
    CHECK(tsc_crypto_x25519_public(apub, alice) == TSC_OK);
    CHECK(tsc_crypto_x25519_public(bpub, bob) == TSC_OK);
    check_hex(apub, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    check_hex(bpub, 32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    /* Private inputs are clamped by the provider, not by callers. */
    alice[0] ^= 7;
    alice[31] ^= 0xc0;
    CHECK(tsc_crypto_x25519_public(ab, alice) == TSC_OK);
    CHECK(tsc_crypto_equal(ab, apub, 32));
    alice[0] ^= 7;
    alice[31] ^= 0xc0;
    CHECK(tsc_crypto_x25519(ab, alice, bpub) == TSC_OK);
    CHECK(tsc_crypto_x25519(ba, bob, apub) == TSC_OK);
    CHECK(tsc_crypto_equal(ab, ba, 32));
    check_hex(ab, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    /* RFC 7748 requires ignoring bit 255 of the input public key. */
    bpub[31] ^= 0x80;
    CHECK(tsc_crypto_x25519(ba, alice, bpub) == TSC_OK);
    CHECK(tsc_crypto_equal(ab, ba, 32));
    memset(ab, 0xaa, 32);
    CHECK(tsc_crypto_x25519(ab, alice, zero) == TSC_ERR_PROTOCOL);
    CHECK(tsc_crypto_equal(ab, zero, 32));
    zero[0] = 1;
    CHECK(tsc_crypto_x25519(ab, alice, zero) == TSC_ERR_PROTOCOL);
    CHECK(tsc_crypto_x25519(NULL, alice, bpub) == TSC_ERR_ARGUMENT);
    CHECK(tsc_crypto_x25519_public(apub, NULL) == TSC_ERR_ARGUMENT);
    /* RFC 7748 section 5.2 iterative vectors exercise raw private/public
     * input handling, including exact in-place scalar/output overlap. */
    for (iteration = 0; iteration < 1000; ++iteration) {
        memcpy(previous, scalar, 32);
        CHECK(tsc_crypto_x25519(scalar, scalar, point) == TSC_OK);
        memcpy(point, previous, 32);
        if (iteration == 0)
            check_hex(scalar, 32, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
    }
    check_hex(scalar, 32, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
}

static void test_aead_vector(void)
{
    const char *plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    uint8_t key[32], nonce[12], aad[12], tag[16], cipher[114], output[114], zero[114] = {0};
    size_t i;
    unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", key);
    unhex("070000004041424344454647", nonce);
    unhex("50515253c0c1c2c3c4c5c6c7", aad);
    CHECK(strlen(plaintext) == sizeof(cipher));
    CHECK(tsc_crypto_chacha20poly1305_encrypt(key, nonce, aad, sizeof(aad),
        plaintext, sizeof(cipher), cipher, tag) == TSC_OK);
    check_hex(cipher, sizeof(cipher),
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3"
        "ff4def08e4b7a9de576d26586cec64b6116");
    check_hex(tag, sizeof(tag), "1ae10b594f09e26a7e902ecbd0600691");
    CHECK(tsc_crypto_chacha20poly1305_decrypt(key, nonce, aad, sizeof(aad),
        cipher, sizeof(cipher), tag, output) == TSC_OK);
    CHECK(memcmp(output, plaintext, sizeof(output)) == 0);
    for (i = 0; i < sizeof(tag); ++i) {
        tag[i] ^= 1;
        memset(output, 0xaa, sizeof(output));
        CHECK(tsc_crypto_chacha20poly1305_decrypt(key, nonce, aad, sizeof(aad),
            cipher, sizeof(cipher), tag, output) == TSC_ERR_PROTOCOL);
        CHECK(tsc_crypto_equal(output, zero, sizeof(output)));
        tag[i] ^= 1;
    }
    cipher[0] ^= 1;
    CHECK(tsc_crypto_chacha20poly1305_decrypt(key, nonce, aad, sizeof(aad),
        cipher, sizeof(cipher), tag, output) == TSC_ERR_PROTOCOL);
    cipher[0] ^= 1;
    aad[0] ^= 1;
    CHECK(tsc_crypto_chacha20poly1305_decrypt(key, nonce, aad, sizeof(aad),
        cipher, sizeof(cipher), tag, output) == TSC_ERR_PROTOCOL);
    aad[0] ^= 1;
    nonce[0] ^= 1;
    CHECK(tsc_crypto_chacha20poly1305_decrypt(key, nonce, aad, sizeof(aad),
        cipher, sizeof(cipher), tag, output) == TSC_ERR_PROTOCOL);
    nonce[0] ^= 1;
    key[0] ^= 1;
    CHECK(tsc_crypto_chacha20poly1305_decrypt(key, nonce, aad, sizeof(aad),
        cipher, sizeof(cipher), tag, output) == TSC_ERR_PROTOCOL);
    key[0] ^= 1;
    CHECK(tsc_crypto_chacha20poly1305_encrypt(key, nonce, NULL, 0, NULL, 0, NULL, tag) == TSC_OK);
    CHECK(tsc_crypto_chacha20poly1305_decrypt(key, nonce, NULL, 0, NULL, 0, tag, NULL) == TSC_OK);
    tag[0] ^= 1;
    CHECK(tsc_crypto_chacha20poly1305_decrypt(key, nonce, NULL, 0, NULL, 0, tag, NULL) == TSC_ERR_PROTOCOL);
    CHECK(tsc_crypto_chacha20poly1305_encrypt(key, nonce, NULL, 1, NULL, 0, NULL, tag) == TSC_ERR_ARGUMENT);
    CHECK(tsc_crypto_chacha20poly1305_encrypt(key, nonce, NULL, 0, cipher, (size_t)INT_MAX + 1, output, tag) == TSC_ERR_ARGUMENT);
}

static void test_roundtrips(void)
{
    static const size_t lengths[] = {0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 1023, 1536};
    uint8_t key[32], nonce[12], buffer[1536], expected[1536], tag[16], aad[1536];
    size_t i, j;
    CHECK(tsc_crypto_random(key, sizeof(key)) == TSC_OK);
    CHECK(tsc_crypto_random(aad, sizeof(aad)) == TSC_OK);
    CHECK(tsc_crypto_random(expected, sizeof(expected)) == TSC_OK);
    for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        for (j = 0; j < sizeof(lengths) / sizeof(lengths[0]); ++j) {
            CHECK(tsc_crypto_random(nonce, sizeof(nonce)) == TSC_OK);
            memcpy(buffer, expected, lengths[i]);
            CHECK(tsc_crypto_chacha20poly1305_encrypt(key, nonce, aad, lengths[j],
                buffer, lengths[i], buffer, tag) == TSC_OK);
            CHECK(tsc_crypto_chacha20poly1305_decrypt(key, nonce, aad, lengths[j],
                buffer, lengths[i], tag, buffer) == TSC_OK);
            CHECK(tsc_crypto_equal(buffer, expected, lengths[i]));
        }
    }
    CHECK(tsc_crypto_random(NULL, 0) == TSC_OK);
    CHECK(tsc_crypto_random(NULL, 1) == TSC_ERR_ARGUMENT);
    CHECK(tsc_crypto_equal(NULL, NULL, 0));
    CHECK(!tsc_crypto_equal(NULL, key, 1));
    CHECK(!tsc_crypto_equal("a", "b", 1));
    tsc_crypto_zero(key, sizeof(key));
    for (i = 0; i < sizeof(key); ++i)
        CHECK(key[i] == 0);
    tsc_crypto_zero(NULL, 0);
}

int main(void)
{
    test_hashes();
    test_x25519();
    test_aead_vector();
    test_roundtrips();
    puts("crypto vectors, authentication failures, boundaries and in-place roundtrips passed");
    return 0;
}
