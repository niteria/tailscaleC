/*
 * TS2021 Noise IK transport, adapted from TailTiny/MicroLink ml_noise.c.
 * Copyright (c) 2025-2026 Cameron Malone
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "protocol.h"
#include "tailscalec/crypto.h"
#include "blake2s.h"
#include <stdio.h>
#include <string.h>

static void hash_mix(uint8_t hash[32], const void *data, size_t length)
{
    blake2s_ctx ctx;
    blake2s_init(&ctx, 32, NULL, 0);
    blake2s_update(&ctx, hash, 32);
    if (length) blake2s_update(&ctx, data, length);
    blake2s_final(&ctx, hash);
    tsc_crypto_zero(&ctx, sizeof(ctx));
}

/* HMAC-BLAKE2s, rather than keyed BLAKE2s: Noise HKDF requires HMAC. */
static void hmac_blake2s(const uint8_t key[32], const void *input,
                         size_t length, uint8_t output[32])
{
    blake2s_ctx ctx;
    uint8_t pad[64], inner[32];
    size_t i;
    memset(pad, 0x36, sizeof(pad));
    for (i = 0; i < 32; ++i) pad[i] ^= key[i];
    blake2s_init(&ctx, 32, NULL, 0);
    blake2s_update(&ctx, pad, sizeof(pad));
    if (length) blake2s_update(&ctx, input, length);
    blake2s_final(&ctx, inner);
    for (i = 0; i < sizeof(pad); ++i) pad[i] ^= 0x36 ^ 0x5c;
    blake2s_init(&ctx, 32, NULL, 0);
    blake2s_update(&ctx, pad, sizeof(pad));
    blake2s_update(&ctx, inner, sizeof(inner));
    blake2s_final(&ctx, output);
    tsc_crypto_zero(&ctx, sizeof(ctx));
    tsc_crypto_zero(pad, sizeof(pad));
    tsc_crypto_zero(inner, sizeof(inner));
}

static void hkdf(const uint8_t chaining[32], const void *input, size_t length,
                  uint8_t first[32], uint8_t second[32])
{
    uint8_t key[32], value[33];
    hmac_blake2s(chaining, input, length, key);
    value[0] = 1;
    hmac_blake2s(key, value, 1, first);
    memcpy(value, first, 32);
    value[32] = 2;
    hmac_blake2s(key, value, sizeof(value), second);
    tsc_crypto_zero(key, sizeof(key));
    tsc_crypto_zero(value, sizeof(value));
}

static int mix_dh(tsc_noise *noise, const uint8_t private_key[32],
                    const uint8_t public_key[32], uint8_t key[32])
{
    uint8_t shared[32];
    int result = tsc_crypto_x25519(shared, private_key, public_key);
    if (result == TSC_OK)
        hkdf(noise->chaining_key, shared, sizeof(shared),
             noise->chaining_key, key);
    tsc_crypto_zero(shared, sizeof(shared));
    return result;
}

/* TS2021 uses a big-endian transport counter, unlike standard Noise's LE
 * counter. Handshake nonces are always zero. */
static void make_nonce(uint8_t nonce[12], uint64_t counter)
{
    unsigned i;
    memset(nonce, 0, 4);
    for (i = 0; i < 8; ++i) nonce[11 - i] = (uint8_t)(counter >> (i * 8));
}

static int fail(tsc_noise *noise, int result)
{
    noise->failed = 1;
    noise->ready = 0;
    tsc_crypto_zero(noise->machine_private, 32);
    tsc_crypto_zero(noise->ephemeral_private, 32);
    tsc_crypto_zero(noise->tx_key, 32);
    tsc_crypto_zero(noise->rx_key, 32);
    tsc_crypto_zero(noise->chaining_key, 32);
    return result;
}

static int stream_read_exact(tsc_noise *noise, void *buffer, size_t length)
{
    uint8_t *bytes = buffer;
    while (length) {
        size_t count = 0;
        int result = tsc_stream_read(noise->stream, bytes, length,
                                     &count, noise->timeout_ms);
        if (result != TSC_OK) return fail(noise, result);
        if (!count || count > length) return fail(noise, TSC_ERR_TRUNCATED);
        bytes += count;
        length -= count;
    }
    return TSC_OK;
}

static int stream_write_exact(tsc_noise *noise, const void *buffer, size_t length)
{
    const uint8_t *bytes = buffer;
    while (length) {
        size_t count = 0;
        int result = tsc_stream_write(noise->stream, bytes, length,
                                      &count, noise->timeout_ms);
        if (result != TSC_OK) return fail(noise, result);
        if (!count || count > length) return fail(noise, TSC_ERR_IO);
        bytes += count;
        length -= count;
    }
    return TSC_OK;
}

int tsc_noise_handshake_start(tsc_noise *noise, tsc_stream *stream,
    uint16_t version, const uint8_t machine_private[32],
    const uint8_t server_public[32], uint8_t initiation[101])
{
    static const char name[] = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
    uint8_t public_key[32], ephemeral_public[32], key[32], nonce[12] = {0};
    char prologue[64];
    int result, length;
    if (!noise || !stream || !machine_private || !server_public || !initiation)
        return TSC_ERR_ARGUMENT;
    memset(noise, 0, sizeof(*noise));
    noise->stream = stream;
    noise->timeout_ms = 10000;
    memcpy(noise->machine_private, machine_private, 32);
    blake2s(noise->hash, 32, NULL, 0, name, sizeof(name) - 1);
    memcpy(noise->chaining_key, noise->hash, 32);
    length = snprintf(prologue, sizeof(prologue),
                       "Tailscale Control Protocol v%u", (unsigned)version);
    if (length < 0 || (size_t)length >= sizeof(prologue))
        return fail(noise, TSC_ERR_ARGUMENT);
    hash_mix(noise->hash, prologue, (size_t)length);
    hash_mix(noise->hash, server_public, 32);
    result = tsc_crypto_random(noise->ephemeral_private, 32);
    if (result != TSC_OK) goto done;
    result = tsc_crypto_x25519_public(ephemeral_public, noise->ephemeral_private);
    if (result != TSC_OK) goto done;
    result = tsc_crypto_x25519_public(public_key, machine_private);
    if (result != TSC_OK) goto done;
    initiation[0] = (uint8_t)(version >> 8);
    initiation[1] = (uint8_t)version;
    initiation[2] = 1;
    initiation[3] = 0;
    initiation[4] = 96;
    memcpy(initiation + 5, ephemeral_public, 32);
    hash_mix(noise->hash, ephemeral_public, 32);
    result = mix_dh(noise, noise->ephemeral_private, server_public, key);
    if (result != TSC_OK) goto done;
    result = tsc_crypto_chacha20poly1305_encrypt(key, nonce, noise->hash, 32,
                   public_key, 32, initiation + 37, initiation + 69);
    if (result != TSC_OK) goto done;
    hash_mix(noise->hash, initiation + 37, 48);
    result = mix_dh(noise, machine_private, server_public, key);
    if (result != TSC_OK) goto done;
    result = tsc_crypto_chacha20poly1305_encrypt(key, nonce, noise->hash, 32,
                   NULL, 0, initiation + 85, initiation + 85);
    if (result == TSC_OK) hash_mix(noise->hash, initiation + 85, 16);
done:
    tsc_crypto_zero(key, sizeof(key));
    if (result != TSC_OK) {
        tsc_crypto_zero(initiation, 101);
        return fail(noise, result);
    }
    return TSC_OK;
}

int tsc_noise_handshake_finish(tsc_noise *noise)
{
    uint8_t response[51], key[32], nonce[12] = {0}, empty[1];
    int result;
    if (!noise || !noise->stream || noise->failed || noise->ready)
        return TSC_ERR_ARGUMENT;
    result = stream_read_exact(noise, response, 3);
    if (result != TSC_OK) return result;
    if (response[0] != 2 || response[1] != 0 || response[2] != 48)
        return fail(noise, TSC_ERR_PROTOCOL);
    result = stream_read_exact(noise, response + 3, 48);
    if (result != TSC_OK) return result;
    hash_mix(noise->hash, response + 3, 32);
    result = mix_dh(noise, noise->ephemeral_private, response + 3, key);
    if (result != TSC_OK) goto done;
    result = mix_dh(noise, noise->machine_private, response + 3, key);
    if (result != TSC_OK) goto done;
    result = tsc_crypto_chacha20poly1305_decrypt(key, nonce, noise->hash, 32,
                  NULL, 0, response + 35, empty);
    if (result != TSC_OK) goto done;
    hash_mix(noise->hash, response + 35, 16);
    hkdf(noise->chaining_key, NULL, 0, noise->tx_key, noise->rx_key);
    noise->ready = 1;
done:
    tsc_crypto_zero(key, sizeof(key));
    tsc_crypto_zero(noise->machine_private, 32);
    tsc_crypto_zero(noise->ephemeral_private, 32);
    tsc_crypto_zero(noise->chaining_key, 32);
    if (result != TSC_OK) return fail(noise, result);
    return TSC_OK;
}

int tsc_noise_send(tsc_noise *noise, const void *data, size_t length)
{
    const uint8_t *bytes = data;
    if (!noise || (!data && length)) return TSC_ERR_ARGUMENT;
    if (!noise->ready || noise->failed) return TSC_ERR_IO;
    while (length) {
        uint8_t nonce[12];
        size_t chunk = length > TSC_NOISE_PLAINTEXT_SIZE ?
                           TSC_NOISE_PLAINTEXT_SIZE : length;
        int result;
        if (noise->tx_nonce == UINT64_MAX) return fail(noise, TSC_ERR_PROTOCOL);
        make_nonce(nonce, noise->tx_nonce++);
        noise->tx_buffer[0] = 4;
        noise->tx_buffer[1] = (uint8_t)((chunk + 16) >> 8);
        noise->tx_buffer[2] = (uint8_t)(chunk + 16);
        result = tsc_crypto_chacha20poly1305_encrypt(noise->tx_key, nonce,
                   NULL, 0, bytes, chunk, noise->tx_buffer + 3,
                   noise->tx_buffer + 3 + chunk);
        if (result != TSC_OK) return fail(noise, result);
        result = stream_write_exact(noise, noise->tx_buffer, chunk + 19);
        if (result != TSC_OK) return result;
        bytes += chunk;
        length -= chunk;
    }
    return TSC_OK;
}

int tsc_noise_read(tsc_noise *noise, void *data, size_t capacity, size_t *length)
{
    if (!noise || (!data && capacity) || !length) return TSC_ERR_ARGUMENT;
    *length = 0;
    if (!noise->ready || noise->failed) return TSC_ERR_IO;
    if (!capacity) return TSC_OK;
    while (noise->rx_offset == noise->rx_length) {
        uint8_t header[3], nonce[12];
        size_t count;
        int result = stream_read_exact(noise, header, 3);
        if (result != TSC_OK) return result;
        count = ((size_t)header[1] << 8) | header[2];
        if (header[0] != 4 || count < 16 || count > TSC_NOISE_RECORD_SIZE - 3 ||
              noise->rx_nonce == UINT64_MAX)
            return fail(noise, TSC_ERR_PROTOCOL);
        result = stream_read_exact(noise, noise->rx_buffer, count);
        if (result != TSC_OK) return result;
        make_nonce(nonce, noise->rx_nonce++);
        result = tsc_crypto_chacha20poly1305_decrypt(noise->rx_key, nonce,
                   NULL, 0, noise->rx_buffer, count - 16,
                   noise->rx_buffer + count - 16, noise->rx_buffer);
        if (result != TSC_OK) return fail(noise, result);
        noise->rx_offset = 0;
        noise->rx_length = count - 16;
    }
    *length = noise->rx_length - noise->rx_offset;
    if (*length > capacity) *length = capacity;
    memcpy(data, noise->rx_buffer + noise->rx_offset, *length);
    noise->rx_offset += *length;
    return TSC_OK;
}

int tsc_noise_read_exact(tsc_noise *noise, void *data, size_t length)
{
    uint8_t *bytes = data;
    if (!noise || (!data && length)) return TSC_ERR_ARGUMENT;
    while (length) {
        size_t count = 0;
        int result = tsc_noise_read(noise, bytes, length, &count);
        if (result != TSC_OK) return result;
        bytes += count;
        length -= count;
    }
    return TSC_OK;
}

void tsc_noise_clear(tsc_noise *noise)
{
    if (noise) tsc_crypto_zero(noise, sizeof(*noise));
}
