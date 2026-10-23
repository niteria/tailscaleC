#include "check.h"
#include "tailscalec/crypto.h"
#include "../src/control/protocol.h"
#include <string.h>

/* A hostile byte stream: split every read/write independently, inject errors,
 * and use the actual provider AEAD so framing/authentication paths are tested. */
typedef struct {
    uint8_t input[200000], output[200000];
    size_t input_size, input_offset, output_size, chunk;
    int read_error, write_error;
    uint64_t nonce;
} mock_stream;
static mock_stream mock;
static const uint8_t key[32] = {1, 3, 7, 19, 21, 47, 91};

int tsc_stream_read(tsc_stream *stream, void *buffer, size_t capacity,
                    size_t *received, uint32_t timeout_ms)
{
    mock_stream *m = stream->implementation;
    size_t length = m->input_size - m->input_offset;
    (void)timeout_ms;
    *received = 0;
    if (m->read_error) return m->read_error;
    if (length > capacity) length = capacity;
    if (length > m->chunk) length = m->chunk;
    if (length) memcpy(buffer, m->input + m->input_offset, length);
    m->input_offset += length;
    *received = length;
    return TSC_OK;
}

int tsc_stream_write(tsc_stream *stream, const void *buffer, size_t length,
                     size_t *written, uint32_t timeout_ms)
{
    mock_stream *m = stream->implementation;
    (void)timeout_ms;
    *written = 0;
    if (m->write_error) return m->write_error;
    if (length > m->chunk) length = m->chunk;
    CHECK(length <= sizeof(m->output) - m->output_size);
    memcpy(m->output + m->output_size, buffer, length);
    m->output_size += length;
    *written = length;
    return TSC_OK;
}

static void counter_nonce(uint8_t nonce[12], uint64_t counter)
{
    unsigned i;
    memset(nonce, 0, 12);
    for (i = 0; i < 8; ++i) nonce[11 - i] = (uint8_t)(counter >> (i * 8));
}

static void setup(tsc_noise *noise, tsc_stream *stream, size_t chunk)
{
    memset(&mock, 0, sizeof(mock));
    mock.chunk = chunk;
    stream->implementation = &mock;
    memset(noise, 0, sizeof(*noise));
    noise->stream = stream;
    noise->ready = 1;
    noise->timeout_ms = 100;
    memcpy(noise->rx_key, key, sizeof(key));
    memcpy(noise->tx_key, key, sizeof(key));
}

static void record(const void *data, size_t length)
{
    uint8_t *out = mock.input + mock.input_size;
    uint8_t nonce[12];
    CHECK(length <= TSC_NOISE_PLAINTEXT_SIZE);
    CHECK(length + 19 <= sizeof(mock.input) - mock.input_size);
    counter_nonce(nonce, mock.nonce++);
    out[0] = 4;
    out[1] = (uint8_t)((length + 16) >> 8);
    out[2] = (uint8_t)(length + 16);
    CHECK(tsc_crypto_chacha20poly1305_encrypt(key, nonce, NULL, 0,
                 data, length, out + 3, out + 3 + length) == TSC_OK);
    mock.input_size += length + 19;
}

static void plaintext(const void *data, size_t length)
{
    const uint8_t *bytes = data;
    while (length) {
        size_t chunk = length > TSC_NOISE_PLAINTEXT_SIZE ?
                              TSC_NOISE_PLAINTEXT_SIZE : length;
        record(bytes, chunk);
        bytes += chunk; length -= chunk;
    }
}

static void frame(uint8_t type, uint8_t flags, uint32_t stream,
                    const void *data, uint32_t length)
{
    uint8_t header[9];
    header[0] = (uint8_t)(length >> 16); header[1] = (uint8_t)(length >> 8);
    header[2] = (uint8_t)length; header[3] = type; header[4] = flags;
    header[5] = (uint8_t)(stream >> 24); header[6] = (uint8_t)(stream >> 16);
    header[7] = (uint8_t)(stream >> 8); header[8] = (uint8_t)stream;
    record(header, sizeof(header));
    plaintext(data, length);
}

static void test_noise(void)
{
    tsc_noise noise;
    tsc_stream stream;
    uint8_t data[5000], buffer[5000], nonce[12];
    size_t i, count, offset;
    for (i = 0; i < sizeof(data); ++i) data[i] = (uint8_t)i;
    setup(&noise, &stream, 1);
    record(NULL, 0); /* Empty authenticated records do not signal EOF. */
    plaintext(data, sizeof(data));
    CHECK(tsc_noise_read_exact(&noise, buffer, sizeof(buffer)) == TSC_OK);
    CHECK(!memcmp(data, buffer, sizeof(data)));
    CHECK(noise.rx_nonce == 3);
    CHECK(tsc_noise_send(&noise, data, sizeof(data)) == TSC_OK);
    offset = 0;
    for (i = 0; i < 2; ++i) {
        const uint8_t *p = mock.output + offset;
        size_t length = (size_t)p[1] << 8 | p[2];
        size_t destination = i ? TSC_NOISE_PLAINTEXT_SIZE : 0;
        CHECK(p[0] == 4 && length >= 16 && length <= TSC_NOISE_RECORD_SIZE - 3);
        counter_nonce(nonce, i);
        CHECK(tsc_crypto_chacha20poly1305_decrypt(key, nonce, NULL, 0,
                  p + 3, length - 16, p + 3 + length - 16,
                  buffer + destination) == TSC_OK);
        offset += length + 3;
    }
    CHECK(offset == mock.output_size && !memcmp(data, buffer, sizeof(data)));

    setup(&noise, &stream, 3);
    record(data, 20);
    mock.input[15] ^= 1;
    CHECK(tsc_noise_read(&noise, buffer, sizeof(buffer), &count) == TSC_ERR_PROTOCOL);
    CHECK(noise.failed && !noise.ready);
    CHECK(tsc_noise_read(&noise, buffer, sizeof(buffer), &count) == TSC_ERR_IO);
    CHECK(tsc_noise_send(&noise, data, 1) == TSC_ERR_IO);
    for (i = 0; i < sizeof(noise.rx_key); ++i) CHECK(noise.rx_key[i] == 0);

    setup(&noise, &stream, 9);
    memcpy(mock.input, "\4\20\0", 3); mock.input_size = 3;
    CHECK(tsc_noise_read(&noise, buffer, sizeof(buffer), &count) == TSC_ERR_PROTOCOL);
    setup(&noise, &stream, 9);
    memcpy(mock.input, "\3\0\20", 3); mock.input_size = 3;
    CHECK(tsc_noise_read(&noise, buffer, sizeof(buffer), &count) == TSC_ERR_PROTOCOL);
    setup(&noise, &stream, 9);
    record(data, 20); --mock.input_size;
    CHECK(tsc_noise_read(&noise, buffer, sizeof(buffer), &count) == TSC_ERR_TRUNCATED);
    setup(&noise, &stream, 9);
    noise.tx_nonce = UINT64_MAX;
    CHECK(tsc_noise_send(&noise, data, 1) == TSC_ERR_PROTOCOL);
    setup(&noise, &stream, 9);
    mock.write_error = TSC_ERR_TIMEOUT;
    CHECK(tsc_noise_send(&noise, data, 1) == TSC_ERR_TIMEOUT);
    CHECK(noise.failed);
    setup(&noise, &stream, 9);
    mock.read_error = TSC_ERR_TIMEOUT;
    CHECK(tsc_noise_read(&noise, buffer, sizeof(buffer), &count) == TSC_ERR_TIMEOUT);
    CHECK(noise.failed);
    tsc_noise_clear(&noise);
    for (i = 0; i < sizeof(noise); ++i) CHECK(((uint8_t *)&noise)[i] == 0);

    {
        uint8_t private_key[32] = {99}, public_key[32] = {0}, initiation[101];
        CHECK(tsc_noise_handshake_start(&noise, &stream, 131, private_key,
                                         public_key, initiation) == TSC_ERR_PROTOCOL);
        for (i = 0; i < sizeof(initiation); ++i) CHECK(initiation[i] == 0);
        CHECK(tsc_crypto_x25519_public(public_key, private_key) == TSC_OK);
        CHECK(tsc_noise_handshake_start(&noise, &stream, 131, private_key,
                                         public_key, initiation) == TSC_OK);
        CHECK(initiation[0] == 0 && initiation[1] == 131 && initiation[2] == 1 &&
              initiation[3] == 0 && initiation[4] == 96);
        mock.input_offset = 0; mock.input_size = 3; mock.read_error = 0;
        memcpy(mock.input, "\2\0\57", 3); /* Invalid response length, 47. */
        CHECK(tsc_noise_handshake_finish(&noise) == TSC_ERR_PROTOCOL);
        CHECK(noise.failed);
    }
}

static void start_h2(tsc_h2 *h2, tsc_noise *noise, tsc_stream *stream)
{
    setup(noise, stream, 2);
    frame(4, 0, 0, NULL, 0);
    CHECK(tsc_h2_start(h2, noise) == TSC_OK);
}

static void test_h2(void)
{
    tsc_noise noise;
    tsc_stream stream;
    tsc_h2 h2;
    uint8_t response[70000], body[16000], status200 = 0x88;
    size_t length, i;
    unsigned status;
    int result;
    setup(&noise, &stream, 1);
    {
        static const char early[] = "{\"nodeKeyChallenge\":\"chalpub:"
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\"}";
        uint8_t prefix[9] = {255, 255, 255, 'T', 'S', 0, 0, 0, sizeof(early) - 1};
        record(prefix, 1); record(prefix + 1, 3); record(prefix + 4, 5);
        record(early, sizeof(early) - 1);
    }
    frame(4, 0, 0, NULL, 0);
    CHECK(tsc_h2_start(&h2, &noise) == TSC_OK);
    CHECK(h2.has_challenge);
    for (i = 0; i < 32; ++i) CHECK(h2.challenge[i] == i);
    frame(4, 1, 0, NULL, 0); /* SETTINGS ack */
    frame(6, 0, 0, "12345678", 8); /* PING: client must ACK. */
    frame(1, 0, 1, "\40", 1); /* Dynamic table size update zero. */
    frame(9, 4, 1, &status200, 1); /* HEADERS split across CONTINUATION. */
    frame(0, 9, 1, "\3helloPAD", 9); /* Padded final DATA. */
    CHECK(tsc_h2_post(&h2, "localhost", "/machine/register", "{}", 2,
                       response, sizeof(response), &length, &status) == TSC_OK);
    CHECK(status == 200 && length == 5 && !memcmp(response, "hello", 5));

    /* Sequential stream IDs and a response exceeding the initial connection
     * receive window: no whole-frame allocation or 64 KiB body limit in H2. */
    for (i = 0; i < sizeof(body); ++i) body[i] = (uint8_t)i;
    frame(1, 4, 3, &status200, 1);
    for (i = 0; i < 4; ++i) frame(0, 0, 3, body, sizeof(body));
    frame(0, 1, 3, body, 6000);
    CHECK(tsc_h2_post(&h2, "localhost", "/machine/map", "{}", 2,
                       response, sizeof(response), &length, &status) == TSC_OK);
    CHECK(status == 200 && length == sizeof(response));
    for (i = 0; i < 4; ++i) CHECK(!memcmp(response + i * 16000, body, 16000));
    CHECK(!memcmp(response + 64000, body, 6000));

    /* Respect peer flow control even when SETTINGS starts the stream at zero.
     * Each WINDOW_UPDATE allows just a portion of the request body. */
    setup(&noise, &stream, 1);
    frame(4, 0, 0, "\0\4\0\0\0\0", 6);
    CHECK(tsc_h2_start(&h2, &noise) == TSC_OK);
    frame(8, 0, 1, "\0\0\0\12", 4);
    frame(8, 0, 1, "\0\0\0\12", 4);
    frame(1, 5, 1, &status200, 1);
    CHECK(tsc_h2_post(&h2, "localhost", "/", body, 20,
                       response, sizeof(response), &length, &status) == TSC_OK);
    CHECK(status == 200 && !length && h2.tx_connection_window == 65515 &&
          h2.tx_stream_window == 0);

    /* Streaming maps have no END_STREAM. Length prefix can straddle DATA
     * frames. Return exactly the first map, consume a coalesced second map,
     * then cancel/ignore in-flight old stream frames before a new poll. */
    start_h2(&h2, &noise, &stream);
    frame(1, 4, 1, &status200, 1);
    frame(0, 0, 1, "\2\0", 2);
    frame(0, 0, 1, "\0\0{}\2\0\0\0{}", 10);
    CHECK(tsc_h2_post_map(&h2, "localhost", "/machine/map", "{}", 2,
                       response, sizeof(response), &length, &status) == TSC_OK);
    CHECK(h2.stream_open && status == 200 && length == 6);
    CHECK(!memcmp(response, "\2\0\0\0{}", 6));
    frame(0, 0, 1, "\2\0\0\0{}", 6);
    frame(1, 4, 1, "\40", 1);
    frame(9, 4, 1, "", 0);
    frame(3, 0, 1, "\0\0\0\10", 4);
    frame(1, 4, 3, &status200, 1);
    frame(0, 0, 3, "\2\0\0\0{}", 6);
    CHECK(tsc_h2_post_map(&h2, "localhost", "/machine/map", "{}", 2,
                       response, sizeof(response), &length, &status) == TSC_OK);
    CHECK(h2.stream_open && h2.active_stream == 3 && status == 200 && length == 6);
    CHECK(!memcmp(response, "\2\0\0\0{}", 6));

    start_h2(&h2, &noise, &stream);
    frame(1, 4, 1, &status200, 1);
    frame(0, 1, 1, "\2\0\0\0{", 5); /* Truncated framed map. */
    CHECK(tsc_h2_post_map(&h2, "localhost", "/machine/map", NULL, 0,
               response, sizeof(response), &length, &status) == TSC_ERR_PROTOCOL);

    start_h2(&h2, &noise, &stream);
    frame(1, 4, 1, &status200, 1);
    frame(0, 0, 1, "\377\377\377\377", 4); /* Oversized framed map. */
    CHECK(tsc_h2_post_map(&h2, "localhost", "/machine/map", NULL, 0,
               response, sizeof(response), &length, &status) == TSC_ERR_SPACE);

    start_h2(&h2, &noise, &stream);
    frame(1, 5, 1, "\10\202\154\0", 4); /* Huffman :status 500 (literal). */
    result = tsc_h2_post(&h2, "localhost", "/", NULL, 0,
                           response, sizeof(response), &length, &status);
    CHECK(result == TSC_OK && status == 500 && !length);

    start_h2(&h2, &noise, &stream);
    frame(1, 4, 1, &status200, 1);
    frame(0, 1, 1, "12345678", 8);
    CHECK(tsc_h2_post(&h2, "localhost", "/", NULL, 0, response, 7,
                       &length, &status) == TSC_ERR_SPACE);
    CHECK(h2.failed);

    start_h2(&h2, &noise, &stream);
    frame(1, 4, 1, &status200, 1);
    frame(0, 9, 1, "\10bad", 4);
    CHECK(tsc_h2_post(&h2, "localhost", "/", NULL, 0,
               response, sizeof(response), &length, &status) == TSC_ERR_PROTOCOL);

    start_h2(&h2, &noise, &stream);
    frame(1, 5, 3, &status200, 1); /* Wrong stream. */
    CHECK(tsc_h2_post(&h2, "localhost", "/", NULL, 0,
               response, sizeof(response), &length, &status) == TSC_ERR_PROTOCOL);

    start_h2(&h2, &noise, &stream);
    frame(1, 5, 1, "\276", 1); /* Dynamic table index forbidden. */
    CHECK(tsc_h2_post(&h2, "localhost", "/", NULL, 0,
               response, sizeof(response), &length, &status) == TSC_ERR_PROTOCOL);

    start_h2(&h2, &noise, &stream);
    frame(1, 0, 1, &status200, 1);
    frame(6, 0, 0, "12345678", 8); /* Interleaved header block forbidden. */
    CHECK(tsc_h2_post(&h2, "localhost", "/", NULL, 0,
               response, sizeof(response), &length, &status) == TSC_ERR_PROTOCOL);

    setup(&noise, &stream, 1);
    frame(4, 0, 0, "x", 1); /* SETTINGS length must be a multiple of six. */
    CHECK(tsc_h2_start(&h2, &noise) == TSC_ERR_PROTOCOL);
}

static uint32_t mutate_random(uint32_t *state)
{
    uint32_t value = *state;
    value ^= value << 13; value ^= value >> 17; value ^= value << 5;
    *state = value;
    return value;
}

static void test_mutated_header_blocks(void)
{
    tsc_noise noise;
    tsc_stream stream;
    tsc_h2 h2;
    uint8_t block[256], response[256];
    uint32_t random_state = UINT32_C(0x171a8fc3);
    size_t iteration;
    for (iteration = 0; iteration < 2000; ++iteration) {
        size_t block_length = mutate_random(&random_state) % sizeof(block);
        size_t j, length;
        unsigned status;
        int result;
        for (j = 0; j < block_length; ++j)
            block[j] = (uint8_t)mutate_random(&random_state);
        start_h2(&h2, &noise, &stream);
        frame(1, 5, 1, block, (uint32_t)block_length);
        result = tsc_h2_post(&h2, "localhost", "/machine/map", "{}", 2,
                            response, sizeof(response), &length, &status);
        CHECK(result == TSC_OK || result == TSC_ERR_PROTOCOL);
        CHECK(length == 0);
        if (result == TSC_OK) CHECK(status >= 100 && status <= 599);
    }
}

int main(void)
{
    test_noise();
    test_h2();
    test_mutated_header_blocks();
    puts("Noise/HTTP2 adversarial protocol tests passed");
    return 0;
}
