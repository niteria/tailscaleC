#include "core.h"
#include "crypto.h"

#include <limits.h>
#include <string.h>

#define TSC_WG_RETRY_MS UINT64_C(5000)
#define TSC_WG_ATTEMPT_MS UINT64_C(90000)
#define TSC_WG_REKEY_MS UINT64_C(120000)
#define TSC_WG_REJECT_MS UINT64_C(180000)

_Static_assert(sizeof(struct message_handshake_initiation) == 148,
               "WireGuard initiation wire size");
_Static_assert(sizeof(struct message_handshake_response) == 92,
               "WireGuard response wire size");
_Static_assert(sizeof(struct message_cookie_reply) == 64,
               "WireGuard cookie wire size");

uint64_t tsc_wgi_sys_now(tsc_wg *device) {
    return device->hooks.monotonic_ms(device->hooks.user);
}

void tsc_wgi_random_bytes(tsc_wg *device, void *bytes, size_t length) {
    if (device->hooks.random_bytes(device->hooks.user, bytes, length) != TSC_OK) {
        tsc_crypto_zero(bytes, length);
        device->random_failed = true;
    }
}

void tsc_wgi_tai64n_now(tsc_wg *device, uint8_t output[12]) {
    size_t i;
    if (device->hooks.tai64n_now(device->hooks.user, output) != TSC_OK) {
        tsc_crypto_zero(output, 12);
        device->timestamp_failed = true;
        return;
    }
    /* Multiple handshakes can happen within one clock tick. */
    if (memcmp(output, device->last_timestamp, 12) <= 0) {
        memcpy(output, device->last_timestamp, 12);
        for (i = 12; i > 0; --i) {
            if (++output[i - 1] != 0) break;
        }
        if (i == 0) device->timestamp_failed = true;
    }
    memcpy(device->last_timestamp, output, 12);
}

static tsc_wg_peer *valid_peer(tsc_wg *device, size_t slot) {
    if (!device || !device->valid || slot >= device->peer_capacity ||
        !device->peers[slot].valid) return NULL;
    return &device->peers[slot];
}

static int begin_output(void *output, size_t capacity, size_t *written) {
    if (written) *written = 0;
    if (!written || (!output && capacity)) return TSC_ERR_ARGUMENT;
    return TSC_OK;
}

int tsc_wg_init(tsc_wg *device, tsc_wg_peer *peers, size_t peer_capacity,
        const uint8_t private_key[32], const tsc_wg_hooks *hooks) {
    static const uint8_t zero[32] = {0};
    uint8_t key[32];
    tsc_wg_hooks callbacks;
    if (!device || !peers || !peer_capacity ||
        peer_capacity > SIZE_MAX / sizeof(*peers) || !private_key || !hooks ||
        !hooks->random_bytes || !hooks->monotonic_ms || !hooks->tai64n_now ||
        tsc_crypto_equal(private_key, zero, sizeof(zero))) return TSC_ERR_ARGUMENT;
    memcpy(key, private_key, sizeof(key));
    callbacks = *hooks;
    memset(device, 0, sizeof(*device));
    memset(peers, 0, peer_capacity * sizeof(*peers));
    device->peers = peers;
    device->peer_capacity = peer_capacity;
    device->hooks = callbacks;
    tsc_wgi_init(device);
    if (!tsc_wgi_device_init(device, key) || device->random_failed) {
        bool rng_error = device->random_failed;
        tsc_crypto_zero(key, sizeof(key));
        tsc_wg_destroy(device);
        return rng_error ? TSC_WG_ERR_RANDOM : TSC_ERR_PROTOCOL;
    }
    tsc_crypto_zero(key, sizeof(key));
    return TSC_OK;
}

void tsc_wg_destroy(tsc_wg *device) {
    if (!device) return;
    if (device->peers && device->peer_capacity <= SIZE_MAX / sizeof(*device->peers))
        tsc_crypto_zero(device->peers, device->peer_capacity * sizeof(*device->peers));
    tsc_crypto_zero(device, sizeof(*device));
}

int tsc_wg_peer_set(tsc_wg *device, size_t slot,
        const uint8_t public_key[32], const uint8_t preshared_key[32]) {
    static const uint8_t zero[32] = {0};
    uint8_t key[32], psk[32];
    tsc_wg_peer *peer;
    size_t i;
    if (!device || !device->valid || slot >= device->peer_capacity ||
        !public_key) return TSC_ERR_ARGUMENT;
    if (tsc_crypto_equal(public_key, device->public_key, 32)) return TSC_ERR_ARGUMENT;
    for (i = 0; i < device->peer_capacity; ++i) {
        if (i != slot && device->peers[i].valid &&
            tsc_crypto_equal(public_key, device->peers[i].public_key, 32))
            return TSC_ERR_ARGUMENT;
    }
    peer = &device->peers[slot];
    if (peer->valid && tsc_crypto_equal(peer->public_key, public_key, 32) &&
        tsc_crypto_equal(peer->preshared_key, preshared_key ? preshared_key : zero, 32))
        return TSC_OK;
    memcpy(key, public_key, 32);
    memcpy(psk, preshared_key ? preshared_key : zero, 32);
    if (!tsc_wgi_peer_init(device, peer, key, psk)) {
        tsc_crypto_zero(peer, sizeof(*peer));
        tsc_crypto_zero(key, sizeof(key));
        tsc_crypto_zero(psk, sizeof(psk));
        return TSC_WG_ERR_AUTH;
    }
    tsc_crypto_zero(key, sizeof(key));
    tsc_crypto_zero(psk, sizeof(psk));
    return TSC_OK;
}

int tsc_wg_peer_remove(tsc_wg *device, size_t slot) {
    if (!device || !device->valid || slot >= device->peer_capacity)
        return TSC_ERR_ARGUMENT;
    tsc_crypto_zero(&device->peers[slot], sizeof(device->peers[slot]));
    return TSC_OK;
}

int tsc_wg_peer_established(const tsc_wg *device, size_t slot) {
    const tsc_wg_peer *peer;
    uint64_t now;
    if (!device || !device->valid || slot >= device->peer_capacity) return 0;
    peer = &device->peers[slot];
    now = device->hooks.monotonic_ms(device->hooks.user);
    return peer->valid && peer->curr_keypair.valid && peer->curr_keypair.sending_valid &&
        peer->curr_keypair.sending_counter < REJECT_AFTER_MESSAGES &&
        now - peer->curr_keypair.keypair_millis < TSC_WG_REJECT_MS;
}

static int initiate(tsc_wg *device, tsc_wg_peer *peer, void *output,
        size_t capacity, size_t *written) {
    struct message_handshake_initiation message;
    uint64_t now = tsc_wgi_sys_now(device);
    int result = TSC_OK;
    if (peer->initiation_sent && now - peer->last_initiation_tx <
        (peer->retry_interval_ms ? peer->retry_interval_ms : TSC_WG_RETRY_MS))
        return TSC_AGAIN;
    if (capacity < sizeof(message)) return TSC_ERR_SPACE;
    device->random_failed = device->timestamp_failed = false;
    if (!tsc_wgi_create_handshake_initiation(device, peer, &message))
        result = TSC_WG_ERR_AUTH;
    if (device->random_failed) result = TSC_WG_ERR_RANDOM;
    if (device->timestamp_failed) result = TSC_ERR_IO;
    if (result == TSC_OK) {
        memcpy(output, &message, sizeof(message));
        *written = sizeof(message);
        peer->last_initiation_tx = now;
        peer->initiation_sent = true;
        /* The uniformly random, per-device-unique handshake sender index is
         * also fresh entropy for protocol retry jitter; no extra RNG call. */
        peer->retry_interval_ms = (uint16_t)(TSC_WG_RETRY_MS +
            U8TO32_LITTLE(message.sender) % 334u);
        peer->send_handshake = false;
        peer->handshake_mac1_valid = true;
        memcpy(peer->handshake_mac1, message.mac1, 16);
    } else {
        tsc_crypto_zero(&peer->handshake, sizeof(peer->handshake));
    }
    tsc_crypto_zero(&message, sizeof(message));
    return result;
}

int tsc_wg_start(tsc_wg *device, size_t slot, void *output,
        size_t capacity, size_t *written) {
    tsc_wg_peer *peer = valid_peer(device, slot);
    int result = begin_output(output, capacity, written);
    if (result != TSC_OK || !peer) return TSC_ERR_ARGUMENT;
    if (!peer->active) {
        peer->active = true;
        peer->handshake_started = tsc_wgi_sys_now(device);
    }
    if (!peer->handshake.valid) peer->handshake_started = tsc_wgi_sys_now(device);
    return initiate(device, peer, output, capacity, written);
}

static bool expired(tsc_wg *device, const tsc_wg_keypair *keypair) {
    return tsc_wgi_sys_now(device) - keypair->keypair_millis >= TSC_WG_REJECT_MS;
}

int tsc_wg_encrypt(tsc_wg *device, size_t slot, const void *plaintext,
        size_t length, void *output, size_t capacity, size_t *written) {
    tsc_wg_peer *peer = valid_peer(device, slot);
    tsc_wg_keypair *keypair;
    uint8_t *bytes = output;
    size_t padded;
    int result = begin_output(output, capacity, written);
    if (result != TSC_OK || !peer || (!plaintext && length)) return TSC_ERR_ARGUMENT;
    if (length > 65472) return TSC_ERR_SPACE;
    padded = (length + 15u) & ~(size_t)15u;
    if (capacity < padded + TSC_WG_OVERHEAD) return TSC_ERR_SPACE;
    keypair = &peer->curr_keypair;
    if (!keypair->valid || !keypair->sending_valid) {
        peer->send_handshake = true;
        return TSC_AGAIN;
    }
    if (expired(device, keypair) || keypair->sending_counter >= REJECT_AFTER_MESSAGES) {
        tsc_wgi_keypair_destroy(keypair);
        peer->send_handshake = true;
        return TSC_WG_ERR_EXPIRED;
    }
    if (length) memmove(bytes + 16, plaintext, length);
    memset(bytes + 16 + length, 0, padded - length);
    memset(bytes, 0, 4);
    bytes[0] = MESSAGE_TRANSPORT_DATA;
    U32TO8_LITTLE(bytes + 4, keypair->remote_index);
    U64TO8_LITTLE(bytes + 8, keypair->sending_counter);
    if (!tsc_wgi_aead_encrypt(bytes + 16, bytes + 16, padded, NULL, 0,
                             keypair->sending_counter, keypair->sending_key)) {
        tsc_crypto_zero(output, padded + TSC_WG_OVERHEAD);
        return TSC_ERR_IO;
    }
    ++keypair->sending_counter;
    keypair->last_tx = peer->last_tx = tsc_wgi_sys_now(device);
    peer->keepalive_pending = false;
    if (length && !peer->new_handshake_pending) {
        peer->new_handshake_pending = true;
        peer->new_handshake_due = peer->last_tx +
            (uint64_t)(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT) * 1000;
    }
    if (keypair->sending_counter >= REKEY_AFTER_MESSAGES ||
        (keypair->initiator && keypair->last_tx - keypair->keypair_millis >= TSC_WG_REKEY_MS))
        peer->send_handshake = true;
    *written = padded + TSC_WG_OVERHEAD;
    return TSC_OK;
}

int tsc_wg_tick(tsc_wg *device, size_t slot, void *output,
        size_t capacity, size_t *written) {
    tsc_wg_peer *peer = valid_peer(device, slot);
    uint64_t now;
    int result = begin_output(output, capacity, written);
    tsc_wg_keypair *keys[3];
    size_t i;
    if (result != TSC_OK || !peer) return TSC_ERR_ARGUMENT;
    now = tsc_wgi_sys_now(device);
    keys[0] = &peer->curr_keypair;
    keys[1] = &peer->prev_keypair;
    keys[2] = &peer->next_keypair;
    for (i = 0; i < 3; ++i)
        if (keys[i]->valid && expired(device, keys[i])) tsc_wgi_keypair_destroy(keys[i]);
    if (!peer->active) return TSC_AGAIN;
    if (peer->new_handshake_pending && now >= peer->new_handshake_due) {
        peer->new_handshake_pending = false;
        peer->send_handshake = true;
    }
    /* A responder's new keys remain pending until an authenticated transport
     * confirms that the remote peer received our handshake response. */
    if (!peer->curr_keypair.valid && peer->next_keypair.valid &&
        !peer->send_handshake) return TSC_AGAIN;
    if (peer->handshake.valid && peer->handshake.initiator &&
        now - peer->handshake_started >= TSC_WG_ATTEMPT_MS) {
        tsc_crypto_zero(&peer->handshake, sizeof(peer->handshake));
        peer->active = false;
        peer->send_handshake = false;
        return TSC_AGAIN;
    }
    if (!peer->curr_keypair.valid || peer->send_handshake ||
        (peer->curr_keypair.initiator &&
         now - peer->curr_keypair.keypair_millis >= TSC_WG_REKEY_MS)) {
        if (!peer->handshake.valid) peer->handshake_started = now;
        return initiate(device, peer, output, capacity, written);
    }
    if ((peer->keepalive_pending && now >= peer->keepalive_due) ||
        (peer->keepalive_interval &&
         now - peer->last_tx >= (uint64_t)peer->keepalive_interval * 1000))
        return tsc_wg_encrypt(device, slot, NULL, 0, output, capacity, written);
    return TSC_AGAIN;
}

static void event_peer(tsc_wg *device, tsc_wg_peer *peer, tsc_wg_event *event) {
    event->peer_index = (size_t)(peer - device->peers);
    event->authenticated = true;
    event->established = tsc_wg_peer_established(device, event->peer_index) != 0;
}

int tsc_wg_receive(tsc_wg *device, const void *packet, size_t length,
        void *output, size_t capacity, tsc_wg_event *event) {
    const uint8_t *bytes = packet;
    uint8_t type;
    tsc_wg_peer *peer;
    if (event) {
        memset(event, 0, sizeof(*event));
        event->peer_index = SIZE_MAX;
    }
    if (!device || !device->valid || !packet || !event || (!output && capacity))
        return TSC_ERR_ARGUMENT;
    if (length > 65507) return TSC_ERR_PROTOCOL;
    type = tsc_wgi_get_message_type(bytes, length);
    if (type == MESSAGE_HANDSHAKE_INITIATION) {
        struct message_handshake_initiation initiation;
        struct message_handshake_response response;
        if (capacity < sizeof(response)) return TSC_ERR_SPACE;
        if (!tsc_wgi_check_mac1(device, bytes, length - 32, bytes + length - 32))
            return TSC_WG_ERR_AUTH;
        memcpy(&initiation, bytes, sizeof(initiation));
        peer = tsc_wgi_process_initiation_message(device, &initiation);
        if (!peer) return TSC_WG_ERR_AUTH;
        device->random_failed = false;
        if (!tsc_wgi_create_handshake_response(device, peer, &response) || device->random_failed) {
            tsc_crypto_zero(&peer->handshake, sizeof(peer->handshake));
            tsc_crypto_zero(&response, sizeof(response));
            return device->random_failed ? TSC_WG_ERR_RANDOM : TSC_WG_ERR_AUTH;
        }
        tsc_wgi_start_session(peer, false);
        peer->active = true;
        peer->new_handshake_pending = false;
        memcpy(peer->handshake_mac1, response.mac1, 16);
        peer->handshake_mac1_valid = true;
        memcpy(output, &response, sizeof(response));
        tsc_crypto_zero(&response, sizeof(response));
        event->kind = TSC_WG_EVENT_TX;
        event->length = sizeof(response);
        event_peer(device, peer, event);
        return TSC_OK;
    }
    if (type == MESSAGE_HANDSHAKE_RESPONSE) {
        struct message_handshake_response response;
        size_t written = 0;
        int result;
        if (capacity < TSC_WG_OVERHEAD) return TSC_ERR_SPACE;
        peer = tsc_wgi_peer_lookup_by_handshake(device, U8TO32_LITTLE(bytes + 8));
        if (!peer || !tsc_wgi_check_mac1(device, bytes, length - 32, bytes + length - 32))
            return TSC_WG_ERR_AUTH;
        memcpy(&response, bytes, sizeof(response));
        if (!tsc_wgi_process_handshake_response(device, peer, &response)) return TSC_WG_ERR_AUTH;
        tsc_wgi_start_session(peer, true);
        peer->send_handshake = false;
        peer->new_handshake_pending = false;
        result = tsc_wg_encrypt(device, (size_t)(peer - device->peers), NULL, 0,
                              output, capacity, &written);
        if (result != TSC_OK) return result;
        event->kind = TSC_WG_EVENT_TX;
        event->length = written;
        event_peer(device, peer, event);
        return TSC_OK;
    }
    if (type == MESSAGE_COOKIE_REPLY) {
        struct message_cookie_reply cookie;
        peer = tsc_wgi_peer_lookup_by_handshake(device, U8TO32_LITTLE(bytes + 4));
        if (!peer) {
            peer = tsc_wgi_peer_lookup_by_receiver(device, U8TO32_LITTLE(bytes + 4));
        }
        if (!peer) return TSC_WG_ERR_AUTH;
        memcpy(&cookie, bytes, sizeof(cookie));
        if (!tsc_wgi_process_cookie_message(device, peer, &cookie)) return TSC_WG_ERR_AUTH;
        event->kind = TSC_WG_EVENT_COOKIE;
        event->peer_index = (size_t)(peer - device->peers);
        return TSC_OK;
    }
    if (type == MESSAGE_TRANSPORT_DATA) {
        tsc_wg_keypair *keypair;
        uint64_t counter = U8TO64_LITTLE(bytes + 8);
        uint32_t receiver = U8TO32_LITTLE(bytes + 4);
        size_t plaintext_length = length - TSC_WG_OVERHEAD;
        if (capacity < plaintext_length) return TSC_ERR_SPACE;
        peer = tsc_wgi_peer_lookup_by_receiver(device, receiver);
        if (!peer) return TSC_WG_ERR_AUTH;
        keypair = tsc_wgi_get_peer_keypair_for_idx(peer, receiver);
        if (!keypair || !keypair->receiving_valid) return TSC_WG_ERR_AUTH;
        if (expired(device, keypair) || counter >= REJECT_AFTER_MESSAGES) return TSC_WG_ERR_EXPIRED;
        if (!tsc_wgi_aead_decrypt(output, bytes + 16, length - 16, NULL, 0,
                                counter, keypair->receiving_key)) return TSC_WG_ERR_AUTH;
        if (!tsc_wgi_check_replay(keypair, counter)) {
            tsc_crypto_zero(output, plaintext_length);
            return TSC_WG_ERR_REPLAY;
        }
        keypair->last_rx = peer->last_rx = tsc_wgi_sys_now(device);
        peer->new_handshake_pending = false;
        if (keypair == &peer->next_keypair) peer->send_handshake = false;
        tsc_wgi_keypair_update(peer, keypair);
        peer->active = true;
        if (plaintext_length && !peer->keepalive_pending) {
            peer->keepalive_pending = true;
            peer->keepalive_due = peer->last_rx + (uint64_t)KEEPALIVE_TIMEOUT * 1000;
        }
        event->kind = plaintext_length ? TSC_WG_EVENT_RX : TSC_WG_EVENT_KEEPALIVE;
        event->length = plaintext_length;
        event_peer(device, peer, event);
        return TSC_OK;
    }
    return TSC_ERR_PROTOCOL;
}
