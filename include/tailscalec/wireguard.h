#ifndef TAILSCALEC_WIREGUARD_H
#define TAILSCALEC_WIREGUARD_H

#include "tailscalec/tsc.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TSC_WG_KEY_SIZE 32u
#define TSC_WG_INITIATION_SIZE 148u
#define TSC_WG_RESPONSE_SIZE 92u
#define TSC_WG_OVERHEAD 32u
#define TSC_WG_REPLAY_BITS 64u

enum {
    TSC_WG_ERR_AUTH = -20,
    TSC_WG_ERR_REPLAY = -21,
    TSC_WG_ERR_EXPIRED = -22,
    TSC_WG_ERR_RANDOM = -23
};

/* The caller serializes access to each device and owns every object/buffer.
 * The engine makes no heap allocations. The selected crypto provider may
 * allocate temporary workspaces. No networking stack or operating system is
 * needed in the engine; time and entropy come exclusively from these hooks.
 * tai64n_now must produce a strictly increasing, big-endian TAI64N timestamp
 * across restarts (normally UTC seconds + 0x400000000000000a, nanoseconds).
 * A persisted monotonic counter is also suitable. Never use a boot-only clock.
 * Every hook is required. random_bytes must use a cryptographic RNG. */
typedef struct {
    void *user;
    int (*random_bytes)(void *user, void *buffer, size_t length);
    uint64_t (*monotonic_ms)(void *user);
    int (*tai64n_now)(void *user, uint8_t timestamp[12]);
} tsc_wg_hooks;

typedef struct tsc_wg_keypair {
    bool valid, initiator;
    uint64_t keypair_millis;
    uint8_t sending_key[32];
    bool sending_valid;
    uint64_t sending_counter;
    uint8_t receiving_key[32];
    bool receiving_valid;
    uint64_t last_tx, last_rx;
    uint64_t replay_bitmap, replay_counter;
    uint32_t local_index, remote_index;
} tsc_wg_keypair;

typedef struct tsc_wg_handshake {
    bool valid, initiator;
    uint32_t local_index, remote_index;
    uint8_t ephemeral_private[32], remote_ephemeral[32];
    uint8_t hash[32], chaining_key[32];
} tsc_wg_handshake;

struct tsc_wg;
typedef struct tsc_wg_peer {
    bool valid, active;
    uint16_t keepalive_interval;
    uint16_t retry_interval_ms;
    uint8_t public_key[32], preshared_key[32], public_key_dh[32];
    tsc_wg_keypair curr_keypair, prev_keypair, next_keypair;
    uint8_t greatest_timestamp[12];
    tsc_wg_handshake handshake;
    uint64_t cookie_millis;
    uint8_t cookie[16];
    bool cookie_valid, handshake_mac1_valid;
    uint8_t handshake_mac1[16];
    uint8_t label_cookie_key[32], label_mac1_key[32];
    uint64_t last_initiation_rx, last_initiation_tx, last_tx, last_rx;
    bool initiation_received, initiation_sent, send_handshake, keepalive_pending;
    uint64_t keepalive_due;
    bool new_handshake_pending;
    uint64_t new_handshake_due;
    uint64_t handshake_started;
    struct tsc_wg *device;
} tsc_wg_peer;

typedef struct tsc_wg {
    uint8_t public_key[32], private_key[32];
    uint8_t cookie_secret[32];
    uint64_t cookie_secret_millis;
    uint8_t label_cookie_key[32], label_mac1_key[32];
    uint8_t construction_hash[32], identifier_hash[32];
    tsc_wg_peer *peers;
    size_t peer_capacity;
    tsc_wg_hooks hooks;
    uint8_t last_timestamp[12];
    bool valid, random_failed, timestamp_failed;
} tsc_wg;

typedef enum {
    TSC_WG_EVENT_NONE = 0,
    TSC_WG_EVENT_TX = 1,
    TSC_WG_EVENT_RX = 2,
    TSC_WG_EVENT_KEEPALIVE = 3,
    TSC_WG_EVENT_COOKIE = 4
} tsc_wg_event_kind;

typedef struct {
    tsc_wg_event_kind kind;
    size_t peer_index;
    size_t length;
    bool authenticated;
    bool established;
} tsc_wg_event;

int tsc_wg_init(tsc_wg *device, tsc_wg_peer *peers, size_t peer_capacity,
                const uint8_t private_key[32], const tsc_wg_hooks *hooks);
void tsc_wg_destroy(tsc_wg *device);
/* Setting an unchanged key preserves the session. Changing/removing a key
 * securely discards all session state. A NULL preshared_key means all zeros. */
int tsc_wg_peer_set(tsc_wg *device, size_t peer_index,
                    const uint8_t public_key[32], const uint8_t preshared_key[32]);
int tsc_wg_peer_remove(tsc_wg *device, size_t peer_index);
int tsc_wg_peer_established(const tsc_wg *device, size_t peer_index);

/* These functions write one packet, or return TSC_AGAIN with *written = 0.
 * Start marks the peer active; tick retries handshakes after 5s plus up to
 * 333ms of random jitter to break synchronized crossed initiations,
 * rekeys active sessions, sends configured persistent keepalives and sends a
 * silent peer an authenticated keepalive 10s after receiving transport data.
 * Sending data without an authenticated reply for 15s starts a new handshake.
 * Stop retries after 90s without success; an explicit start restarts them.
 * Transport payloads are padded to a multiple of 16 bytes. */
int tsc_wg_start(tsc_wg *device, size_t peer_index, void *output,
                 size_t capacity, size_t *written);
int tsc_wg_tick(tsc_wg *device, size_t peer_index, void *output,
                size_t capacity, size_t *written);
int tsc_wg_encrypt(tsc_wg *device, size_t peer_index,
                   const void *plaintext, size_t length, void *output,
                   size_t capacity, size_t *written);

/* A receive produces either a response packet (TX), an authenticated inner
 * packet (RX), KEEPALIVE, or COOKIE. RX length includes zero padding: use
 * the inner IP header's length to trim it. Only authenticated events identify
 * a peer safe for endpoint rebinding. COOKIE is not peer authentication.
 * Invalid packets never update replay windows or report plaintext.
 * Input and output must not overlap. Capacity >= max(148, packet length)
 * always suffices. The embedding application MUST check inner source IPs
 * against the authenticated peer's allowed addresses before delivering RX. */
int tsc_wg_receive(tsc_wg *device, const void *packet, size_t length,
                   void *output, size_t capacity, tsc_wg_event *event);

#ifdef __cplusplus
}
#endif
#endif
