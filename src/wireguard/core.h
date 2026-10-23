/*
 * Copyright (c) 2021 Daniel Hope (www.floorsense.nz)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 * 3. Neither the name of "Floorsense Ltd", "Agile Workspace Ltd" nor the names of
 *  its contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Daniel Hope <daniel.hope@smartalock.com>
 */

#ifndef TSC_WG_CORE_H
#define TSC_WG_CORE_H
#include "tailscalec/wireguard.h"
// tai64n contains 64-bit seconds and 32-bit nano offset (12 bytes)
#define WIREGUARD_TAI64N_LEN		(12)
// Auth algorithm is chacha20pol1305 which is 128bit (16 byte) authenticator
#define WIREGUARD_AUTHTAG_LEN		(16)
// Hash algorithm is blake2s which makes 32 byte hashes
#define WIREGUARD_HASH_LEN			(32)
// Public key algo is curve22519 which uses 32 byte keys
#define WIREGUARD_PUBLIC_KEY_LEN	(32)
// Public key algo is curve22519 which uses 32 byte keys
#define WIREGUARD_PRIVATE_KEY_LEN	(32)
// Symmetric session keys are chacha20/poly1305 which uses 32 byte keys
#define WIREGUARD_SESSION_KEY_LEN	(32)

// Timers / Limits
#define WIREGUARD_COOKIE_LEN		(16)
#define COOKIE_SECRET_MAX_AGE		(2 * 60)
#define COOKIE_NONCE_LEN			(24)

#define REKEY_AFTER_MESSAGES		(1ULL << 60)
#define REJECT_AFTER_MESSAGES		(0xFFFFFFFFFFFFFFFFULL - (1ULL << 13))
#define REKEY_AFTER_TIME			(120)
#define REJECT_AFTER_TIME			(180)
#define REKEY_TIMEOUT				(5)
#define KEEPALIVE_TIMEOUT			(10)

#define MESSAGE_INVALID					0
#define MESSAGE_HANDSHAKE_INITIATION	1
#define MESSAGE_HANDSHAKE_RESPONSE		2
#define MESSAGE_COOKIE_REPLY			3
#define MESSAGE_TRANSPORT_DATA			4


// 5.4.2 First Message: Initiator to Responder
struct message_handshake_initiation {
	uint8_t type;
	uint8_t reserved[3];
	uint8_t sender[4];
	uint8_t ephemeral[32];
	uint8_t enc_static[32 + WIREGUARD_AUTHTAG_LEN];
	uint8_t enc_timestamp[WIREGUARD_TAI64N_LEN + WIREGUARD_AUTHTAG_LEN];
	uint8_t mac1[WIREGUARD_COOKIE_LEN];
	uint8_t mac2[WIREGUARD_COOKIE_LEN];
};

// 5.4.3 Second Message: Responder to Initiator
struct message_handshake_response {
	uint8_t type;
	uint8_t reserved[3];
	uint8_t sender[4];
	uint8_t receiver[4];
	uint8_t ephemeral[32];
	uint8_t enc_empty[0 + WIREGUARD_AUTHTAG_LEN];
	uint8_t mac1[WIREGUARD_COOKIE_LEN];
	uint8_t mac2[WIREGUARD_COOKIE_LEN];
};

// 5.4.7 Under Load: Cookie Reply Message
struct message_cookie_reply {
	uint8_t type;
	uint8_t reserved[3];
	uint8_t receiver[4];
	uint8_t nonce[COOKIE_NONCE_LEN];
	uint8_t enc_cookie[WIREGUARD_COOKIE_LEN + WIREGUARD_AUTHTAG_LEN];
};

// 5.4.6 Subsequent Messages: Transport Data Messages
struct message_transport_data {
	uint8_t type;
	uint8_t reserved[3];
	uint8_t receiver[4];
	uint8_t counter[8];
	// Followed by encrypted data
	uint8_t enc_packet[];
};

// Initialise the WireGuard system - need to call this before anything else
void tsc_wgi_init(struct tsc_wg *device);
bool tsc_wgi_device_init(struct tsc_wg *device, const uint8_t *private_key);
bool tsc_wgi_peer_init(struct tsc_wg *device, struct tsc_wg_peer *peer, const uint8_t *public_key, const uint8_t *preshared_key);

struct tsc_wg_peer *tsc_wgi_peer_alloc(struct tsc_wg *device);
size_t tsc_wgi_peer_index(struct tsc_wg *device, struct tsc_wg_peer *peer);
struct tsc_wg_peer *tsc_wgi_peer_lookup_by_pubkey(struct tsc_wg *device, uint8_t *public_key);
struct tsc_wg_peer *tsc_wgi_peer_lookup_by_peer_index(struct tsc_wg *device, size_t peer_index);
struct tsc_wg_peer *tsc_wgi_peer_lookup_by_receiver(struct tsc_wg *device, uint32_t receiver);
struct tsc_wg_peer *tsc_wgi_peer_lookup_by_handshake(struct tsc_wg *device, uint32_t receiver);

void tsc_wgi_start_session(struct tsc_wg_peer *peer, bool initiator);

void tsc_wgi_keypair_update(struct tsc_wg_peer *peer, struct tsc_wg_keypair *received_keypair);
void tsc_wgi_keypair_destroy(struct tsc_wg_keypair *keypair);

struct tsc_wg_keypair *tsc_wgi_get_peer_keypair_for_idx(struct tsc_wg_peer *peer, uint32_t idx);
bool tsc_wgi_check_replay(struct tsc_wg_keypair *keypair, uint64_t seq);

uint8_t tsc_wgi_get_message_type(const uint8_t *data, size_t len);

struct tsc_wg_peer *tsc_wgi_process_initiation_message(struct tsc_wg *device, struct message_handshake_initiation *msg);
bool tsc_wgi_process_handshake_response(struct tsc_wg *device, struct tsc_wg_peer *peer, struct message_handshake_response *src);
bool tsc_wgi_process_cookie_message(struct tsc_wg *device, struct tsc_wg_peer *peer, struct message_cookie_reply *src);

bool tsc_wgi_create_handshake_initiation(struct tsc_wg *device, struct tsc_wg_peer *peer, struct message_handshake_initiation *dst);
bool tsc_wgi_create_handshake_response(struct tsc_wg *device, struct tsc_wg_peer *peer, struct message_handshake_response *dst);
void tsc_wgi_create_cookie_reply(struct tsc_wg *device, struct message_cookie_reply *dst, const uint8_t *mac1, uint32_t index, uint8_t *source_addr_port, size_t source_length);


bool tsc_wgi_check_mac1(struct tsc_wg *device, const uint8_t *data, size_t len, const uint8_t *mac1);
bool tsc_wgi_check_mac2(struct tsc_wg *device, const uint8_t *data, size_t len, uint8_t *source_addr_port, size_t source_length, const uint8_t *mac2);

bool tsc_wgi_expired(struct tsc_wg *device, uint64_t created_millis, uint32_t valid_seconds);

void tsc_wgi_encrypt_packet(uint8_t *dst, const uint8_t *src, size_t src_len, struct tsc_wg_keypair *keypair);
bool tsc_wgi_decrypt_packet(uint8_t *dst, const uint8_t *src, size_t src_len, uint64_t counter, struct tsc_wg_keypair *keypair);


uint64_t tsc_wgi_sys_now(struct tsc_wg *device);
void tsc_wgi_random_bytes(struct tsc_wg *device, void *bytes, size_t length);
void tsc_wgi_tai64n_now(struct tsc_wg *device, uint8_t output[12]);
#endif
