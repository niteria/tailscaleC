#ifndef TAILSCALEC_STREAM_H
#define TAILSCALEC_STREAM_H

#include "tailscalec/tsc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Single-owner TCP stream. The implementation and TLS library allocate memory;
 * application packet limits do not bound the TLS library's heap usage. Initialize
 * before use, do not copy a connected stream, and close before reconnecting. */
typedef struct {
    void *implementation;
} tsc_stream;

#define TSC_STREAM_INITIALIZER { NULL }

typedef struct {
    uint32_t timeout_ms;  /* 1..INT_MAX: total TCP and TLS connection deadline. */
    int use_tls;         /* 0 = plaintext TCP; 1 = authenticated TLS. */
    const char *ca_pem;  /* Optional explicit trust roots, PEM certificate(s). */
    size_t ca_pem_length; /* Bytes excluding or including a final NUL. */
} tsc_stream_options;

/* TLS always checks the certificate chain AND the requested host/IP identity.
 * With no explicit CA, POSIX uses OpenSSL's system trust paths; ESP-IDF uses its
 * certificate bundle if enabled, otherwise TLS fails closed. ESP32 needs a
 * correct wall clock before verifying certificates.
 *
 * Hostname resolution uses the platform's blocking resolver and is outside the
 * connection timeout. Use connect_address with a previously resolved endpoint
 * when the application requires a strict deadline including name resolution. */
int tsc_stream_connect(tsc_stream *stream, const char *host, uint16_t port,
                       const tsc_stream_options *options);
int tsc_stream_connect_address(tsc_stream *stream, const tsc_endpoint *address,
                               const char *tls_server_name,
                               const tsc_stream_options *options);

/* A successful call may transfer fewer bytes than requested. TSC_OK with zero
 * received bytes means orderly EOF (or a zero-capacity request). A timeout with
 * no transferred bytes returns TSC_ERR_TIMEOUT. timeout_ms may be zero to only
 * attempt currently available progress; values above INT_MAX are invalid.
 * On failure the count is zero. TLS read/write share the stream and must not be
 * called concurrently. A caller retrying a TLS write after a timeout must use
 * the same bytes and length until it succeeds, or close the stream. */
int tsc_stream_read(tsc_stream *stream, void *buffer, size_t capacity,
                    size_t *received, uint32_t timeout_ms);
int tsc_stream_write(tsc_stream *stream, const void *buffer, size_t length,
                     size_t *written, uint32_t timeout_ms);
/* Best-effort nonblocking TLS close_notify, then release all owned resources. */
void tsc_stream_close(tsc_stream *stream);

#ifdef __cplusplus
}
#endif
#endif
