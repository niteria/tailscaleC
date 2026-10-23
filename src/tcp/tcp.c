#include "tailscalec/tcp.h"

#if TSC_APP_TCP

#include "lwip/init.h"
#include "lwip/ip4.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"
#include <limits.h>
#include <string.h>

/* All lwIP exports are prefixed in port/namespace.h. Its static pools are
 * process-wide, so admitting a second instance would alias live connections. */
static tsc_tcp *active_stack;
static struct netif tunnel_netif;
static int lwip_initialized;
static u8_t connection_arg_id;

/* Automatic lwIP timeout scheduling is disabled; poll drives tcp_tmr. */
void tcp_timer_needed(void) { }

static int map_error(err_t error)
{
    switch (error) {
    case ERR_OK: return TSC_OK;
    case ERR_MEM: case ERR_BUF: return TSC_ERR_SPACE;
    case ERR_TIMEOUT: return TSC_ERR_TIMEOUT;
    case ERR_WOULDBLOCK: case ERR_INPROGRESS: return TSC_AGAIN;
    case ERR_ARG: case ERR_VAL: case ERR_USE: return TSC_ERR_ARGUMENT;
    default: return TSC_ERR_IO;
    }
}

static int valid(const tsc_tcp *stack)
{
    return stack && active_stack == stack && stack->initialized && !stack->in_call;
}

static tsc_tcp_connection_storage *connection(tsc_tcp *stack, tsc_tcp_handle id)
{
    if (!valid(stack) || id == 0 || id > TSC_MAX_TCP_CONNECTIONS) return NULL;
    if (stack->connections[id - 1].state == TSC_TCP_UNUSED) return NULL;
    return &stack->connections[id - 1];
}

uint32_t tsc_tcp_random_word(void)
{
    uint32_t word = 0;
    if (!active_stack || active_stack->config.random_bytes(
            active_stack->config.user, &word, sizeof(word)) != TSC_OK) {
        if (active_stack) active_stack->rng_failed = 1;
    }
    return word;
}

static err_t output(struct netif *netif, struct pbuf *packet,
                    const ip4_addr_t *destination)
{
    tsc_tcp *stack = netif->state;
    (void)destination;
    if (!stack || stack->rng_failed || packet->tot_len > sizeof(stack->output))
        return ERR_IF;
    if (pbuf_copy_partial(packet, stack->output, packet->tot_len, 0) != packet->tot_len)
        return ERR_BUF;
    return stack->config.send_ip(stack->config.user, stack->output,
                                 packet->tot_len) == TSC_OK ? ERR_OK : ERR_IF;
}

static err_t netif_initialize(struct netif *netif)
{
    tsc_tcp *stack = netif->state;
    netif->name[0] = 't';
    netif->name[1] = 's';
    netif->mtu = stack->config.mtu;
    netif->output = output;
    netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

static void failed(void *user, err_t error)
{
    tsc_tcp_connection_storage *conn = user;
    conn->pcb = NULL; /* lwIP owns and releases this PCB around the callback. */
    if (error == ERR_CLSD && conn->state == TSC_TCP_EOF && conn->write_closed) {
        conn->error = TSC_OK;
        return;
    }
    conn->error = map_error(error);
    conn->state = TSC_TCP_FAILED;
}

static err_t received(void *user, struct tcp_pcb *pcb, struct pbuf *packet,
                       err_t error)
{
    tsc_tcp_connection_storage *conn = user;
    size_t tail, first;
    (void)pcb;
    if (!packet) {
        conn->state = TSC_TCP_EOF;
        return ERR_OK;
    }
    if (error != ERR_OK || packet->tot_len > sizeof(conn->receive) - conn->length)
        return ERR_MEM; /* lwIP keeps the pbuf and retries after window opens. */
    tail = (conn->head + conn->length) % sizeof(conn->receive);
    first = sizeof(conn->receive) - tail;
    if (first > packet->tot_len) first = packet->tot_len;
    pbuf_copy_partial(packet, conn->receive + tail, (u16_t)first, 0);
    if (first < packet->tot_len)
        pbuf_copy_partial(packet, conn->receive, (u16_t)(packet->tot_len - first),
                           (u16_t)first);
    conn->length += packet->tot_len;
    pbuf_free(packet);
    return ERR_OK;
}

static void pcb_destroyed(u8_t id, void *user)
{
    tsc_tcp_connection_storage *conn = user;
    (void)id;
    if (!conn) return;
    conn->pcb = NULL;
    if (conn->state != TSC_TCP_EOF && conn->state != TSC_TCP_FAILED &&
        conn->state != TSC_TCP_UNUSED) {
        conn->error = TSC_ERR_IO;
        conn->state = TSC_TCP_FAILED;
    }
}

static const struct tcp_ext_arg_callbacks connection_lifetime = {
    .destroy = pcb_destroyed, .passive_open = NULL
};

static void attach(tsc_tcp_connection_storage *conn, struct tcp_pcb *pcb)
{
    conn->pcb = pcb;
    tcp_ext_arg_set(pcb, connection_arg_id, conn);
    tcp_ext_arg_set_callbacks(pcb, connection_arg_id, &connection_lifetime);
    tcp_arg(pcb, conn);
    tcp_recv(pcb, received);
    tcp_err(pcb, failed);
    tcp_nagle_disable(pcb);
}

static tsc_tcp_connection_storage *allocate(tsc_tcp *stack)
{
    unsigned i;
    for (i = 0; i < TSC_MAX_TCP_CONNECTIONS; ++i) {
        tsc_tcp_connection_storage *conn = &stack->connections[i];
        if (conn->state == TSC_TCP_UNUSED) {
            memset(conn, 0, sizeof(*conn));
            conn->owner = stack;
            conn->state = TSC_TCP_CONNECTING;
            return conn;
        }
    }
    return NULL;
}

static err_t connected(void *user, struct tcp_pcb *pcb, err_t error)
{
    tsc_tcp_connection_storage *conn = user;
    (void)pcb;
    if (error != ERR_OK) {
        conn->error = map_error(error);
        conn->state = TSC_TCP_FAILED;
    } else {
        conn->state = TSC_TCP_ESTABLISHED;
    }
    return ERR_OK;
}

static err_t accepted(void *user, struct tcp_pcb *pcb, err_t error)
{
    tsc_tcp *stack = active_stack;
    tsc_tcp_handle listener = (tsc_tcp_handle)(uintptr_t)user;
    tsc_tcp_connection_storage *conn;
    if (!stack || stack->rng_failed || error != ERR_OK) {
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    conn = allocate(stack);
    if (!conn) {
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    conn->state = TSC_TCP_ESTABLISHED;
    conn->pending = 1;
    conn->listener = listener;
    conn->remote.family = TSC_AF_IPV4;
    memcpy(conn->remote.address, &ip_2_ip4(&pcb->remote_ip)->addr, 4);
    conn->remote.port = pcb->remote_port;
    attach(conn, pcb);
    tcp_backlog_delayed(pcb);
    return ERR_OK;
}

static void release(tsc_tcp_connection_storage *conn)
{
    if (conn->pcb) {
        struct tcp_pcb *pcb = conn->pcb;
        tcp_arg(pcb, NULL);
        tcp_recv(pcb, NULL);
        tcp_err(pcb, NULL);
        tcp_ext_arg_set(pcb, connection_arg_id, NULL);
        if (conn->pending) tcp_backlog_accepted(pcb);
        /* A graceful application exchange has already delivered both FINs.
         * tcp_close releases CLOSE_WAIT/LAST_ACK or waits in FIN_WAIT/TIME_WAIT.
         * Other closes deliberately abort, discarding unsent app data. */
        if (conn->state == TSC_TCP_EOF && conn->write_closed) {
            if (tcp_close(pcb) != ERR_OK) tcp_abort(pcb);
        } else {
            tcp_abort(pcb);
        }
    }
    memset(conn, 0, sizeof(*conn));
}

int tsc_tcp_init(tsc_tcp *stack, const tsc_tcp_config *config, uint64_t now_ms)
{
    tsc_tcp_config copy;
    ip4_addr_t address, mask, gateway;
    uint32_t probe;
    if (!stack || !config || !config->send_ip || !config->random_bytes ||
        config->local_ipv4[0] == 0 || config->local_ipv4[0] >= 224)
        return TSC_ERR_ARGUMENT;
    if (active_stack) return TSC_ERR_SPACE;
    copy = *config;
    if (copy.mtu == 0) copy.mtu = 1280;
    if (copy.mtu < 576 || copy.mtu > TSC_MAX_DATAGRAM_SIZE)
        return TSC_ERR_ARGUMENT;
    if (copy.random_bytes(copy.user, &probe, sizeof(probe)) != TSC_OK)
        return TSC_ERR_IO;
    memset(stack, 0, sizeof(*stack));
    stack->config = copy;
    stack->timer_ms = now_ms;
    active_stack = stack;
    if (!lwip_initialized) {
        lwip_init();
        connection_arg_id = tcp_ext_arg_alloc_id();
        lwip_initialized = 1;
    }
    memcpy(&address.addr, copy.local_ipv4, 4);
    mask.addr = 0; /* All destinations are routed through this tunnel. */
    gateway.addr = 0;
    memset(&tunnel_netif, 0, sizeof(tunnel_netif));
    if (!netif_add(&tunnel_netif, &address, &mask, &gateway, stack,
                    netif_initialize, ip4_input)) {
        active_stack = NULL;
        memset(stack, 0, sizeof(*stack));
        return TSC_ERR_IO;
    }
    netif_set_default(&tunnel_netif);
    stack->initialized = 1;
    if (stack->rng_failed) {
        tsc_tcp_destroy(stack);
        return TSC_ERR_IO;
    }
    return TSC_OK;
}

void tsc_tcp_destroy(tsc_tcp *stack)
{
    unsigned i;
    if (!valid(stack)) return;
    stack->in_call = 1;
    for (i = 0; i < TSC_MAX_TCP_CONNECTIONS; ++i) release(&stack->connections[i]);
    for (i = 0; i < TSC_MAX_TCP_LISTENERS; ++i)
        if (stack->listeners[i]) tcp_close(stack->listeners[i]);
    /* Gracefully closed PCBs can outlive application handles in TIME_WAIT. */
    while (tcp_active_pcbs) tcp_abort(tcp_active_pcbs);
    while (tcp_tw_pcbs) tcp_abort(tcp_tw_pcbs);
    while (tcp_bound_pcbs) tcp_abort(tcp_bound_pcbs);
    netif_remove(&tunnel_netif);
    active_stack = NULL;
    memset(stack, 0, sizeof(*stack));
}

int tsc_tcp_input(tsc_tcp *stack, const void *ipv4, size_t length)
{
    const uint8_t *bytes = ipv4;
    struct pbuf *packet;
    size_t header, declared;
    err_t result;
    if (!valid(stack) || !ipv4) return TSC_ERR_ARGUMENT;
    if (stack->rng_failed) return TSC_ERR_IO;
    if (length < 40 || length > TSC_MAX_DATAGRAM_SIZE) return TSC_ERR_PROTOCOL;
    header = (size_t)(bytes[0] & 15) * 4;
    declared = (size_t)bytes[2] * 256 + bytes[3];
    if ((bytes[0] >> 4) != 4 || header < 20 || header + 20 > length ||
        declared != length || bytes[9] != 6 || (bytes[6] & 0x3f) || bytes[7] ||
        memcmp(bytes + 16, stack->config.local_ipv4, 4) != 0)
        return TSC_ERR_PROTOCOL;
    packet = pbuf_alloc(PBUF_RAW, (u16_t)length, PBUF_POOL);
    if (!packet) return TSC_ERR_SPACE;
    if (pbuf_take(packet, ipv4, (u16_t)length) != ERR_OK) {
        pbuf_free(packet);
        return TSC_ERR_SPACE;
    }
    stack->in_call = 1;
    result = ip4_input(packet, &tunnel_netif); /* Always consumes packet. */
    stack->in_call = 0;
    return stack->rng_failed ? TSC_ERR_IO : map_error(result);
}

int tsc_tcp_poll(tsc_tcp *stack, uint64_t now_ms)
{
    uint64_t ticks, i;
    if (!valid(stack)) return TSC_ERR_ARGUMENT;
    if (stack->rng_failed) return TSC_ERR_IO;
    if (now_ms < stack->timer_ms) return TSC_ERR_ARGUMENT;
    ticks = (now_ms - stack->timer_ms) / TCP_TMR_INTERVAL;
    /* Avoid a huge event-loop stall after suspend/time discontinuities. Long
     * delays expire connections over subsequent calls, never busy loop. */
    if (ticks > 256) ticks = 256;
    stack->in_call = 1;
    for (i = 0; i < ticks; ++i) tcp_tmr();
    stack->timer_ms += ticks * TCP_TMR_INTERVAL;
    stack->in_call = 0;
    return stack->rng_failed ? TSC_ERR_IO : TSC_OK;
}

int tsc_tcp_listen(tsc_tcp *stack, uint16_t port, tsc_tcp_handle *listener)
{
    struct tcp_pcb *pcb, *listening;
    ip_addr_t address;
    err_t result;
    unsigned i;
    if (listener) *listener = 0;
    if (!valid(stack) || !listener || port == 0) return TSC_ERR_ARGUMENT;
    if (stack->rng_failed) return TSC_ERR_IO;
    for (i = 0; i < TSC_MAX_TCP_LISTENERS; ++i) if (!stack->listeners[i]) break;
    if (i == TSC_MAX_TCP_LISTENERS) return TSC_ERR_SPACE;
    stack->in_call = 1;
    pcb = tcp_new();
    if (!pcb) { stack->in_call = 0; return TSC_ERR_SPACE; }
    ip_addr_copy_from_ip4(address, *netif_ip4_addr(&tunnel_netif));
    result = tcp_bind(pcb, &address, port);
    if (result != ERR_OK) {
        tcp_abort(pcb);
        stack->in_call = 0;
        return map_error(result);
    }
    listening = tcp_listen_with_backlog_and_err(pcb, TSC_MAX_TCP_CONNECTIONS,
                                                &result);
    if (!listening) {
        tcp_abort(pcb);
        stack->in_call = 0;
        return map_error(result);
    }
    stack->listeners[i] = listening;
    tcp_arg(listening, (void *)(uintptr_t)(i + 1));
    tcp_accept(listening, accepted);
    *listener = i + 1;
    stack->in_call = 0;
    return TSC_OK;
}

int tsc_tcp_unlisten(tsc_tcp *stack, tsc_tcp_handle listener)
{
    unsigned i;
    if (!valid(stack) || listener == 0 || listener > TSC_MAX_TCP_LISTENERS ||
        !stack->listeners[listener - 1]) return TSC_ERR_ARGUMENT;
    stack->in_call = 1;
    for (i = 0; i < TSC_MAX_TCP_CONNECTIONS; ++i)
        if (stack->connections[i].pending && stack->connections[i].listener == listener)
            release(&stack->connections[i]);
    tcp_close(stack->listeners[listener - 1]);
    stack->listeners[listener - 1] = NULL;
    stack->in_call = 0;
    return TSC_OK;
}

int tsc_tcp_accept(tsc_tcp *stack, tsc_tcp_handle listener,
                   tsc_tcp_handle *id, tsc_endpoint *remote)
{
    unsigned i;
    if (id) *id = 0;
    if (!valid(stack) || !id || listener == 0 || listener > TSC_MAX_TCP_LISTENERS ||
        !stack->listeners[listener - 1]) return TSC_ERR_ARGUMENT;
    for (i = 0; i < TSC_MAX_TCP_CONNECTIONS; ++i) {
        tsc_tcp_connection_storage *conn = &stack->connections[i];
        if (!conn->pending || conn->listener != listener) continue;
        if (conn->state == TSC_TCP_FAILED) { release(conn); continue; }
        conn->pending = 0;
        if (conn->pcb) tcp_backlog_accepted(conn->pcb);
        *id = i + 1;
        if (remote) *remote = conn->remote;
        return TSC_OK;
    }
    return TSC_AGAIN;
}

int tsc_tcp_connect(tsc_tcp *stack, const tsc_endpoint *remote,
                    uint16_t local_port, tsc_tcp_handle *id)
{
    tsc_tcp_connection_storage *conn;
    struct tcp_pcb *pcb;
    ip_addr_t address;
    err_t result;
    if (id) *id = 0;
    if (!valid(stack) || !remote || !id || remote->family != TSC_AF_IPV4 ||
        remote->port == 0 || remote->address[0] == 0 || remote->address[0] >= 224)
        return TSC_ERR_ARGUMENT;
    if (stack->rng_failed) return TSC_ERR_IO;
    conn = allocate(stack);
    if (!conn) return TSC_ERR_SPACE;
    stack->in_call = 1;
    pcb = tcp_new();
    if (!pcb) {
        memset(conn, 0, sizeof(*conn));
        stack->in_call = 0;
        return TSC_ERR_SPACE;
    }
    conn->remote = *remote;
    attach(conn, pcb);
    ip_addr_copy_from_ip4(address, *netif_ip4_addr(&tunnel_netif));
    result = tcp_bind(pcb, &address, local_port);
    if (result == ERR_OK) {
        memcpy(&ip_2_ip4(&address)->addr, remote->address, 4);
        result = tcp_connect(pcb, &address, remote->port, connected);
    }
    if (result != ERR_OK || stack->rng_failed) {
        release(conn);
        stack->in_call = 0;
        return stack->rng_failed ? TSC_ERR_IO : map_error(result);
    }
    *id = (tsc_tcp_handle)(conn - stack->connections) + 1;
    stack->in_call = 0;
    return TSC_OK;
}

int tsc_tcp_get_state(tsc_tcp *stack, tsc_tcp_handle id, tsc_tcp_state *state)
{
    tsc_tcp_connection_storage *conn = connection(stack, id);
    if (!conn || !state) return TSC_ERR_ARGUMENT;
    *state = (tsc_tcp_state)conn->state;
    return TSC_OK;
}

int tsc_tcp_send(tsc_tcp *stack, tsc_tcp_handle id,
                 const void *data, size_t length, size_t *sent)
{
    tsc_tcp_connection_storage *conn = connection(stack, id);
    size_t amount;
    err_t result;
    if (sent) *sent = 0;
    if (!conn || !sent || (!data && length)) return TSC_ERR_ARGUMENT;
    if (stack->rng_failed) return TSC_ERR_IO;
    if (conn->state == TSC_TCP_FAILED) return conn->error;
    if (conn->state == TSC_TCP_CONNECTING) return TSC_AGAIN;
    if (!conn->pcb || conn->write_closed) return TSC_ERR_IO;
    if (length == 0) return TSC_OK;
    amount = tcp_sndbuf((struct tcp_pcb *)conn->pcb);
    if (amount > length) amount = length;
    if (amount > UINT16_MAX) amount = UINT16_MAX;
    if (!amount) return TSC_AGAIN;
    stack->in_call = 1;
    result = tcp_write(conn->pcb, data, (u16_t)amount, TCP_WRITE_FLAG_COPY);
    if (result == ERR_OK) {
        *sent = amount;
        /* A transient transport failure leaves bytes queued for retransmit. */
        (void)tcp_output(conn->pcb);
    }
    stack->in_call = 0;
    return result == ERR_MEM ? TSC_AGAIN : map_error(result);
}

int tsc_tcp_receive(tsc_tcp *stack, tsc_tcp_handle id,
                    void *data, size_t capacity, size_t *received_length)
{
    tsc_tcp_connection_storage *conn = connection(stack, id);
    size_t amount, first;
    if (received_length) *received_length = 0;
    if (!conn || !received_length || (!data && capacity)) return TSC_ERR_ARGUMENT;
    if (capacity == 0) return TSC_ERR_ARGUMENT;
    if (conn->length == 0) {
        if (conn->state == TSC_TCP_EOF) return TSC_OK;
        if (conn->state == TSC_TCP_FAILED) return conn->error;
        return TSC_AGAIN;
    }
    amount = conn->length < capacity ? conn->length : capacity;
    first = sizeof(conn->receive) - conn->head;
    if (first > amount) first = amount;
    memcpy(data, conn->receive + conn->head, first);
    if (first < amount) memcpy((uint8_t *)data + first, conn->receive, amount - first);
    conn->head = (conn->head + amount) % sizeof(conn->receive);
    conn->length -= amount;
    stack->in_call = 1;
    if (conn->pcb) tcp_recved(conn->pcb, (u16_t)amount);
    stack->in_call = 0;
    *received_length = amount;
    return TSC_OK;
}

int tsc_tcp_shutdown(tsc_tcp *stack, tsc_tcp_handle id)
{
    tsc_tcp_connection_storage *conn = connection(stack, id);
    err_t result;
    if (!conn) return TSC_ERR_ARGUMENT;
    if (stack->rng_failed) return TSC_ERR_IO;
    if (conn->state == TSC_TCP_FAILED) return conn->error;
    if (conn->state == TSC_TCP_CONNECTING) return TSC_AGAIN;
    if (conn->write_closed) return TSC_OK;
    if (!conn->pcb) return TSC_ERR_IO;
    stack->in_call = 1;
    result = tcp_shutdown(conn->pcb, 0, 1);
    if (result == ERR_OK) conn->write_closed = 1;
    stack->in_call = 0;
    return result == ERR_MEM ? TSC_AGAIN : map_error(result);
}

int tsc_tcp_close(tsc_tcp *stack, tsc_tcp_handle id)
{
    tsc_tcp_connection_storage *conn = connection(stack, id);
    if (!conn) return TSC_ERR_ARGUMENT;
    stack->in_call = 1;
    release(conn);
    stack->in_call = 0;
    return TSC_OK;
}

#endif /* TSC_APP_TCP */
