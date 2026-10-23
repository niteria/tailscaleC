#ifndef TSC_LWIPOPTS_H
#define TSC_LWIPOPTS_H

#include "tailscalec/config.h"
#include "namespace.h"

#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_TIMERS 0
#define LWIP_TCP 1
#define LWIP_TCP_PCB_NUM_EXT_ARGS 1
#define LWIP_UDP 0
#define LWIP_UDPLITE 0
#define LWIP_RAW 0
#define LWIP_IPV4 1
#define LWIP_IPV6 0
#define LWIP_ICMP 0
#define LWIP_IGMP 0
#define LWIP_DNS 0
#define LWIP_DHCP 0
#define LWIP_AUTOIP 0
#define LWIP_ARP 0
#define LWIP_ETHERNET 0
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define LWIP_ALTCP 0
#define LWIP_STATS 0
#define LWIP_NETIF_HOSTNAME 0
#define LWIP_NETIF_API 0
#define LWIP_NETIF_LOOPBACK 0
#define LWIP_MULTICAST_TX_OPTIONS 0
#define LWIP_RANDOMIZE_INITIAL_LOCAL_PORTS 1
#define LWIP_TCP_TIMESTAMPS 0
#define LWIP_TCP_SACK_OUT 1
#define TCP_QUEUE_OOSEQ 1
#define TCP_OOSEQ_MAX_BYTES TSC_TCP_RECEIVE_BUFFER
#define TCP_OOSEQ_MAX_PBUFS 2
#define TCP_LISTEN_BACKLOG 1
#define TCP_DEFAULT_LISTEN_BACKLOG TSC_MAX_TCP_CONNECTIONS
#define TCP_MSS TSC_TCP_MSS
#define TCP_WND TSC_TCP_RECEIVE_BUFFER
#define TCP_SND_BUF TSC_TCP_SEND_BUFFER
#define TCP_SND_QUEUELEN ((4 * TCP_SND_BUF + TCP_MSS - 1) / TCP_MSS)
#define TCP_OVERSIZE 0
#define LWIP_WND_SCALE 0
#define IP_FORWARD 0
#define IP_REASSEMBLY 0
#define IP_FRAG 0
#define MEM_ALIGNMENT 8
#define MEM_SIZE (TSC_MAX_TCP_CONNECTIONS * (TSC_TCP_SEND_BUFFER + 1024) + 4096)
#define MEM_LIBC_MALLOC 0
#define MEMP_MEM_MALLOC 0
#define MEMP_NUM_TCP_PCB (2 * TSC_MAX_TCP_CONNECTIONS)
#define MEMP_NUM_TCP_PCB_LISTEN TSC_MAX_TCP_LISTENERS
#define MEMP_NUM_TCP_SEG (TSC_MAX_TCP_CONNECTIONS * (TCP_SND_QUEUELEN + 3))
#define MEMP_NUM_PBUF (2 * TSC_MAX_TCP_CONNECTIONS + 4)
/* Keep room for a complete advertised window as well as per-flow packets.
 * The 80-byte allowance covers the lwIP link/IP/transport header reserve. */
#define PBUF_POOL_SIZE (2 * TSC_MAX_TCP_CONNECTIONS + 4 + \
    (TSC_TCP_RECEIVE_BUFFER + TSC_MAX_DATAGRAM_SIZE - 81) / \
    (TSC_MAX_DATAGRAM_SIZE - 80))
#define PBUF_POOL_BUFSIZE TSC_MAX_DATAGRAM_SIZE
#define LWIP_CHECKSUM_ON_COPY 1
#define CHECKSUM_GEN_IP 1
#define CHECKSUM_GEN_TCP 1
#define CHECKSUM_CHECK_IP 1
#define CHECKSUM_CHECK_TCP 1
#define LWIP_NOASSERT_ON_ERROR 0

/* This stack is intentionally independent of an ESP-IDF/system lwIP. */
#define LWIP_HOOK_FILENAME "hooks.h"
#define LWIP_HOOK_TCP_ISN(local, lp, remote, rp) tsc_tcp_random_word()
#define LWIP_RAND() tsc_tcp_random_word()

#endif
