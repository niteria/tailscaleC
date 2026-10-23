#include "check.h"
#include "tailscalec/disco.h"
#include "tailscalec/nacl.h"
#include "tailscalec/crypto.h"
#include <string.h>

#if TSC_ENABLE_DISCO
#define OUT_CAP (TSC_MAX_PEER_ENDPOINTS + 4)
typedef struct {
    uint8_t packet[TSC_MAX_DATAGRAM_SIZE];
    size_t length;
    tsc_endpoint destination;
    uint8_t node[32];
    int relay;
} captured;
typedef struct {
    tsc_disco disco;
    uint64_t now, rng;
    tsc_endpoint local, path, observed;
    uint8_t node[32];
    captured out[OUT_CAP];
    size_t count, paths, observations;
    uint32_t rtt;
    int send_status, random_status;
} actor;
static actor a, b;
static uint64_t now_ms(void *user) { return ((actor *)user)->now; }
static int random_bytes(void *user, void *out, size_t n) {
    actor *f=user;
    if (f->random_status) return f->random_status;
    uint8_t *p=out;
    for (size_t i=0;i<n;++i) {
        f->rng^=f->rng<<13; f->rng^=f->rng>>7; f->rng^=f->rng<<17;
        p[i]=(uint8_t)f->rng;
    }
    return TSC_OK;
}
static int udp_send(void *user, const tsc_endpoint *to, const void *packet, size_t n) {
    actor *f=user;
    if (f->send_status) return f->send_status;
    CHECK(f->count<OUT_CAP && n<=TSC_MAX_DATAGRAM_SIZE);
    captured *c=&f->out[f->count++]; memset(c,0,sizeof(*c));
    memcpy(c->packet,packet,n); c->length=n; c->destination=*to;
    return TSC_OK;
}
static int relay_send(void *user, const uint8_t node[32], const void *packet, size_t n) {
    actor *f=user;
    tsc_endpoint empty={0};
    int status=udp_send(user,&empty,packet,n);
    if (status==TSC_OK) { f->out[f->count-1].relay=1; memcpy(f->out[f->count-1].node,node,32); }
    return status;
}
static void path_changed(void *user, const uint8_t node[32], const tsc_endpoint *ep, uint32_t rtt) {
    actor *f=user; CHECK(memcmp(node,f->node,32));
    f->path=*ep; f->rtt=rtt; ++f->paths;
}
static void observed(void *user, const tsc_endpoint *ep) {
    actor *f=user; f->observed=*ep; ++f->observations;
}
static tsc_endpoint endpoint(uint8_t last, uint16_t port) {
    tsc_endpoint ep={TSC_AF_IPV4,{127,0,0,0},port,0}; ep.address[3]=last; return ep;
}
static void initialize(actor *f, uint8_t seed) {
    uint8_t priv[32], node_priv[32];
    memset(f,0,sizeof(*f)); f->now=1000; f->rng=seed;
    memset(priv,seed,32); memset(node_priv,seed+12,32);
    CHECK(tsc_crypto_x25519_public(f->node,node_priv)==TSC_OK);
    f->local=endpoint(seed,(uint16_t)(10000+seed));
    tsc_platform platform={f,udp_send,NULL,now_ms,random_bytes};
    tsc_disco_callbacks callbacks={f,relay_send,path_changed,observed};
    CHECK(tsc_disco_init(&f->disco,&platform,&callbacks,priv,f->node)==TSC_OK);
}
static void fixture(void) {
    initialize(&a,1); initialize(&b,2);
    CHECK(tsc_disco_set_peer(&a.disco,b.node,b.disco.public_key,&b.local,1)==TSC_OK);
    CHECK(tsc_disco_set_peer(&b.disco,a.node,a.disco.public_key,&a.local,1)==TSC_OK);
}
static int receive(actor *to, const actor *from, const captured *c) {
    return c->relay ? tsc_disco_receive_relay(&to->disco,from->node,c->packet,c->length) :
        tsc_disco_receive(&to->disco,&from->local,c->packet,c->length);
}
static void direct_and_attacks(void) {
    fixture();
    a.disco.callbacks.relay_send=NULL;
    tsc_endpoint selected;
    CHECK(tsc_disco_endpoint(&a.disco,b.node,&selected)==TSC_AGAIN);
    CHECK(tsc_disco_probe(&a.disco,b.node,0)==TSC_OK && a.count==1);
    CHECK(a.out[0].length==124 && tsc_disco_is_packet(a.out[0].packet,a.out[0].length));
    CHECK(!tsc_disco_is_packet(a.out[0].packet,61));
    CHECK(receive(&b,&a,&a.out[0])==TSC_OK && b.count==1);
    CHECK(b.paths==0); /* Pings alone are not proof of a return path. */
    captured pong=b.out[0];
    a.now+=17;
    /* A captured direct response cannot be replayed through DERP or from an
     * endpoint that was not probed. Neither attempt consumes its transaction. */
    CHECK(tsc_disco_receive_relay(&a.disco,b.node,pong.packet,pong.length)==TSC_AGAIN);
    tsc_endpoint spoof=endpoint(9,9999);
    CHECK(tsc_disco_receive(&a.disco,&spoof,pong.packet,pong.length)==TSC_AGAIN);
    uint8_t saved=pong.packet[pong.length-1]; pong.packet[pong.length-1]^=1;
    CHECK(tsc_disco_receive(&a.disco,&b.local,pong.packet,pong.length)==TSC_ERR_PROTOCOL);
    pong.packet[pong.length-1]=saved;
    CHECK(receive(&a,&b,&pong)==TSC_OK);
    CHECK(a.paths==1 && a.rtt==17 && a.observations==1);
    CHECK(tsc_endpoint_equal(&a.path,&b.local));
    CHECK(tsc_endpoint_equal(&a.observed,&a.local));
    CHECK(tsc_disco_endpoint(&a.disco,b.node,&selected)==TSC_OK);
    CHECK(tsc_endpoint_equal(&selected,&b.local));
    uint64_t trust=a.disco.peers[0].trusted_until_ms;
    a.now+=100;
    CHECK(receive(&a,&b,&pong)==TSC_AGAIN);
    CHECK(a.disco.peers[0].trusted_until_ms==trust);
    a.now=trust;
    CHECK(tsc_disco_endpoint(&a.disco,b.node,&selected)==TSC_AGAIN);
    CHECK(tsc_disco_tick(&a.disco)==TSC_OK);
    CHECK(a.count==2);
    a.now+=5000;
    CHECK(receive(&b,&a,&a.out[1])==TSC_OK);
    CHECK(receive(&a,&b,&b.out[1])==TSC_AGAIN);
}
static void relays(void) {
    fixture();
    CHECK(tsc_disco_probe(&a.disco,b.node,1)==TSC_OK);
#if TSC_DISCO_MAX_PROBES == 1
    CHECK(a.count==1 && !a.out[0].relay);
    a.now+=5000;
    CHECK(tsc_disco_probe(&a.disco,b.node,1)==TSC_OK);
#endif
    CHECK(a.count==2 && a.out[1].relay);
    uint8_t wrong[32]={4};
    CHECK(tsc_disco_receive_relay(&b.disco,wrong,a.out[1].packet,a.out[1].length)==TSC_ERR_PROTOCOL);
    CHECK(receive(&b,&a,&a.out[1])==TSC_OK && b.count==1 && b.out[0].relay);
    CHECK(receive(&a,&b,&b.out[0])==TSC_OK);
    tsc_endpoint ep;
    CHECK(tsc_disco_endpoint(&a.disco,b.node,&ep)==TSC_AGAIN && a.paths==0);
#if TSC_DISCO_MAX_PROBES == 1
    CHECK(tsc_disco_probe(&a.disco,b.node,0)==TSC_OK && a.count==3);
    CHECK(receive(&b,&a,&a.out[2])==TSC_OK && !b.out[1].relay);
#else
    CHECK(receive(&b,&a,&a.out[0])==TSC_OK && !b.out[1].relay);
#endif
    CHECK(receive(&a,&b,&b.out[1])==TSC_OK && a.paths==1);
}
static void call_me_maybe(void) {
    fixture();
    tsc_endpoint extra=endpoint(3,12121);
    CHECK(tsc_disco_call_me_maybe(&a.disco,b.node,&extra,1)==TSC_OK);
    CHECK(a.count==1 && a.out[0].relay);
    CHECK(tsc_disco_receive(&b.disco,&a.local,a.out[0].packet,a.out[0].length)==TSC_ERR_PROTOCOL);
    CHECK(receive(&b,&a,&a.out[0])==TSC_OK);
#if TSC_MAX_PEER_ENDPOINTS > 1
    CHECK(b.disco.peers[0].endpoint_count==2);
#if TSC_DISCO_MAX_PROBES > 1
    CHECK(b.count==2 && tsc_endpoint_equal(&b.out[1].destination,&extra));
#else
    CHECK(b.count==1);
#endif
#else
    CHECK(b.disco.peers[0].endpoint_count==1 && b.count==1);
#endif
    /* Endpoint announcements beyond the configured limit are rejected. */
    CHECK(tsc_disco_call_me_maybe(&a.disco,b.node,&extra,TSC_MAX_PEER_ENDPOINTS+1)==TSC_ERR_SPACE);
    CHECK(tsc_disco_set_peer(&a.disco,b.node,b.disco.public_key,&extra,TSC_MAX_PEER_ENDPOINTS+1)==TSC_ERR_SPACE);
    CHECK(tsc_disco_call_me_maybe(&a.disco,b.node,NULL,0)==TSC_OK);
    CHECK(tsc_disco_receive_relay(&b.disco,a.node,a.out[1].packet,a.out[1].length)==TSC_AGAIN);
}
static void identity_and_bounds(void) {
    fixture();
    uint8_t packet[124], plain[46]={1,0}, nonce[24]={0};
    const uint8_t magic[6]={0x54,0x53,0xf0,0x9f,0x92,0xac};
    memcpy(packet,magic,6); memcpy(packet+6,a.disco.public_key,32); memcpy(packet+38,nonce,24);
    memset(plain+2,8,12); memset(plain+14,7,32);
    CHECK(tsc_nacl_box_afternm(packet+62,plain,46,nonce,a.disco.peers[0].shared_key)==TSC_OK);
    CHECK(tsc_disco_receive(&b.disco,&a.local,packet,sizeof(packet))==TSC_ERR_PROTOCOL);
    CHECK(b.count==0);
    memcpy(plain+14,a.node,32); plain[1]=1; /* New ping versions retain known fields. */
    CHECK(tsc_nacl_box_afternm(packet+62,plain,46,nonce,a.disco.peers[0].shared_key)==TSC_OK);
    CHECK(tsc_disco_receive(&b.disco,&a.local,packet,sizeof(packet))==TSC_OK);
    uint8_t zero[32]={0}, low[32]={1}, node[32]={3};
    CHECK(tsc_disco_set_peer(&a.disco,node,zero,NULL,0)==TSC_ERR_ARGUMENT);
    CHECK(tsc_disco_set_peer(&a.disco,b.node,low,NULL,0)==TSC_ERR_PROTOCOL);
    CHECK(tsc_disco_set_peer(&a.disco,node,b.disco.public_key,NULL,0)==TSC_ERR_ARGUMENT);
    CHECK(tsc_disco_receive(NULL,&a.local,packet,sizeof(packet))==TSC_ERR_ARGUMENT);
    CHECK(tsc_disco_receive(&b.disco,NULL,packet,sizeof(packet))==TSC_ERR_ARGUMENT);
    CHECK(tsc_disco_receive_relay(&b.disco,NULL,packet,sizeof(packet))==TSC_ERR_ARGUMENT);
    CHECK(tsc_disco_receive(&b.disco,&a.local,packet,79)==TSC_ERR_PROTOCOL);
    /* Key rotation invalidates paths and pending transactions. */
    CHECK(tsc_disco_probe(&a.disco,b.node,0)==TSC_OK);
    uint8_t priv[32]={9}, pub[32]; CHECK(tsc_crypto_x25519_public(pub,priv)==TSC_OK);
    CHECK(tsc_disco_set_peer(&a.disco,b.node,pub,&b.local,1)==TSC_OK);
    for (size_t i=0;i<TSC_DISCO_MAX_PROBES;++i) CHECK(!a.disco.probes[i].active);
    CHECK(tsc_disco_remove_peer(&a.disco,b.node)==TSC_OK);
    CHECK(tsc_disco_remove_peer(&a.disco,b.node)==TSC_AGAIN);
    CHECK(tsc_disco_tick(&a.disco)==TSC_AGAIN);
    tsc_disco_clear(&a.disco);
    const uint8_t *raw=(const uint8_t *)&a.disco;
    for (size_t i=0;i<sizeof(a.disco);++i) CHECK(raw[i]==0);
}
static void capacities_and_failures(void) {
    fixture();
    a.random_status=TSC_ERR_IO;
    CHECK(tsc_disco_probe(&a.disco,b.node,0)==TSC_ERR_IO);
    a.random_status=0; a.send_status=TSC_AGAIN;
    CHECK(tsc_disco_probe(&a.disco,b.node,0)==TSC_AGAIN);
    for (size_t i=0;i<TSC_DISCO_MAX_PROBES;++i) CHECK(!a.disco.probes[i].active);
    a.send_status=0;
    for (size_t i=0;i<TSC_DISCO_MAX_PROBES;++i) a.disco.probes[i].active=1;
    CHECK(tsc_disco_probe(&a.disco,b.node,0)==TSC_ERR_SPACE);
    a.now+=5000;
    CHECK(tsc_disco_probe(&a.disco,b.node,0)==TSC_OK);
    for (size_t i=1;i<TSC_CLIENT_PEER_SLOTS;++i) {
        uint8_t priv[32]={0},pub[32],node[32]={0};
        priv[1]=(uint8_t)(i+40); node[0]=(uint8_t)(i+1);
        CHECK(tsc_crypto_x25519_public(pub,priv)==TSC_OK);
        CHECK(tsc_disco_set_peer(&a.disco,node,pub,NULL,0)==TSC_OK);
    }
    uint8_t priv[32]={99},pub[32],node[32]={99};
    CHECK(tsc_crypto_x25519_public(pub,priv)==TSC_OK);
    CHECK(tsc_disco_set_peer(&a.disco,node,pub,NULL,0)==TSC_ERR_SPACE);
}
static void quota_one(void) {
#if TSC_DISCO_MAX_PROBES == TSC_CLIENT_PEER_SLOTS
    fixture();
    for (size_t i=1;i<TSC_CLIENT_PEER_SLOTS;++i) {
        uint8_t priv[32]={0},pub[32],node[32]={0};
        priv[1]=(uint8_t)(i+90); node[0]=(uint8_t)(i+10);
        CHECK(tsc_crypto_x25519_public(pub,priv)==TSC_OK);
        CHECK(tsc_disco_set_peer(&a.disco,node,pub,NULL,0)==TSC_OK);
    }
    CHECK(tsc_disco_probe(&a.disco,b.node,1)==TSC_OK);
    CHECK(a.count==1 && !a.out[0].relay);
    a.now+=5000; a.count=0;
    CHECK(tsc_disco_probe(&a.disco,b.node,1)==TSC_OK);
    CHECK(a.count==1 && a.out[0].relay);
    a.now+=5000; a.count=0;
    CHECK(tsc_disco_probe(&a.disco,b.node,1)==TSC_OK);
    CHECK(a.count==1 && !a.out[0].relay);
#endif
}
static void fairness_and_ipv6(void) {
#if TSC_MAX_PEER_ENDPOINTS > 1 && TSC_DISCO_MAX_PROBES >= 2 * TSC_MAX_PEERS
    fixture();
    uint8_t nodes[TSC_MAX_PEERS][32];
    tsc_endpoint eps[TSC_MAX_PEER_ENDPOINTS];
    CHECK(tsc_disco_remove_peer(&a.disco,b.node)==TSC_OK);
    for (size_t i=0;i<TSC_MAX_PEERS;++i) {
        uint8_t priv[32]={0},pub[32];
        priv[1]=(uint8_t)(i+70); memset(nodes[i],(int)(i+1),32);
        CHECK(tsc_crypto_x25519_public(pub,priv)==TSC_OK);
        for (size_t j=0;j<TSC_MAX_PEER_ENDPOINTS;++j)
            eps[j]=endpoint((uint8_t)(i+10),(uint16_t)(13000+j));
        CHECK(tsc_disco_set_peer(&a.disco,nodes[i],pub,eps,TSC_MAX_PEER_ENDPOINTS)==TSC_OK);
    }
    for (size_t round=0;round<2;++round) {
        for (size_t i=0;i<TSC_MAX_PEERS;++i) {
            a.count=0;
            CHECK(tsc_disco_probe(&a.disco,nodes[i],1)==TSC_OK);
            CHECK(a.count>=2);
            CHECK(a.out[0].destination.port==(uint16_t)(13000+round));
            CHECK(a.out[1].relay);
        }
        a.now+=5000;
    }
#endif
#if TSC_ENABLE_IPV6
    fixture();
    memset(&a.local,0,sizeof(a.local)); a.local.family=TSC_AF_IPV6;
    a.local.address[0]=0x20; a.local.address[1]=1; a.local.address[15]=1; a.local.port=11111;
    b.local=a.local; b.local.address[15]=2; b.local.port=22222;
    CHECK(tsc_disco_set_peer(&a.disco,b.node,b.disco.public_key,&b.local,1)==TSC_OK);
    CHECK(tsc_disco_set_peer(&b.disco,a.node,a.disco.public_key,&a.local,1)==TSC_OK);
    CHECK(tsc_disco_probe(&a.disco,b.node,0)==TSC_OK);
    CHECK(receive(&b,&a,&a.out[0])==TSC_OK);
    CHECK(receive(&a,&b,&b.out[0])==TSC_OK);
    CHECK(tsc_endpoint_equal(&a.observed,&a.local));
#endif
}
static void malformed_sweep(void) {
    fixture();
    CHECK(tsc_disco_probe(&a.disco,b.node,0)==TSC_OK);
    captured valid=a.out[0];
    /* Authenticated unknown types and short bodies exercise the inner parser. */
    uint8_t plain[TSC_MAX_DATAGRAM_SIZE], packet[TSC_MAX_DATAGRAM_SIZE+1];
    for (size_t n=2;n<96;++n) {
        for (size_t type=0;type<10;++type) {
            memset(plain,0,n); plain[0]=(uint8_t)type;
            memcpy(packet,valid.packet,62);
            CHECK(tsc_nacl_box_afternm(packet+62,plain,n,packet+38,a.disco.peers[0].shared_key)==TSC_OK);
            b.count=0;
            (void)tsc_disco_receive(&b.disco,&a.local,packet,n+78);
        }
    }
    for (size_t n=0;n<=sizeof(packet);++n) {
        memset(packet,0xa5,n);
        if (n>=62) memcpy(packet,valid.packet,62);
        b.count=0;
        int status=tsc_disco_receive(&b.disco,&a.local,packet,n);
        CHECK(status<0);
    }
}
#endif
int main(void) {
#if TSC_ENABLE_DISCO
    direct_and_attacks(); relays(); call_me_maybe(); identity_and_bounds();
    capacities_and_failures(); quota_one(); fairness_and_ipv6(); malformed_sweep();
    puts("DISCO direct/DERP discovery, identities, replay, capacity and malformed input passed");
    return 0;
#else
    return 77;
#endif
}
