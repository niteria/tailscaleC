#include "check.h"
#include "tailscalec/nacl.h"
#include "tailscalec/crypto.h"
#include <string.h>

#if TSC_ENABLE_DISCO || TSC_ENABLE_DERP
static void hex(uint8_t *out, const char *in) {
    const char *digits = "0123456789abcdef";
    for (size_t i = 0; in[2 * i]; ++i)
        out[i] = (uint8_t)((strchr(digits, in[2*i]) - digits) * 16 +
                           strchr(digits, in[2*i+1]) - digits);
}
static void vectors(void) {
    /* Independently generated with libsodium crypto_box_easy. Boundary lengths
     * cover the first 32 stream bytes and full/partial Salsa/Poly1305 blocks. */
    static const struct { size_t n; const char *sha256; } v[] = {
        {0,"43ab40c0bea87540875fbb2d1c365f00fdd0435b333d7c055d62620b74173773"},
        {1,"e2ba5bdae1f502912ef5b55ebf9ace824d360a51b35df778b0cd3b2e3747b5c6"},
        {15,"ce3a2a4075c6c0ed1faa4899c83cb72fff578da3cc1ef196ba22493baac8e1b4"},
        {16,"b6b032564d2759c288e8a03de06fef3645ebd8e3dab94339d974c55432510ee1"},
        {17,"75e860e688e27643b8d11afdbf55fcc32884a734af2f65a8109742a85358034b"},
        {31,"fbfb889c938ca86b5a9aae8df42ecf5a3f91711ea74ab85fd76163c7db6de067"},
        {32,"17175020c8a2b71010dce1a344c92baba0030b049c4cd1d687c09b1f1d38413f"},
        {33,"08b0f52fee346043fbbd8eb1bb79170932bfc2064c76dd58885469a493b95f7a"},
        {63,"3cd2ed09f361e38f7d316814f5baa86efb16680b881a9e2bd83dba285e83806f"},
        {64,"22a5d7f65103b96c03805b2a432b4f7db362537cfbd1cf8afc9949c9d85f3246"},
        {65,"3a7a20ff827081680e29d561c2eeef2f6f0049500fa22cb7506fdfad99d99869"},
        {127,"9cab679840dda159cf93b7ae152ab56b136c01e2cec456849ab9017ac37ffb63"},
        {128,"5c52b4ea2b29423931f8e9944f83958ab70613f0aac31c25d1f34bbcd55396e0"},
        {255,"ff86c79b10c05abb0212f0746422b313c71a8f87b9a18edd247a5123ccc4ef27"},
        {1024,"99b8c176e0174fd924c53a3ad97842ff9273fc79bd1efbbd0edaba1dc9bed7ec"},
        {1536,"2959e33bd9d51d55016a933155bb7a0fef1e95bf491abbff173bf35e9948bdeb"}
    };
    uint8_t a[32], b[32], ap[32], bp[32], shared[32], expected[32], digest[32];
    uint8_t nonce[24], message[1536], ciphertext[1552], opened[1552];
    for (size_t i=0;i<32;++i) { a[i]=(uint8_t)i; b[i]=(uint8_t)(32+i); }
    for (size_t i=0;i<24;++i) nonce[i]=(uint8_t)i;
    for (size_t i=0;i<sizeof(message);++i) message[i]=(uint8_t)(i*7+3);
    CHECK(tsc_crypto_x25519_public(ap,a)==TSC_OK);
    CHECK(tsc_crypto_x25519_public(bp,b)==TSC_OK);
    CHECK(tsc_nacl_box_beforenm(shared,bp,a)==TSC_OK);
    hex(expected,"429b61f5d96e37268dfc5114849d599c9ceabffdb68c1f52cd0499af30f5b377");
    CHECK(!memcmp(shared,expected,32));
    for (size_t i=0;i<sizeof(v)/sizeof(v[0]);++i) {
        size_t n=v[i].n;
        CHECK(tsc_nacl_box(ciphertext,message,n,nonce,bp,a)==TSC_OK);
        CHECK(tsc_crypto_sha256(ciphertext,n+16,digest)==TSC_OK);
        hex(expected,v[i].sha256); CHECK(!memcmp(expected,digest,32));
        CHECK(tsc_nacl_box_open(opened,ciphertext,n+16,nonce,ap,b)==TSC_OK);
        CHECK(!memcmp(opened,message,n));
        memcpy(opened,ciphertext,n+16);
        CHECK(tsc_nacl_box_open_afternm(opened,opened,n+16,nonce,shared)==TSC_OK);
        CHECK(!memcmp(opened,message,n));
        /* Failed authentication must not disclose any plaintext. */
        ciphertext[n/2]^=0x80;
        memset(opened,0x7f,n);
        CHECK(tsc_nacl_box_open(opened,ciphertext,n+16,nonce,ap,b)==TSC_ERR_PROTOCOL);
        for (size_t j=0;j<n;++j) CHECK(opened[j]==0);
    }
    uint8_t zero[32]={0};
    CHECK(tsc_nacl_box_beforenm(shared,zero,a)==TSC_ERR_PROTOCOL);
    CHECK(!memcmp(shared,zero,32));
    CHECK(tsc_nacl_box_beforenm(NULL,bp,a)==TSC_ERR_ARGUMENT);
    CHECK(tsc_nacl_box_afternm(NULL,message,1,nonce,shared)==TSC_ERR_ARGUMENT);
    CHECK(tsc_nacl_box_afternm(ciphertext,NULL,1,nonce,shared)==TSC_ERR_ARGUMENT);
    CHECK(tsc_nacl_box_open_afternm(opened,ciphertext,15,nonce,shared)==TSC_ERR_ARGUMENT);
    CHECK(tsc_nacl_box_afternm(ciphertext,NULL,0,nonce,shared)==TSC_OK);
    CHECK(tsc_nacl_box_open_afternm(NULL,ciphertext,16,nonce,shared)==TSC_OK);
}
#endif
int main(void) {
#if TSC_ENABLE_DISCO || TSC_ENABLE_DERP
    vectors();
    puts("NaCl box vectors, authentication, overlap and input checks passed");
    return 0;
#else
    return 77;
#endif
}
