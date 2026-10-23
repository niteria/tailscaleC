#ifndef TSC_CONTROL_ADDRESS_H
#define TSC_CONTROL_ADDRESS_H
#include "tailscalec/tsc.h"
int tsc_control_ip_parse(const char *text, uint8_t output[16],
                         unsigned *family);
int tsc_control_endpoint_parse(const char *text, tsc_endpoint *out);
int tsc_control_endpoint_format(const tsc_endpoint *endpoint, char *out,
                                size_t capacity);
#endif
