#include "tailscalec/tsc.h"
#include <string.h>

int tsc_endpoint_equal(const tsc_endpoint *a, const tsc_endpoint *b)
{
    size_t length;
    if (!a || !b || a->family != b->family || a->port != b->port)
        return 0;
    if (a->family == TSC_AF_IPV4) {
        length = 4;
    } else if (a->family == TSC_AF_IPV6) {
#if TSC_ENABLE_IPV6
        if (a->scope_id != b->scope_id)
            return 0;
        length = 16;
#else
        return 0;
#endif
    } else {
        return 0;
    }
    return memcmp(a->address, b->address, length) == 0;
}

const char *tsc_status_string(int status)
{
    switch (status) {
    case TSC_OK: return "success";
    case TSC_AGAIN: return "pending";
    case TSC_ERR_ARGUMENT: return "invalid argument";
    case TSC_ERR_IO: return "platform I/O failure";
    case TSC_ERR_SPACE: return "buffer or configured limit exceeded";
    case TSC_ERR_PROTOCOL: return "invalid protocol message";
    case TSC_ERR_TIMEOUT: return "timed out";
    case TSC_ERR_UNSUPPORTED: return "unsupported feature";
    case TSC_ERR_TRUNCATED: return "datagram truncated and discarded";
    default: return "unknown status";
    }
}
