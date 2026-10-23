#ifndef TAILSCALEC_CONTROL_TIME_H
#define TAILSCALEC_CONTROL_TIME_H

#include "tailscalec/tsc.h"

/* Parse the Go time.Time RFC3339Nano representation, with years 0001..9999,
 * optional 1..9 fractional digits, and Z or an offset from -23:59 to +23:59.
 * Leap seconds and out-of-range dates are rejected. The millisecond result is
 * rounded toward negative infinity; submillisecond_nonzero indicates a
 * nonzero discarded fraction. is_zero_time follows Go Time.IsZero: the instant
 * 0001-01-01T00:00:00Z, including equivalent numeric-offset representations.
 * No libc timezone/calendar support or allocation is required. On failure,
 * output values remain unchanged. */
int tsc_control_time_parse(const char *text, int64_t *floor_millis,
                            unsigned *submillisecond_nonzero,
                            unsigned *is_zero_time);

#endif
