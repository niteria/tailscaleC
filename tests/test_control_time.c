#include "../src/control/control_time.h"
#include "check.h"

#include <string.h>

static void fixtures(void)
{
    static const struct {
        const char *text;
        int64_t millis;
        unsigned submillis, zero;
    } fixtures[] = {
        {"1970-01-01T00:00:00Z", 0, 0, 0},
        {"1970-01-01T00:00:00+00:00", 0, 0, 0},
        {"1970-01-01T00:00:00-00:00", 0, 0, 0},
        {"1970-01-01T00:00:00.1Z", 100, 0, 0},
        {"1970-01-01T00:00:00.12Z", 120, 0, 0},
        {"1970-01-01T00:00:00.123Z", 123, 0, 0},
        {"1970-01-01T00:00:00.1230Z", 123, 0, 0},
        {"1970-01-01T00:00:00.123000000Z", 123, 0, 0},
        {"1970-01-01T00:00:00.123000001Z", 123, 1, 0},
        {"1970-01-01T00:00:00.000000001Z", 0, 1, 0},
        {"1970-01-01T00:00:00.999999999Z", 999, 1, 0},
        {"1969-12-31T23:59:59Z", -1000, 0, 0},
        {"1969-12-31T23:59:59.9Z", -100, 0, 0},
        {"1969-12-31T23:59:59.999Z", -1, 0, 0},
        {"1969-12-31T23:59:59.999999999Z", -1, 1, 0},
        {"1969-12-31T23:59:59.000000001Z", -1000, 1, 0},
        {"2000-02-29T00:00:00Z", INT64_C(951782400000), 0, 0},
        {"1900-03-01T00:00:00Z", INT64_C(-2203891200000), 0, 0},
        {"2024-02-29T12:34:56Z", INT64_C(1709210096000), 0, 0},
        {"2026-10-18T12:30:45+02:00", INT64_C(1792319445000), 0, 0},
        {"1970-01-01T00:00:00+23:59", -86340000, 0, 0},
        {"1970-01-01T00:00:00-23:59", 86340000, 0, 0},
        {"1970-01-01T01:30:00+01:30", 0, 0, 0},
        {"1969-12-31T22:30:00-01:30", 0, 0, 0},
        {"0001-01-01T00:00:00Z", INT64_C(-62135596800000), 0, 1},
        {"0001-01-01T00:00:00.000000000Z", INT64_C(-62135596800000), 0, 1},
        {"0001-01-01T00:00:00+00:00", INT64_C(-62135596800000), 0, 1},
        {"0001-01-01T01:30:00+01:30", INT64_C(-62135596800000), 0, 1},
        {"0001-01-01T00:00:00.000000001Z", INT64_C(-62135596800000), 1, 0},
        {"0001-01-01T00:00:00.001Z", INT64_C(-62135596799999), 0, 0},
        {"0001-01-01T00:00:00+23:59", INT64_C(-62135683140000), 0, 0},
        {"9999-12-31T23:59:59.999999999Z", INT64_C(253402300799999), 1, 0},
        {"9999-12-31T23:59:59.999-23:59", INT64_C(253402387139999), 0, 0}
    };
    for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); ++i) {
        int64_t millis = 123;
        unsigned submillis = 456, zero = 789;
        CHECK(tsc_control_time_parse(fixtures[i].text, &millis, &submillis, &zero) == TSC_OK);
        if (millis != fixtures[i].millis || submillis != fixtures[i].submillis ||
            zero != fixtures[i].zero)
            fprintf(stderr, "Timestamp mismatch: %s\n", fixtures[i].text);
        CHECK(millis == fixtures[i].millis);
        CHECK(submillis == fixtures[i].submillis && zero == fixtures[i].zero);
    }
}

static void malformed(void)
{
    const char *const invalid[] = {
        "", "0", "1970-01-01", "1970-01-01T00:00:00", "1970-01-01T00:00:00.",
        "0000-01-01T00:00:00Z", "10000-01-01T00:00:00Z", "-001-01-01T00:00:00Z",
        "1970-00-01T00:00:00Z", "1970-13-01T00:00:00Z", "1970-01-00T00:00:00Z",
        "1970-01-32T00:00:00Z", "1900-02-29T00:00:00Z", "2100-02-29T00:00:00Z",
        "0001-02-29T00:00:00Z", "2000-02-30T00:00:00Z", "2024-04-31T00:00:00Z",
        "1970-01-01T24:00:00Z", "1970-01-01T00:60:00Z", "1970-01-01T00:00:60Z",
        "1970-01-01T-1:00:00Z", "1970-01-01T00:-1:00Z", "1970-01-01T00:00:-1Z",
        "1970-01-01t00:00:00Z", "1970-01-01T00:00:00z", "1970-01-01 00:00:00Z",
        "1970/01/01T00:00:00Z", "1970-1-01T00:00:00Z", "1970-01-1T00:00:00Z",
        "1970-01-01T0:00:00Z", "1970-01-01T00:0:00Z", "1970-01-01T00:00:0Z",
        "1970-01-01T00:00:00.Z", "1970-01-01T00:00:00,1Z",
        "1970-01-01T00:00:00.1234567890Z", "1970-01-01T00:00:00.-1Z",
        "1970-01-01T00:00:00.1e1Z", "1970-01-01T00:00:00.1",
        "1970-01-01T00:00:00+24:00", "1970-01-01T00:00:00-24:00",
        "1970-01-01T00:00:00+00:60", "1970-01-01T00:00:00-00:60",
        "1970-01-01T00:00:00+00", "1970-01-01T00:00:00+0000",
        "1970-01-01T00:00:00+0:00", "1970-01-01T00:00:00+00:0",
        "1970-01-01T00:00:00+00:00:00", "1970-01-01T00:00:00+ab:cd",
        "1970-01-01T00:00:00Z ", " 1970-01-01T00:00:00Z", "1970-01-01T00:00:00Z\n",
        "1970-01-01T00:00:00ZZ", "1970-01-01T00:00:00Z+00:00",
        "1970-01-01T00:00:00+00:00Z", "1970-01-01T00:00:00Z\xff",
        "1970-01-01T00:00:00\xc3\xa9", "1970-01-01T00:00:00.1\xff"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        int64_t millis = 123;
        unsigned submillis = 456, zero = 789;
        if (tsc_control_time_parse(invalid[i], &millis, &submillis, &zero) != TSC_ERR_PROTOCOL)
            fprintf(stderr, "Accepted malformed timestamp: %s\n", invalid[i]);
        CHECK(tsc_control_time_parse(invalid[i], &millis, &submillis, &zero) == TSC_ERR_PROTOCOL);
        CHECK(millis == 123 && submillis == 456 && zero == 789);
    }
    /* Every truncation must fail, including the longest valid representation. */
    const char text[] = "2024-02-29T12:34:56.123456789+23:59";
    for (size_t i = 0; i < sizeof(text) - 1; ++i) {
        char prefix[sizeof(text)];
        memcpy(prefix, text, i);
        prefix[i] = '\0';
        int64_t millis;
        unsigned submillis, zero;
        CHECK(tsc_control_time_parse(prefix, &millis, &submillis, &zero) == TSC_ERR_PROTOCOL);
    }
}

static void calendars(void)
{
    /* Every date in a 400-year Gregorian cycle, independently advanced one day
     * at a time. The cycle contains 146097 days and repeats exactly. */
    int64_t expected = 0;
    for (unsigned year = 1970; year < 2370; ++year) {
        for (unsigned month = 1; month <= 12; ++month) {
            static const unsigned months[] = {31,28,31,30,31,30,31,31,30,31,30,31};
            unsigned days = months[month - 1];
            if (month == 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))
                ++days;
            for (unsigned day = 1; day <= days; ++day) {
                char text[36];
                CHECK(snprintf(text, sizeof(text), "%04u-%02u-%02uT00:00:00Z",
                                 year, month, day) == 20);
                int64_t millis;
                unsigned submillis, zero;
                CHECK(tsc_control_time_parse(text, &millis, &submillis, &zero) == TSC_OK);
                CHECK(millis == expected && submillis == 0 && zero == 0);
                expected += INT64_C(86400000);
            }
        }
    }
    CHECK(expected == INT64_C(146097) * 86400000);
}

static void arguments(void)
{
    int64_t millis;
    unsigned submillis, zero;
    const char text[] = "1970-01-01T00:00:00Z";
    CHECK(tsc_control_time_parse(NULL, &millis, &submillis, &zero) == TSC_ERR_ARGUMENT);
    CHECK(tsc_control_time_parse(text, NULL, &submillis, &zero) == TSC_ERR_ARGUMENT);
    CHECK(tsc_control_time_parse(text, &millis, NULL, &zero) == TSC_ERR_ARGUMENT);
    CHECK(tsc_control_time_parse(text, &millis, &submillis, NULL) == TSC_ERR_ARGUMENT);
}

int main(void)
{
    fixtures();
    malformed();
    calendars();
    arguments();
    puts("control RFC3339Nano timestamp tests passed");
    return 0;
}
