#include "control_time.h"

#include <string.h>

static int decimal(const char *text, size_t width, unsigned *value)
{
    unsigned result = 0;
    for (size_t i = 0; i < width; ++i) {
        unsigned char c = (unsigned char)text[i];
        if (c < '0' || c > '9')
            return TSC_ERR_PROTOCOL;
        result = result * 10 + (unsigned)(c - '0');
    }
    *value = result;
    return TSC_OK;
}

static int leap_year(unsigned year)
{
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

/* Gregorian ordinal with 0001-01-01 = 0. */
static int64_t ordinal(unsigned year, unsigned month, unsigned day)
{
    static const unsigned month_start[] = {
        0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
    };
    int64_t previous = (int64_t)year - 1;
    return previous * 365 + previous / 4 - previous / 100 + previous / 400 +
           month_start[month - 1] + (month > 2 && leap_year(year)) + day - 1;
}

int tsc_control_time_parse(const char *text, int64_t *floor_millis,
                            unsigned *submillisecond_nonzero,
                            unsigned *is_zero_time)
{
    if (text == NULL || floor_millis == NULL || submillisecond_nonzero == NULL ||
        is_zero_time == NULL)
        return TSC_ERR_ARGUMENT;
    size_t length = strlen(text);
    if (length < 20 || length > 35 || text[4] != '-' || text[7] != '-' ||
        text[10] != 'T' || text[13] != ':' || text[16] != ':')
        return TSC_ERR_PROTOCOL;
    unsigned year, month, day, hour, minute, second;
    if (decimal(text, 4, &year) != TSC_OK ||
        decimal(text + 5, 2, &month) != TSC_OK ||
        decimal(text + 8, 2, &day) != TSC_OK ||
        decimal(text + 11, 2, &hour) != TSC_OK ||
        decimal(text + 14, 2, &minute) != TSC_OK ||
        decimal(text + 17, 2, &second) != TSC_OK ||
        year == 0 || month == 0 || month > 12 || day == 0 ||
        hour > 23 || minute > 59 || second > 59)
        return TSC_ERR_PROTOCOL;
    static const unsigned month_days[] = {
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };
    unsigned days = month_days[month - 1] + (month == 2 && leap_year(year));
    if (day > days)
        return TSC_ERR_PROTOCOL;

    size_t position = 19;
    unsigned millis = 0, submillis = 0;
    if (text[position] == '.') {
        ++position;
        unsigned digits = 0;
        while (position < length && text[position] >= '0' && text[position] <= '9') {
            if (digits == 9)
                return TSC_ERR_PROTOCOL;
            unsigned value = (unsigned)(text[position++] - '0');
            if (digits < 3)
                millis = millis * 10 + value;
            else if (value != 0)
                submillis = 1;
            ++digits;
        }
        if (digits == 0)
            return TSC_ERR_PROTOCOL;
        for (; digits < 3; ++digits)
            millis *= 10;
    }

    int64_t offset = 0;
    if (position < length && text[position] == 'Z') {
        if (++position != length)
            return TSC_ERR_PROTOCOL;
    } else {
        if (length - position != 6 ||
            (text[position] != '+' && text[position] != '-') ||
            text[position + 3] != ':')
            return TSC_ERR_PROTOCOL;
        unsigned offset_hour, offset_minute;
        if (decimal(text + position + 1, 2, &offset_hour) != TSC_OK ||
            decimal(text + position + 4, 2, &offset_minute) != TSC_OK ||
            offset_hour > 23 || offset_minute > 59)
            return TSC_ERR_PROTOCOL;
        offset = (int64_t)offset_hour * 3600 + (int64_t)offset_minute * 60;
        if (text[position] == '-')
            offset = -offset;
    }

    const int64_t epoch_ordinal = 719162;
    int64_t seconds = (ordinal(year, month, day) - epoch_ordinal) * 86400 +
                      (int64_t)hour * 3600 + (int64_t)minute * 60 + second - offset;
    *floor_millis = seconds * 1000 + millis;
    *submillisecond_nonzero = submillis;
    *is_zero_time = seconds == -epoch_ordinal * 86400 && millis == 0 && submillis == 0;
    return TSC_OK;
}
