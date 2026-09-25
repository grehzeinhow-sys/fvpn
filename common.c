/*
 * common.c — Общие утилиты: логирование, хекс-дамп.
 */
#include "tunnel.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

void log_msg(const char *fmt, ...)
{
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);

    char ts[32];
    strftime(ts, sizeof(ts), "%H:%M:%S", &tm);

    fprintf(stderr, "[%s] ", ts);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

void log_hex(const char *label, const uint8_t *data, size_t len)
{
    fprintf(stderr, "  %s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len && i < 32; i++)
        fprintf(stderr, "%02x", data[i]);
    if (len > 32) fprintf(stderr, "...");
    fprintf(stderr, "\n");
}
