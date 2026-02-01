/*
 * audit_log.c - Structured JSON audit logging for LemonLDAP::NG PAM module
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <pthread.h>
#include <openssl/rand.h>
#include <json-c/json.h>

#include "audit_log.h"

/* Audit context structure */
struct audit_context {
    audit_config_t config;
    pthread_mutex_t lock;
    char hostname[256];
};

/* Event type strings */
static const char *event_type_strings[] = {
    "AUTH_SUCCESS",
    "AUTH_FAILURE",
    "AUTH_DENIED",
    "AUTHZ_SUCCESS",
    "AUTHZ_DENIED",
    "TOKEN_INTROSPECT",
    "TOKEN_REFRESH",
    "TOKEN_REFRESH_ROTATED",
    "CACHE_HIT",
    "CACHE_MISS",
    "RATE_LIMITED",
    "CONFIG_ERROR",
    "SECURITY_ERROR",
    "SERVER_ERROR",
    "ENROLLMENT_START",
    "ENROLLMENT_SUCCESS",
    "ENROLLMENT_FAILURE",
    "USER_CREATED"
};

const char *audit_event_type_str(audit_event_type_t type)
{
    if (type >= 0 && type < (int)(sizeof(event_type_strings) / sizeof(event_type_strings[0]))) {
        return event_type_strings[type];
    }
    return "UNKNOWN";
}

/* Generate UUID v4 */
void audit_generate_correlation_id(char *buf, size_t buf_size)
{
    if (buf_size < 37) {
        if (buf_size > 0) buf[0] = '\0';
        return;
    }

    unsigned char uuid[16];
    if (RAND_bytes(uuid, sizeof(uuid)) != 1) {
        /* Failed to generate random bytes */
        buf[0] = '\0';
        return;
    }

    /* Set version (4) and variant bits */
    uuid[6] = (uuid[6] & 0x0F) | 0x40;
    uuid[8] = (uuid[8] & 0x3F) | 0x80;

    snprintf(buf, buf_size,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             uuid[0], uuid[1], uuid[2], uuid[3],
             uuid[4], uuid[5],
             uuid[6], uuid[7],
             uuid[8], uuid[9],
             uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

audit_context_t *audit_init(const audit_config_t *config)
{
    if (!config) return NULL;

    audit_context_t *ctx = calloc(1, sizeof(audit_context_t));
    if (!ctx) return NULL;

    ctx->config.enabled = config->enabled;
    ctx->config.log_to_syslog = config->log_to_syslog;
    ctx->config.level = config->level;

    if (config->log_file) {
        ctx->config.log_file = strdup(config->log_file);
    }

    pthread_mutex_init(&ctx->lock, NULL);

    if (gethostname(ctx->hostname, sizeof(ctx->hostname)) != 0) {
        strncpy(ctx->hostname, "unknown", sizeof(ctx->hostname) - 1);
    }

    /* Open syslog if needed */
    if (ctx->config.log_to_syslog) {
        openlog("pam_llng", LOG_PID, LOG_AUTH);
    }

    return ctx;
}

void audit_destroy(audit_context_t *ctx)
{
    if (!ctx) return;

    if (ctx->config.log_to_syslog) {
        closelog();
    }

    free(ctx->config.log_file);
    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
}

void audit_event_init(audit_event_t *event, audit_event_type_t type)
{
    if (!event) return;

    memset(event, 0, sizeof(*event));
    event->event_type = type;
    clock_gettime(CLOCK_REALTIME, &event->start_time);
    audit_generate_correlation_id(event->correlation_id, sizeof(event->correlation_id));
}

void audit_event_set_end_time(audit_event_t *event)
{
    if (!event) return;
    clock_gettime(CLOCK_REALTIME, &event->end_time);
}

long audit_event_latency_ms(const audit_event_t *event)
{
    if (!event) return 0;

    long sec_diff = event->end_time.tv_sec - event->start_time.tv_sec;
    long nsec_diff = event->end_time.tv_nsec - event->start_time.tv_nsec;

    return (sec_diff * 1000) + (nsec_diff / 1000000);
}


/* Format timestamp as ISO 8601 with milliseconds */
static void format_timestamp(const struct timespec *ts, char *buf, size_t buf_size)
{
    if (buf_size < 25) {
        if (buf_size > 0) buf[0] = '\0';
        return;
    }

    struct tm tm;
    gmtime_r(&ts->tv_sec, &tm);

    /* Clamp all values to valid ranges to avoid format-truncation warnings */
    int year = tm.tm_year + 1900;
    int mon = tm.tm_mon + 1;
    int day = tm.tm_mday;
    int hour = tm.tm_hour;
    int min = tm.tm_min;
    int sec = tm.tm_sec;
    int ms = (int)(ts->tv_nsec / 1000000);

    /* Ensure values are in valid ranges */
    if (year < 0) year = 0;
    if (year > 9999) year = 9999;
    if (mon < 1) mon = 1;
    if (mon > 12) mon = 12;
    if (day < 1) day = 1;
    if (day > 31) day = 31;
    if (hour < 0) hour = 0;
    if (hour > 23) hour = 23;
    if (min < 0) min = 0;
    if (min > 59) min = 59;
    if (sec < 0) sec = 0;
    if (sec > 60) sec = 60;  /* Allow leap second */
    if (ms < 0) ms = 0;
    if (ms > 999) ms = 999;

    /* ISO 8601 format: 2025-01-15T12:30:45.123Z = 24 chars + null */
    snprintf(buf, buf_size, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             year, mon, day, hour, min, sec, ms);
}

int audit_log_event(audit_context_t *ctx, const audit_event_t *event)
{
    if (!ctx || !ctx->config.enabled || !event) {
        return 0;  /* Not an error, just disabled */
    }

    /* Check level filtering */
    int event_level = 1;  /* Default: auth events */
    switch (event->event_type) {
        case AUDIT_CONFIG_ERROR:
        case AUDIT_SECURITY_ERROR:
        case AUDIT_RATE_LIMITED:
            event_level = 0;  /* Critical */
            break;
        case AUDIT_AUTH_SUCCESS:
        case AUDIT_AUTH_FAILURE:
        case AUDIT_AUTH_DENIED:
        case AUDIT_AUTHZ_SUCCESS:
        case AUDIT_AUTHZ_DENIED:
        case AUDIT_ENROLLMENT_START:
        case AUDIT_ENROLLMENT_SUCCESS:
        case AUDIT_ENROLLMENT_FAILURE:
            event_level = 1;  /* Auth events */
            break;
        default:
            event_level = 2;  /* All events */
            break;
    }

    if (event_level > ctx->config.level) {
        return 0;  /* Filtered out */
    }

    /* Build JSON using json-c for proper escaping */
    char timestamp[32];
    format_timestamp(&event->start_time, timestamp, sizeof(timestamp));

    long latency = audit_event_latency_ms(event);

    json_object *jobj = json_object_new_object();
    if (!jobj) return -1;

    json_object_object_add(jobj, "timestamp", json_object_new_string(timestamp));
    json_object_object_add(jobj, "event_type",
                           json_object_new_string(audit_event_type_str(event->event_type)));
    json_object_object_add(jobj, "correlation_id",
                           json_object_new_string(event->correlation_id));
    json_object_object_add(jobj, "module", json_object_new_string("pam_llng"));
    json_object_object_add(jobj, "host", json_object_new_string(ctx->hostname));
    json_object_object_add(jobj, "user",
                           event->user ? json_object_new_string(event->user) : NULL);
    json_object_object_add(jobj, "service",
                           event->service ? json_object_new_string(event->service) : NULL);
    json_object_object_add(jobj, "client_ip",
                           event->client_ip ? json_object_new_string(event->client_ip) : NULL);
    json_object_object_add(jobj, "tty",
                           event->tty ? json_object_new_string(event->tty) : NULL);
    json_object_object_add(jobj, "result_code", json_object_new_int(event->result_code));
    json_object_object_add(jobj, "cache_hit", json_object_new_boolean(event->cache_hit));
    json_object_object_add(jobj, "latency_ms", json_object_new_int64(latency));
    json_object_object_add(jobj, "reason",
                           event->reason ? json_object_new_string(event->reason) : NULL);
    json_object_object_add(jobj, "details",
                           event->details ? json_object_new_string(event->details) : NULL);

    const char *json_str = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN);

    /* Build the complete line with newline */
    size_t json_len = strlen(json_str);
    char *json_line = malloc(json_len + 2);
    if (!json_line) {
        json_object_put(jobj);
        return -1;
    }
    memcpy(json_line, json_str, json_len);
    json_line[json_len] = '\n';
    json_line[json_len + 1] = '\0';

    /* Write to file */
    if (ctx->config.log_file) {
        pthread_mutex_lock(&ctx->lock);

        /*
         * Security: open file first with O_NOFOLLOW to prevent symlink attacks,
         * then use fstat on the opened fd to avoid TOCTOU race conditions.
         */
        int fd = open(ctx->config.log_file,
                      O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0640);
        if (fd >= 0) {
            struct stat st;
            bool permissions_ok = true;

            if (fstat(fd, &st) == 0) {
                if (st.st_mode & S_IWOTH) {
                    permissions_ok = false;
                }
                if (st.st_mode & S_IWGRP) {
                    permissions_ok = false;
                }
                if (st.st_uid != geteuid()) {
                    permissions_ok = false;
                }
            } else {
                permissions_ok = false;
            }

            if (permissions_ok) {
                fchmod(fd, 0640);
                ssize_t ret = write(fd, json_line, strlen(json_line));
                (void)ret;  /* Intentionally ignore write errors for audit */
            }
            close(fd);
        }

        pthread_mutex_unlock(&ctx->lock);
    }

    /* Write to syslog */
    if (ctx->config.log_to_syslog) {
        int priority = LOG_INFO;
        switch (event->event_type) {
            case AUDIT_AUTH_FAILURE:
            case AUDIT_AUTH_DENIED:
            case AUDIT_AUTHZ_DENIED:
                priority = LOG_WARNING;
                break;
            case AUDIT_CONFIG_ERROR:
            case AUDIT_SECURITY_ERROR:
            case AUDIT_SERVER_ERROR:
            case AUDIT_RATE_LIMITED:
                priority = LOG_ERR;
                break;
            default:
                priority = LOG_INFO;
                break;
        }

        syslog(priority, "%s user=%s service=%s client_ip=%s result=%d",
               audit_event_type_str(event->event_type),
               event->user ? event->user : "-",
               event->service ? event->service : "-",
               event->client_ip ? event->client_ip : "-",
               event->result_code);
    }

    free(json_line);
    json_object_put(jobj);

    return 0;
}

int audit_log(audit_context_t *ctx,
              audit_event_type_t type,
              const char *user,
              const char *service,
              const char *client_ip,
              int result_code,
              const char *reason)
{
    audit_event_t event;
    audit_event_init(&event, type);

    event.user = user;
    event.service = service;
    event.client_ip = client_ip;
    event.result_code = result_code;
    event.reason = reason;

    audit_event_set_end_time(&event);

    return audit_log_event(ctx, &event);
}
