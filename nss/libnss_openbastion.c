/*
 * libnss_llng.c - NSS module for LemonLDAP::NG
 *
 * This module allows NSS to resolve users from a LemonLDAP::NG server.
 * It responds to getpwnam() calls by querying the LLNG /pam/userinfo endpoint.
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <ctype.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>
#include <curl/curl.h>
#include <json-c/json.h>

/* Shared path validation functions */
#include "path_validator.h"

/* Mark NSS entry points as visible when using -fvisibility=hidden */
#define NSS_VISIBLE __attribute__((visibility("default")))

/* Configuration file path */
#define NSS_LLNG_CONF "/etc/nss_llng.conf"

/* Cache settings */
#define CACHE_TTL 300           /* 5 minutes */
#define CACHE_MAX_ENTRIES 1000
#define CACHE_FILE "/var/cache/nss_llng/users.cache"
#define CACHE_DIR "/var/cache/nss_llng"

/* Default values for user creation */
#define DEFAULT_SHELL "/bin/bash"
#define DEFAULT_HOME_BASE "/home"
#define DEFAULT_MIN_UID 10000
#define DEFAULT_MAX_UID 60000

/* Reserved UID for 'nobody' user - must never be assigned */
#define NOBODY_UID 65534

/* Recursion guard - prevent infinite loops when NSS calls trigger more NSS lookups */
static __thread int g_in_nss_lookup = 0;

/* Configuration structure */
typedef struct {
    char *portal_url;
    char *server_token_file;
    char *server_token;
    int timeout;
    int verify_ssl;
    int cache_ttl;
    char *default_shell;
    char *default_home_base;
    uid_t min_uid;
    uid_t max_uid;
    gid_t default_gid;
} nss_llng_config_t;

/* Cache entry */
typedef struct {
    char *username;
    struct passwd pw;
    char *pw_buffer;        /* Buffer for passwd strings */
    time_t timestamp;
    int valid;              /* 1 = user exists, 0 = user not found */
} cache_entry_t;

/* Cache structure */
typedef struct {
    cache_entry_t *entries;
    size_t count;
    size_t capacity;
    pthread_mutex_t lock;
} nss_cache_t;

/* Global state */
static nss_llng_config_t g_config = {0};
static nss_cache_t g_cache = {0};
static int g_initialized = 0;
static pthread_mutex_t g_init_lock = PTHREAD_MUTEX_INITIALIZER;

/* HTTP response buffer */
typedef struct {
    char *data;
    size_t size;
} http_response_t;

/* Trim whitespace */
static char *trim(char *str)
{
    while (*str == ' ' || *str == '\t') str++;
    char *end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
        *end-- = '\0';
    }
    return str;
}

/*
 * Safe string copy with guaranteed null termination and bounds checking.
 * Updates dst pointer and remaining size after copy.
 * Returns 0 on success, -1 if buffer too small.
 */
static int safe_strcpy(char **dst, size_t *remaining, const char *src)
{
    if (!dst || !*dst || !remaining || *remaining == 0) {
        return -1;
    }

    const char *source = src ? src : "";
    size_t src_len = strlen(source);

    /* Need space for string + null terminator */
    if (src_len >= *remaining) {
        return -1;  /* Buffer too small */
    }

    memcpy(*dst, source, src_len);
    (*dst)[src_len] = '\0';

    size_t advance = src_len + 1;
    *dst += advance;
    *remaining -= advance;

    return 0;
}

/*
 * Safe parsing functions to replace atoi().
 * These handle overflow, invalid input, and provide proper error detection.
 */
static int safe_parse_uid(const char *str, uid_t *result)
{
    if (!str || !result) return -1;

    char *endptr;
    errno = 0;
    unsigned long val = strtoul(str, &endptr, 10);

    if (errno != 0 || endptr == str || *endptr != '\0') {
        return -1;  /* Parse error or trailing garbage */
    }
    if (val > (unsigned long)((uid_t)-1)) {
        return -1;  /* Overflow */
    }

    *result = (uid_t)val;
    return 0;
}

static int safe_parse_gid(const char *str, gid_t *result)
{
    if (!str || !result) return -1;

    char *endptr;
    errno = 0;
    unsigned long val = strtoul(str, &endptr, 10);

    if (errno != 0 || endptr == str || *endptr != '\0') {
        return -1;  /* Parse error or trailing garbage */
    }
    if (val > (unsigned long)((gid_t)-1)) {
        return -1;  /* Overflow */
    }

    *result = (gid_t)val;
    return 0;
}

static int safe_parse_int(const char *str, int *result, int min_val, int max_val)
{
    if (!str || !result) return -1;

    char *endptr;
    errno = 0;
    long val = strtol(str, &endptr, 10);

    if (errno != 0 || endptr == str || *endptr != '\0') {
        return -1;  /* Parse error or trailing garbage */
    }
    if (val < min_val || val > max_val) {
        return -1;  /* Out of range */
    }

    *result = (int)val;
    return 0;
}

/*
 * Wrappers for shared path validation functions from path_validator.h
 * These use the default approved lists.
 */
static inline int validate_shell(const char *shell)
{
    return path_validator_check_shell(shell, NULL);
}

static inline int validate_home(const char *home)
{
    return path_validator_check_home(home, NULL);
}

/*
 * Check if a UID is already in use by reading /etc/passwd directly.
 * This avoids NSS recursion by not calling getpwuid().
 * Returns 1 if UID is in use, 0 otherwise.
 */
static int uid_exists_locally(uid_t uid)
{
    FILE *f = fopen("/etc/passwd", "r");
    if (!f) return 0;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        /* Format: username:x:uid:gid:gecos:home:shell */
        char *p = line;
        int field = 0;
        char *start = p;

        while (*p && field < 3) {
            if (*p == ':') {
                if (field == 2) {
                    *p = '\0';
                    uid_t local_uid;
                    if (safe_parse_uid(start, &local_uid) == 0 && local_uid == uid) {
                        fclose(f);
                        return 1;
                    }
                }
                field++;
                start = p + 1;
            }
            p++;
        }
    }

    fclose(f);
    return 0;
}

/*
 * Generate a unique UID from username hash, checking for collisions.
 * Tries up to 100 times with different seeds before giving up.
 *
 * Returns valid UID on success, 0 on failure (UID 0 is reserved for root).
 * Caller MUST check for return value of 0 and handle as error.
 */
static uid_t generate_unique_uid(const char *username, uid_t min_uid, uid_t max_uid)
{
    if (!username || !*username) {
        return 0;  /* Error: invalid username */
    }

    if (min_uid >= max_uid || min_uid < 1000) {
        return 0;  /* Error: invalid UID range */
    }

    unsigned int hash = 5381;
    for (const char *c = username; *c; c++) {
        hash = ((hash << 5) + hash) + (unsigned char)*c;
    }

    uid_t range = max_uid - min_uid;
    if (range == 0) {
        return 0;  /* Error: zero range */
    }

    /* Try to find a non-colliding UID */
    for (int attempt = 0; attempt < 100; attempt++) {
        uid_t candidate = min_uid + ((hash + (unsigned int)attempt) % range);

        /* Skip reserved UIDs */
        if (candidate < 1000) continue;      /* System UIDs */
        if (candidate == NOBODY_UID) continue;

        if (!uid_exists_locally(candidate)) {
            return candidate;
        }
    }

    /*
     * SECURITY: Return 0 (error) instead of a colliding UID.
     * Returning a colliding UID could lead to privilege escalation
     * if the new user shares UID with an existing privileged user.
     */
    return 0;
}

/* Load server token from file */
static int load_server_token(nss_llng_config_t *config)
{
    if (!config->server_token_file) return -1;

    FILE *f = fopen(config->server_token_file, "r");
    if (!f) return -1;

    char buffer[8192];
    size_t len = fread(buffer, 1, sizeof(buffer) - 1, f);
    fclose(f);

    if (len == 0) return -1;
    buffer[len] = '\0';

    /* Remove trailing whitespace/newlines */
    while (len > 0 && (buffer[len-1] == '\n' || buffer[len-1] == '\r' ||
                       buffer[len-1] == ' ' || buffer[len-1] == '\t')) {
        buffer[--len] = '\0';
    }

    /* Try to parse as JSON first (format: {"access_token": "..."}) */
    struct json_object *json = json_tokener_parse(buffer);
    if (json) {
        struct json_object *token_obj;
        if (json_object_object_get_ex(json, "access_token", &token_obj)) {
            const char *token = json_object_get_string(token_obj);
            if (token) {
                free(config->server_token);
                config->server_token = strdup(token);
            }
        }
        json_object_put(json);
    }

    /* If JSON parsing failed or no access_token found, treat as plain token */
    if (!config->server_token && len > 0) {
        config->server_token = strdup(buffer);
    }

    /* Clear sensitive token from stack buffer */
    explicit_bzero(buffer, sizeof(buffer));

    return config->server_token ? 0 : -1;
}

/* Load configuration */
static int load_config(nss_llng_config_t *config)
{
    FILE *f = fopen(NSS_LLNG_CONF, "r");
    if (!f) return -1;

    /* Set defaults */
    config->timeout = 5;
    config->verify_ssl = 1;
    config->cache_ttl = CACHE_TTL;
    config->min_uid = DEFAULT_MIN_UID;
    config->max_uid = DEFAULT_MAX_UID;
    config->default_gid = 100;  /* users group */

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line);
        if (*p == '#' || *p == '\0') continue;

        char *eq = strchr(p, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = trim(p);
        char *value = trim(eq + 1);

        /* Remove quotes */
        size_t vlen = strlen(value);
        if (vlen >= 2 && ((value[0] == '"' && value[vlen-1] == '"') ||
                          (value[0] == '\'' && value[vlen-1] == '\''))) {
            value[vlen-1] = '\0';
            value++;
        }

        if (strcmp(key, "portal_url") == 0) {
            free(config->portal_url);
            config->portal_url = strdup(value);
        }
        else if (strcmp(key, "server_token_file") == 0) {
            free(config->server_token_file);
            config->server_token_file = strdup(value);
        }
        else if (strcmp(key, "timeout") == 0) {
            int timeout;
            if (safe_parse_int(value, &timeout, 1, 300) == 0) {
                config->timeout = timeout;
            }
        }
        else if (strcmp(key, "verify_ssl") == 0) {
            config->verify_ssl = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        }
        else if (strcmp(key, "cache_ttl") == 0) {
            int cache_ttl;
            if (safe_parse_int(value, &cache_ttl, 0, 86400) == 0) {
                config->cache_ttl = cache_ttl;
            }
        }
        else if (strcmp(key, "default_shell") == 0) {
            free(config->default_shell);
            config->default_shell = strdup(value);
        }
        else if (strcmp(key, "default_home_base") == 0) {
            free(config->default_home_base);
            config->default_home_base = strdup(value);
        }
        else if (strcmp(key, "min_uid") == 0) {
            uid_t min_uid;
            if (safe_parse_uid(value, &min_uid) == 0) {
                config->min_uid = min_uid;
            }
        }
        else if (strcmp(key, "max_uid") == 0) {
            uid_t max_uid;
            if (safe_parse_uid(value, &max_uid) == 0) {
                config->max_uid = max_uid;
            }
        }
        else if (strcmp(key, "default_gid") == 0) {
            gid_t default_gid;
            if (safe_parse_gid(value, &default_gid) == 0) {
                config->default_gid = default_gid;
            }
        }
    }

    fclose(f);

    /* Load server token */
    if (config->server_token_file) {
        load_server_token(config);
    }

    /* Set remaining defaults */
    if (!config->default_shell) {
        config->default_shell = strdup(DEFAULT_SHELL);
    }
    if (!config->default_home_base) {
        config->default_home_base = strdup(DEFAULT_HOME_BASE);
    }

    return (config->portal_url && config->server_token) ? 0 : -1;
}

/* Initialize cache */
static int init_cache(void)
{
    g_cache.capacity = 100;
    g_cache.entries = calloc(g_cache.capacity, sizeof(cache_entry_t));
    if (!g_cache.entries) {
        g_cache.capacity = 0;
        return -1;  /* OOM */
    }
    g_cache.count = 0;
    pthread_mutex_init(&g_cache.lock, NULL);
    return 0;
}

/* Find cache entry by username */
static cache_entry_t *cache_find(const char *username)
{
    /* Guard against uninitialized cache */
    if (!g_cache.entries || g_cache.capacity == 0) {
        return NULL;
    }

    time_t now = time(NULL);

    for (size_t i = 0; i < g_cache.count; i++) {
        if (g_cache.entries[i].username &&
            strcmp(g_cache.entries[i].username, username) == 0) {

            /* Check TTL */
            if (now - g_cache.entries[i].timestamp < g_config.cache_ttl) {
                return &g_cache.entries[i];
            }

            /* Expired - remove */
            free(g_cache.entries[i].username);
            free(g_cache.entries[i].pw_buffer);
            g_cache.entries[i].username = NULL;
            return NULL;
        }
    }
    return NULL;
}

/* Find cache entry by UID */
static cache_entry_t *cache_find_by_uid(uid_t uid)
{
    /* Guard against uninitialized cache */
    if (!g_cache.entries || g_cache.capacity == 0) {
        return NULL;
    }

    time_t now = time(NULL);

    for (size_t i = 0; i < g_cache.count; i++) {
        if (g_cache.entries[i].username && g_cache.entries[i].valid &&
            g_cache.entries[i].pw.pw_uid == uid) {

            /* Check TTL */
            if (now - g_cache.entries[i].timestamp < g_config.cache_ttl) {
                return &g_cache.entries[i];
            }

            /* Expired - remove */
            free(g_cache.entries[i].username);
            free(g_cache.entries[i].pw_buffer);
            g_cache.entries[i].username = NULL;
            return NULL;
        }
    }
    return NULL;
}

/*
 * File-based cache for cross-process persistence.
 * Format: username:uid:gid:gecos:home:shell:timestamp
 * One file per UID: /var/cache/nss_llng/<uid>
 */

/* Save user info to file cache */
static void file_cache_save(const struct passwd *pw)
{
    if (!pw || !pw->pw_name) return;

    /* Ensure cache directory exists with world-readable permissions.
     * Use mkdir with correct mode; if it already exists (EEXIST), proceed.
     * The directory needs to be world-readable (0755) so all users can do UID lookups. */
    if (mkdir(CACHE_DIR, 0755) == -1 && errno != EEXIST) {
        syslog(LOG_WARNING, "libnss_llng: cannot create cache directory %s: %s",
               CACHE_DIR, strerror(errno));
        return;
    }

    char filepath[256];
    int len = snprintf(filepath, sizeof(filepath), "%s/%u", CACHE_DIR, (unsigned)pw->pw_uid);
    if (len < 0 || (size_t)len >= sizeof(filepath)) {
        syslog(LOG_ERR, "libnss_llng: cache filepath truncated for uid %u",
               (unsigned)pw->pw_uid);
        return;
    }

    FILE *f = fopen(filepath, "w");
    if (!f) {
        syslog(LOG_WARNING, "libnss_llng: cannot create cache file %s: %s",
               filepath, strerror(errno));
        return;
    }

    /* Write in format: username:uid:gid:gecos:home:shell:timestamp */
    fprintf(f, "%s:%u:%u:%s:%s:%s:%ld\n",
            pw->pw_name,
            (unsigned)pw->pw_uid,
            (unsigned)pw->pw_gid,
            pw->pw_gecos ? pw->pw_gecos : "",
            pw->pw_dir ? pw->pw_dir : "",
            pw->pw_shell ? pw->pw_shell : "",
            (long)time(NULL));

    /* Make cache file world-readable so all users can do UID lookups.
     * Use fchmod() on the file descriptor to avoid TOCTOU race condition
     * (file could be replaced between fclose and chmod) */
    fchmod(fileno(f), 0644);
    fclose(f);
}

/* Load user info from file cache by UID */
static int file_cache_load_by_uid(uid_t uid, struct passwd *pw, char *buffer, size_t buflen)
{
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/%u", CACHE_DIR, (unsigned)uid);

    FILE *f = fopen(filepath, "r");
    if (!f) return -1;

    char line[1024];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);

    /* Parse: username:uid:gid:gecos:home:shell:timestamp */
    char *saveptr;
    char *username_str = strtok_r(line, ":", &saveptr);
    char *uid_str = strtok_r(NULL, ":", &saveptr);
    char *gid_str = strtok_r(NULL, ":", &saveptr);
    char *gecos_str = strtok_r(NULL, ":", &saveptr);
    char *home_str = strtok_r(NULL, ":", &saveptr);
    char *shell_str = strtok_r(NULL, ":", &saveptr);
    char *timestamp_str = strtok_r(NULL, ":", &saveptr);

    if (!username_str || !uid_str || !gid_str || !timestamp_str) {
        return -1;
    }

    /* Check TTL - use strtol for safe parsing */
    char *endptr;
    errno = 0;
    long timestamp = strtol(timestamp_str, &endptr, 10);
    /* Allow trailing whitespace (e.g. newline from fgets) after the number */
    while (*endptr != '\0' && isspace((unsigned char)*endptr)) {
        endptr++;
    }
    if (errno != 0 || endptr == timestamp_str || *endptr != '\0') {
        return -1;  /* Invalid timestamp */
    }
    if (time(NULL) - timestamp > g_config.cache_ttl) {
        /* Expired - remove file */
        unlink(filepath);
        return -1;
    }

    /* Check UID matches */
    uid_t file_uid;
    if (safe_parse_uid(uid_str, &file_uid) != 0 || file_uid != uid) {
        return -1;
    }

    /* Parse GID */
    gid_t file_gid;
    if (safe_parse_gid(gid_str, &file_gid) != 0) {
        return -1;
    }

    /* Copy data to buffer with safe bounds checking */
    char *p = buffer;
    size_t remaining = buflen;

    pw->pw_name = p;
    if (safe_strcpy(&p, &remaining, username_str) != 0) return -1;

    pw->pw_passwd = p;
    if (safe_strcpy(&p, &remaining, "x") != 0) return -1;

    pw->pw_uid = file_uid;
    pw->pw_gid = file_gid;

    pw->pw_gecos = p;
    if (safe_strcpy(&p, &remaining, gecos_str ? gecos_str : "") != 0) return -1;

    pw->pw_dir = p;
    if (safe_strcpy(&p, &remaining, home_str ? home_str : "") != 0) return -1;

    pw->pw_shell = p;
    if (safe_strcpy(&p, &remaining, shell_str ? shell_str : "") != 0) return -1;

    return 0;
}

/* Add to cache */
static void cache_add(const char *username, const struct passwd *pw, int valid)
{
    /* Guard against uninitialized cache */
    if (!g_cache.entries || g_cache.capacity == 0) {
        return;
    }

    pthread_mutex_lock(&g_cache.lock);

    size_t slot;

    if (g_cache.count < g_cache.capacity) {
        /* Use next available slot */
        slot = g_cache.count++;
    } else {
        /* Cache full - find oldest entry to evict */
        slot = 0;
        time_t oldest = g_cache.entries[0].timestamp;

        for (size_t i = 1; i < g_cache.count; i++) {
            if (g_cache.entries[i].timestamp < oldest) {
                oldest = g_cache.entries[i].timestamp;
                slot = i;
            }
        }

        /* Evict old entry */
        free(g_cache.entries[slot].username);
        free(g_cache.entries[slot].pw_buffer);
    }

    cache_entry_t *entry = &g_cache.entries[slot];
    entry->username = strdup(username);
    entry->timestamp = time(NULL);
    entry->valid = valid;
    entry->pw_buffer = NULL;

    if (valid && pw) {
        /* Pre-calculate string lengths for efficiency */
        size_t name_len = strlen(pw->pw_name) + 1;
        size_t passwd_len = strlen(pw->pw_passwd) + 1;
        size_t gecos_len = strlen(pw->pw_gecos) + 1;
        size_t dir_len = strlen(pw->pw_dir) + 1;
        size_t shell_len = strlen(pw->pw_shell) + 1;
        size_t bufsize = name_len + passwd_len + gecos_len + dir_len + shell_len;

        entry->pw_buffer = malloc(bufsize);
        if (!entry->pw_buffer) {
            pthread_mutex_unlock(&g_cache.lock);
            return;
        }
        char *p = entry->pw_buffer;

        entry->pw.pw_name = p;
        memcpy(p, pw->pw_name, name_len);
        p += name_len;

        entry->pw.pw_passwd = p;
        memcpy(p, pw->pw_passwd, passwd_len);
        p += passwd_len;

        entry->pw.pw_uid = pw->pw_uid;
        entry->pw.pw_gid = pw->pw_gid;

        entry->pw.pw_gecos = p;
        memcpy(p, pw->pw_gecos, gecos_len);
        p += gecos_len;

        entry->pw.pw_dir = p;
        memcpy(p, pw->pw_dir, dir_len);
        p += dir_len;

        entry->pw.pw_shell = p;
        memcpy(p, pw->pw_shell, shell_len);
    }

    pthread_mutex_unlock(&g_cache.lock);
}

/* CURL write callback */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    http_response_t *resp = (http_response_t *)userp;

    char *ptr = realloc(resp->data, resp->size + realsize + 1);
    if (!ptr) return 0;

    resp->data = ptr;
    memcpy(&resp->data[resp->size], contents, realsize);
    resp->size += realsize;
    resp->data[resp->size] = '\0';

    return realsize;
}

/* Query LLNG server for user info */
static int query_llng_userinfo(const char *username, struct passwd *pw,
                                char *buffer, size_t buflen)
{
    if (!g_config.portal_url || !g_config.server_token) {
        return -1;
    }

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    /* Build URL */
    char url[512];
    snprintf(url, sizeof(url), "%s/pam/userinfo", g_config.portal_url);

    /* Build request body */
    struct json_object *req_json = json_object_new_object();
    json_object_object_add(req_json, "user", json_object_new_string(username));
    const char *req_body = json_object_to_json_string(req_json);

    /* Build Authorization header */
    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", g_config.server_token);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, auth_header);

    http_response_t response = {0};

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req_body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, g_config.timeout);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    if (!g_config.verify_ssl) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        /* Log warning only once per process to avoid log spam */
        static int ssl_warning_logged = 0;
        if (!ssl_warning_logged) {
            ssl_warning_logged = 1;
            syslog(LOG_WARNING, "nss_openbastion: SSL verification disabled - "
                   "vulnerable to MITM attacks");
        }
    }

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    json_object_put(req_json);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || !response.data) {
        free(response.data);
        return -1;
    }

    /* Parse response */
    struct json_object *json = json_tokener_parse(response.data);
    free(response.data);

    if (!json) return -1;

    struct json_object *val;
    int found = 0;

    /* Check if user was found */
    if (json_object_object_get_ex(json, "found", &val)) {
        found = json_object_get_boolean(val);
    }

    if (!found) {
        json_object_put(json);
        return -1;
    }

    /* Extract user info with safe bounds checking */
    char *p = buffer;
    size_t remaining = buflen;

    /* Verify minimum buffer size (rough estimate) */
    size_t min_needed = strlen(username) + 64 + 256 + 256 + 128;
    if (buflen < min_needed) {
        json_object_put(json);
        return -1;
    }

    /* Username */
    pw->pw_name = p;
    if (safe_strcpy(&p, &remaining, username) != 0) {
        json_object_put(json);
        return -1;
    }

    /* Password (disabled) */
    pw->pw_passwd = p;
    if (safe_strcpy(&p, &remaining, "x") != 0) {
        json_object_put(json);
        return -1;
    }

    /* UID - only use if it's actually an integer, not a string like "username" */
    if (json_object_object_get_ex(json, "uid", &val)) {
        if (json_object_is_type(val, json_type_int)) {
            pw->pw_uid = (uid_t)json_object_get_int(val);
            /* Validate server-provided UID is in acceptable range */
            if (pw->pw_uid < g_config.min_uid || pw->pw_uid > g_config.max_uid ||
                pw->pw_uid == NOBODY_UID) {
                /* Reject UIDs outside configured range and nobody - security risk */
                json_object_put(json);
                return -1;
            }
        } else {
            /* Server returned non-integer uid (likely string username) - log warning */
            syslog(LOG_WARNING, "libnss_llng: server returned non-integer uid for user %s, generating UID from hash", username);
            pw->pw_uid = generate_unique_uid(username, g_config.min_uid, g_config.max_uid);
            if (pw->pw_uid == 0) {
                json_object_put(json);
                return -1;
            }
        }
    } else {
        /* No UID provided - generate unique UID from username hash */
        pw->pw_uid = generate_unique_uid(username, g_config.min_uid, g_config.max_uid);
        if (pw->pw_uid == 0) {
            /* Failed to generate unique UID - all candidates collide */
            json_object_put(json);
            return -1;
        }
    }

    /* GID - only use if it's actually an integer */
    if (json_object_object_get_ex(json, "gid", &val) &&
        json_object_is_type(val, json_type_int)) {
        pw->pw_gid = (gid_t)json_object_get_int(val);
    } else {
        pw->pw_gid = g_config.default_gid;
    }

    /* GECOS - sanitize to remove dangerous characters */
    pw->pw_gecos = p;
    const char *gecos_raw = "";
    if (json_object_object_get_ex(json, "gecos", &val)) {
        const char *tmp = json_object_get_string(val);
        if (tmp) gecos_raw = tmp;
    }
    /* Sanitize GECOS: remove colons and newlines which could corrupt passwd format */
    char gecos_safe[256];
    size_t gi = 0;
    for (const char *gc = gecos_raw; *gc && gi < sizeof(gecos_safe) - 1; gc++) {
        if (*gc != ':' && *gc != '\n' && *gc != '\r') {
            gecos_safe[gi++] = *gc;
        }
    }
    gecos_safe[gi] = '\0';
    if (safe_strcpy(&p, &remaining, gecos_safe) != 0) {
        json_object_put(json);
        return -1;
    }

    /* Home directory - validate server-provided path */
    pw->pw_dir = p;
    char home_buf[256];
    if (json_object_object_get_ex(json, "home", &val)) {
        const char *home = json_object_get_string(val);
        /* Only use server-provided home if it passes validation */
        if (home && *home && validate_home(home) == 0) {
            snprintf(home_buf, sizeof(home_buf), "%s", home);
        } else {
            /* Fall back to default if invalid or missing */
            snprintf(home_buf, sizeof(home_buf), "%s/%s", g_config.default_home_base, username);
        }
    } else {
        snprintf(home_buf, sizeof(home_buf), "%s/%s", g_config.default_home_base, username);
    }
    if (safe_strcpy(&p, &remaining, home_buf) != 0) {
        json_object_put(json);
        return -1;
    }

    /* Shell - validate server-provided path */
    pw->pw_shell = p;
    const char *shell_to_use = g_config.default_shell;
    if (json_object_object_get_ex(json, "shell", &val)) {
        const char *shell = json_object_get_string(val);
        /* Only use server-provided shell if it passes validation */
        if (shell && *shell && validate_shell(shell) == 0) {
            shell_to_use = shell;
        }
        /* Otherwise fall back to default shell */
    }
    if (safe_strcpy(&p, &remaining, shell_to_use) != 0) {
        json_object_put(json);
        return -1;
    }

    json_object_put(json);
    return 0;
}

/* Initialize module */
static void ensure_initialized(void)
{
    if (g_initialized) return;

    pthread_mutex_lock(&g_init_lock);
    if (!g_initialized) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        load_config(&g_config);
        if (init_cache() != 0) {
            /* Cache init failed (OOM), continue without caching */
            g_cache.capacity = 0;
            g_cache.count = 0;
            g_cache.entries = NULL;
        }
        g_initialized = 1;
    }
    pthread_mutex_unlock(&g_init_lock);
}

/* NSS entry point: getpwnam_r */
NSS_VISIBLE enum nss_status _nss_llng_getpwnam_r(const char *name,
                                      struct passwd *result,
                                      char *buffer,
                                      size_t buflen,
                                      int *errnop)
{
    if (!name || !result || !buffer) {
        *errnop = EINVAL;
        return NSS_STATUS_UNAVAIL;
    }

    /* Recursion guard: if we're already in a lookup, don't recurse */
    if (g_in_nss_lookup) {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }

    g_in_nss_lookup = 1;

    ensure_initialized();

    if (!g_config.portal_url) {
        g_in_nss_lookup = 0;
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }

    /* Check cache first */
    pthread_mutex_lock(&g_cache.lock);
    cache_entry_t *cached = cache_find(name);
    if (cached) {
        if (!cached->valid) {
            pthread_mutex_unlock(&g_cache.lock);
            g_in_nss_lookup = 0;
            *errnop = ENOENT;
            return NSS_STATUS_NOTFOUND;
        }

        /* Copy from cache with safe bounds checking */
        size_t needed = strlen(cached->pw.pw_name) + strlen(cached->pw.pw_passwd) +
                       strlen(cached->pw.pw_gecos) + strlen(cached->pw.pw_dir) +
                       strlen(cached->pw.pw_shell) + 16;

        if (buflen < needed) {
            pthread_mutex_unlock(&g_cache.lock);
            g_in_nss_lookup = 0;
            *errnop = ERANGE;
            return NSS_STATUS_TRYAGAIN;
        }

        char *p = buffer;
        size_t remaining = buflen;

        result->pw_name = p;
        if (safe_strcpy(&p, &remaining, cached->pw.pw_name) != 0) goto cache_overflow;

        result->pw_passwd = p;
        if (safe_strcpy(&p, &remaining, cached->pw.pw_passwd) != 0) goto cache_overflow;

        result->pw_uid = cached->pw.pw_uid;
        result->pw_gid = cached->pw.pw_gid;

        result->pw_gecos = p;
        if (safe_strcpy(&p, &remaining, cached->pw.pw_gecos) != 0) goto cache_overflow;

        result->pw_dir = p;
        if (safe_strcpy(&p, &remaining, cached->pw.pw_dir) != 0) goto cache_overflow;

        result->pw_shell = p;
        if (safe_strcpy(&p, &remaining, cached->pw.pw_shell) != 0) goto cache_overflow;

        pthread_mutex_unlock(&g_cache.lock);
        g_in_nss_lookup = 0;
        return NSS_STATUS_SUCCESS;

    cache_overflow:
        pthread_mutex_unlock(&g_cache.lock);
        g_in_nss_lookup = 0;
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    pthread_mutex_unlock(&g_cache.lock);

    /* Query LLNG server */
    if (query_llng_userinfo(name, result, buffer, buflen) == 0) {
        /* Add to memory cache */
        cache_add(name, result, 1);
        /* Also save to file cache for cross-process UID lookups */
        file_cache_save(result);
        g_in_nss_lookup = 0;
        return NSS_STATUS_SUCCESS;
    }

    /* Not found - cache negative result */
    cache_add(name, NULL, 0);
    g_in_nss_lookup = 0;
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}

/* NSS entry point: getpwuid_r */
NSS_VISIBLE enum nss_status _nss_llng_getpwuid_r(uid_t uid,
                                      struct passwd *result,
                                      char *buffer,
                                      size_t buflen,
                                      int *errnop)
{
    if (!result || !buffer) {
        *errnop = EINVAL;
        return NSS_STATUS_UNAVAIL;
    }

    /* Recursion guard: if we're already in a lookup, don't recurse */
    if (g_in_nss_lookup) {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }

    g_in_nss_lookup = 1;

    ensure_initialized();

    /*
     * UID lookup is done from cache only.
     * Users must be looked up by name first (via getpwnam) before
     * UID lookup will work. This happens automatically during PAM
     * authentication when the user logs in.
     */
    pthread_mutex_lock(&g_cache.lock);
    cache_entry_t *cached = cache_find_by_uid(uid);
    if (cached && cached->valid) {
        /* Copy from cache with safe bounds checking */
        size_t needed = strlen(cached->pw.pw_name) + strlen(cached->pw.pw_passwd) +
                       strlen(cached->pw.pw_gecos) + strlen(cached->pw.pw_dir) +
                       strlen(cached->pw.pw_shell) + 16;

        if (buflen < needed) {
            pthread_mutex_unlock(&g_cache.lock);
            g_in_nss_lookup = 0;
            *errnop = ERANGE;
            return NSS_STATUS_TRYAGAIN;
        }

        char *p = buffer;
        size_t remaining = buflen;

        result->pw_name = p;
        if (safe_strcpy(&p, &remaining, cached->pw.pw_name) != 0) goto uid_cache_overflow;

        result->pw_passwd = p;
        if (safe_strcpy(&p, &remaining, cached->pw.pw_passwd) != 0) goto uid_cache_overflow;

        result->pw_uid = cached->pw.pw_uid;
        result->pw_gid = cached->pw.pw_gid;

        result->pw_gecos = p;
        if (safe_strcpy(&p, &remaining, cached->pw.pw_gecos) != 0) goto uid_cache_overflow;

        result->pw_dir = p;
        if (safe_strcpy(&p, &remaining, cached->pw.pw_dir) != 0) goto uid_cache_overflow;

        result->pw_shell = p;
        if (safe_strcpy(&p, &remaining, cached->pw.pw_shell) != 0) goto uid_cache_overflow;

        pthread_mutex_unlock(&g_cache.lock);
        g_in_nss_lookup = 0;
        return NSS_STATUS_SUCCESS;

    uid_cache_overflow:
        pthread_mutex_unlock(&g_cache.lock);
        g_in_nss_lookup = 0;
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    pthread_mutex_unlock(&g_cache.lock);

    /* Try file-based cache (shared across processes) */
    if (file_cache_load_by_uid(uid, result, buffer, buflen) == 0) {
        /* Also add to memory cache for future lookups in this process */
        cache_add(result->pw_name, result, 1);
        g_in_nss_lookup = 0;
        return NSS_STATUS_SUCCESS;
    }

    /* UID not found in cache - cannot query LLNG by UID */
    g_in_nss_lookup = 0;
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}

/* NSS entry point: setpwent (start enumeration) */
NSS_VISIBLE enum nss_status _nss_llng_setpwent(void)
{
    /* We don't support enumeration */
    return NSS_STATUS_SUCCESS;
}

/* NSS entry point: endpwent (end enumeration) */
NSS_VISIBLE enum nss_status _nss_llng_endpwent(void)
{
    return NSS_STATUS_SUCCESS;
}

/* NSS entry point: getpwent_r (enumerate) */
NSS_VISIBLE enum nss_status _nss_llng_getpwent_r(struct passwd *result,
                                      char *buffer,
                                      size_t buflen,
                                      int *errnop)
{
    /* We don't support enumeration */
    (void)result;
    (void)buffer;
    (void)buflen;
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}
