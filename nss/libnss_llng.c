/*
 * libnss_llng.c - NSS module for LemonLDAP::NG
 *
 * This module allows NSS to resolve users from a LemonLDAP::NG server.
 * It responds to getpwnam() calls by querying the LLNG /pam/userinfo endpoint.
 *
 * Copyright (C) 2024 Linagora
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
#include <sys/stat.h>
#include <curl/curl.h>
#include <json-c/json.h>

/* Configuration file path */
#define NSS_LLNG_CONF "/etc/nss_llng.conf"

/* Cache settings */
#define CACHE_TTL 300           /* 5 minutes */
#define CACHE_MAX_ENTRIES 1000
#define CACHE_FILE "/var/cache/nss_llng/users.cache"

/* Default values for user creation */
#define DEFAULT_SHELL "/bin/bash"
#define DEFAULT_HOME_BASE "/home"
#define DEFAULT_MIN_UID 10000
#define DEFAULT_MAX_UID 60000

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
            config->timeout = atoi(value);
        }
        else if (strcmp(key, "verify_ssl") == 0) {
            config->verify_ssl = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        }
        else if (strcmp(key, "cache_ttl") == 0) {
            config->cache_ttl = atoi(value);
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
            config->min_uid = (uid_t)atoi(value);
        }
        else if (strcmp(key, "max_uid") == 0) {
            config->max_uid = (uid_t)atoi(value);
        }
        else if (strcmp(key, "default_gid") == 0) {
            config->default_gid = (gid_t)atoi(value);
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
static void init_cache(void)
{
    g_cache.capacity = 100;
    g_cache.entries = calloc(g_cache.capacity, sizeof(cache_entry_t));
    g_cache.count = 0;
    pthread_mutex_init(&g_cache.lock, NULL);
}

/* Find cache entry */
static cache_entry_t *cache_find(const char *username)
{
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

/* Add to cache */
static void cache_add(const char *username, const struct passwd *pw, int valid)
{
    pthread_mutex_lock(&g_cache.lock);

    /* Find empty slot or oldest entry */
    size_t slot = 0;
    time_t oldest = time(NULL);

    for (size_t i = 0; i < g_cache.count; i++) {
        if (!g_cache.entries[i].username) {
            slot = i;
            break;
        }
        if (g_cache.entries[i].timestamp < oldest) {
            oldest = g_cache.entries[i].timestamp;
            slot = i;
        }
    }

    if (g_cache.count < g_cache.capacity) {
        slot = g_cache.count++;
    } else {
        /* Evict old entry */
        free(g_cache.entries[slot].username);
        free(g_cache.entries[slot].pw_buffer);
    }

    cache_entry_t *entry = &g_cache.entries[slot];
    entry->username = strdup(username);
    entry->timestamp = time(NULL);
    entry->valid = valid;

    if (valid && pw) {
        /* Copy passwd struct */
        size_t bufsize = strlen(pw->pw_name) + strlen(pw->pw_passwd) +
                         strlen(pw->pw_gecos) + strlen(pw->pw_dir) +
                         strlen(pw->pw_shell) + 16;
        entry->pw_buffer = malloc(bufsize);
        char *p = entry->pw_buffer;

        entry->pw.pw_name = p;
        strcpy(p, pw->pw_name);
        p += strlen(pw->pw_name) + 1;

        entry->pw.pw_passwd = p;
        strcpy(p, pw->pw_passwd);
        p += strlen(pw->pw_passwd) + 1;

        entry->pw.pw_uid = pw->pw_uid;
        entry->pw.pw_gid = pw->pw_gid;

        entry->pw.pw_gecos = p;
        strcpy(p, pw->pw_gecos);
        p += strlen(pw->pw_gecos) + 1;

        entry->pw.pw_dir = p;
        strcpy(p, pw->pw_dir);
        p += strlen(pw->pw_dir) + 1;

        entry->pw.pw_shell = p;
        strcpy(p, pw->pw_shell);
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

    /* Extract user info */
    char *p = buffer;
    size_t remaining = buflen;

    /* Username */
    pw->pw_name = p;
    strncpy(p, username, remaining);
    size_t len = strlen(username) + 1;
    p += len;
    remaining -= len;

    /* Password (disabled) */
    pw->pw_passwd = p;
    strncpy(p, "x", remaining);
    p += 2;
    remaining -= 2;

    /* UID */
    if (json_object_object_get_ex(json, "uid", &val)) {
        pw->pw_uid = (uid_t)json_object_get_int(val);
    } else {
        /* Generate UID from username hash */
        unsigned int hash = 5381;
        for (const char *c = username; *c; c++) {
            hash = ((hash << 5) + hash) + *c;
        }
        pw->pw_uid = g_config.min_uid + (hash % (g_config.max_uid - g_config.min_uid));
    }

    /* GID */
    if (json_object_object_get_ex(json, "gid", &val)) {
        pw->pw_gid = (gid_t)json_object_get_int(val);
    } else {
        pw->pw_gid = g_config.default_gid;
    }

    /* GECOS */
    pw->pw_gecos = p;
    if (json_object_object_get_ex(json, "gecos", &val)) {
        const char *gecos = json_object_get_string(val);
        strncpy(p, gecos ? gecos : "", remaining);
    } else {
        strncpy(p, "", remaining);
    }
    len = strlen(pw->pw_gecos) + 1;
    p += len;
    remaining -= len;

    /* Home directory */
    pw->pw_dir = p;
    if (json_object_object_get_ex(json, "home", &val)) {
        const char *home = json_object_get_string(val);
        if (home && *home) {
            strncpy(p, home, remaining);
        } else {
            snprintf(p, remaining, "%s/%s", g_config.default_home_base, username);
        }
    } else {
        snprintf(p, remaining, "%s/%s", g_config.default_home_base, username);
    }
    len = strlen(pw->pw_dir) + 1;
    p += len;
    remaining -= len;

    /* Shell */
    pw->pw_shell = p;
    if (json_object_object_get_ex(json, "shell", &val)) {
        const char *shell = json_object_get_string(val);
        strncpy(p, (shell && *shell) ? shell : g_config.default_shell, remaining);
    } else {
        strncpy(p, g_config.default_shell, remaining);
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
        init_cache();
        g_initialized = 1;
    }
    pthread_mutex_unlock(&g_init_lock);
}

/* NSS entry point: getpwnam_r */
enum nss_status _nss_llng_getpwnam_r(const char *name,
                                      struct passwd *result,
                                      char *buffer,
                                      size_t buflen,
                                      int *errnop)
{
    if (!name || !result || !buffer) {
        *errnop = EINVAL;
        return NSS_STATUS_UNAVAIL;
    }

    ensure_initialized();

    if (!g_config.portal_url) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }

    /* Check cache first */
    pthread_mutex_lock(&g_cache.lock);
    cache_entry_t *cached = cache_find(name);
    if (cached) {
        if (!cached->valid) {
            pthread_mutex_unlock(&g_cache.lock);
            *errnop = ENOENT;
            return NSS_STATUS_NOTFOUND;
        }

        /* Copy from cache */
        size_t needed = strlen(cached->pw.pw_name) + strlen(cached->pw.pw_passwd) +
                       strlen(cached->pw.pw_gecos) + strlen(cached->pw.pw_dir) +
                       strlen(cached->pw.pw_shell) + 16;

        if (buflen < needed) {
            pthread_mutex_unlock(&g_cache.lock);
            *errnop = ERANGE;
            return NSS_STATUS_TRYAGAIN;
        }

        char *p = buffer;
        result->pw_name = p;
        strcpy(p, cached->pw.pw_name);
        p += strlen(p) + 1;

        result->pw_passwd = p;
        strcpy(p, cached->pw.pw_passwd);
        p += strlen(p) + 1;

        result->pw_uid = cached->pw.pw_uid;
        result->pw_gid = cached->pw.pw_gid;

        result->pw_gecos = p;
        strcpy(p, cached->pw.pw_gecos);
        p += strlen(p) + 1;

        result->pw_dir = p;
        strcpy(p, cached->pw.pw_dir);
        p += strlen(p) + 1;

        result->pw_shell = p;
        strcpy(p, cached->pw.pw_shell);

        pthread_mutex_unlock(&g_cache.lock);
        return NSS_STATUS_SUCCESS;
    }
    pthread_mutex_unlock(&g_cache.lock);

    /* Query LLNG server */
    if (query_llng_userinfo(name, result, buffer, buflen) == 0) {
        /* Add to cache */
        cache_add(name, result, 1);
        return NSS_STATUS_SUCCESS;
    }

    /* Not found - cache negative result */
    cache_add(name, NULL, 0);
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}

/* NSS entry point: getpwuid_r */
enum nss_status _nss_llng_getpwuid_r(uid_t uid,
                                      struct passwd *result,
                                      char *buffer,
                                      size_t buflen,
                                      int *errnop)
{
    /* We don't support UID lookup - only username lookup */
    (void)uid;
    (void)result;
    (void)buffer;
    (void)buflen;
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}

/* NSS entry point: setpwent (start enumeration) */
enum nss_status _nss_llng_setpwent(void)
{
    /* We don't support enumeration */
    return NSS_STATUS_SUCCESS;
}

/* NSS entry point: endpwent (end enumeration) */
enum nss_status _nss_llng_endpwent(void)
{
    return NSS_STATUS_SUCCESS;
}

/* NSS entry point: getpwent_r (enumerate) */
enum nss_status _nss_llng_getpwent_r(struct passwd *result,
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
