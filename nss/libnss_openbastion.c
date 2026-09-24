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
#include <stdint.h>
#include <fcntl.h>

/* Shared path validation functions */
#include "path_validator.h"

/* Shared string helpers (str_parse_bool_strict, issue #183) */
#include "str_utils.h"

/* Mark NSS entry points as visible when using -fvisibility=hidden */
#define NSS_VISIBLE __attribute__((visibility("default")))

/* Configuration file path. Overridable, with the uid that must own it, ONLY by
 * tests/test_nss_force_shell.c, which runs unprivileged and needs the real
 * loader to read a file it wrote. */
#ifndef NSS_OB_CONF
#define NSS_OB_CONF "/etc/open-bastion/nss_openbastion.conf"
#endif
#ifndef NSS_CONF_TRUSTED_UID
#define NSS_CONF_TRUSTED_UID ((uid_t)0)
#endif

/* Cache settings */
#define CACHE_TTL 300           /* 5 minutes */
#define CACHE_MAX_ENTRIES 1000

/*
 * Longest serialized cache record we are willing to write, newline included.
 *
 * The readers pull a record with fgets() into a 1024-byte buffer, so a longer
 * line comes back TRUNCATED: its field count is wrong and it can never be
 * parsed again. Refusing to write past this bound is what keeps the on-disk
 * format and the read buffer in agreement; the margin below 1024 leaves room
 * for the terminating NUL and for a reader with a slightly smaller buffer.
 */
#define CACHE_LINE_MAX 900

/* Overridable so tests/test_nss_cache.c (which includes this file) can point
 * the file cache at a temporary directory instead of the real system path. */
#ifndef CACHE_DIR
#define CACHE_DIR "/var/cache/nss_llng"
#endif
/* Name-keyed cross-process cache lives in its own subdirectory so usernames
 * (validated as a filename) can never collide with the numeric per-uid files
 * that live directly under CACHE_DIR. Separately overridable because a test may
 * substitute a non-literal CACHE_DIR, which cannot be string-concatenated. */
#ifndef CACHE_DIR_BYNAME
#define CACHE_DIR_BYNAME CACHE_DIR "/byname"
#endif

/*
 * The single uid that is allowed to own and to write the on-disk cache.
 *
 * Production always requires root: the cache files are consumed by privileged
 * callers (sshd, sudo, cron) which act on the uid/gid we hand back, so anything
 * an unprivileged user could own or write is untrusted by definition.
 *
 * Overridable ONLY by tests/test_nss_cache.c, which runs unprivileged and
 * therefore owns the throwaway cache directory it drives these helpers against.
 * Overriding it in the shipped module would be a privilege-escalation bug.
 */
#ifndef CACHE_TRUSTED_UID
#define CACHE_TRUSTED_UID ((uid_t)0)
#endif

/*
 * Mode of the cache directories: 0711, i.e. traversable but NOT listable.
 *
 * Entries themselves stay 0644 (an NSS module runs inside the calling process,
 * so getpwuid() must be servable to unprivileged programs — see
 * file_cache_write_atomic_at), but nobody except root can readdir() the
 * directory, so the SSO user directory cannot be harvested wholesale by a local
 * account. This matters most for the name-keyed subdirectory, where the
 * filenames are the login names themselves. Refs #189.
 */
#define CACHE_DIR_MODE 0711

/* Default values for user creation */
#define DEFAULT_SHELL "/bin/bash"

/* An unusable force_shell value falls back to the launcher, never to bash. */
#define DEFAULT_FORCE_SHELL "/usr/sbin/ob-login-shell"
#define DEFAULT_HOME_BASE "/home"
#define DEFAULT_MIN_UID 10000

/*
 * Default path to the Open Bastion service-accounts configuration. Can be
 * overridden in nss_openbastion.conf with `service_accounts_file = …`
 * (same key name pam_openbastion uses) so both modules keep a consistent
 * view of which file is authoritative.
 */
#define DEFAULT_SERVICE_ACCOUNTS_CONF_FILE "/etc/open-bastion/service-accounts.conf"
#define DEFAULT_MAX_UID 60000

/* Reserved UID for 'nobody' user - must never be assigned */
#define NOBODY_UID 65534

/*
 * Policy range for a *server-supplied* primary GID (the `gid` key of
 * pamAccessExportedVars, typically an LDAP gidNumber).
 *
 * This is deliberately NOT the synthetic [min_uid, max_uid] range: those bounds
 * exist so generate_unique_uid() can mint UIDs that cannot collide with local
 * accounts, and an LDAP gidNumber has no reason to live there. Validating a gid
 * against them replaces every ordinary group (1000, 5000, a Debian user-private
 * group) with default_gid - a silent permission change on shared files.
 *
 * The line that matters is system group vs. user group:
 *   - Debian login.defs / adduser: SYS_GID_MIN=100, SYS_GID_MAX=999, GID_MIN=1000
 *   - RHEL/Fedora login.defs:      system groups <= 999, GID_MIN=1000
 *   - this module already refuses a min_uid below 1000 in generate_unique_uid()
 *     "to protect system UIDs" - the same boundary, applied to groups.
 *
 * So the default floor is 1000. It covers the whole static band (root=0, adm=4,
 * disk=6, wheel=10, sudo=27, shadow=42, staff=50) *and* the dynamic band where
 * `docker`, `lxd` or `libvirt` land on Debian (adduser --system allocates from
 * 100-999) - a "< 100" cut would let `docker` through, which is a root
 * equivalent. Sites that legitimately export a low gidNumber (e.g. 100/users)
 * can lower min_gid in nss_openbastion.conf.
 *
 * GID 0 is rejected unconditionally, whatever min_gid says.
 */
#define DEFAULT_MIN_GID 1000
#define DEFAULT_MAX_GID 65533

/* Reserved GID for 'nogroup'/'nobody' - must never be assigned */
#define NOBODY_GID 65534

/* Recursion guard - prevent infinite loops when NSS calls trigger more NSS lookups */
static __thread int g_in_nss_lookup = 0;

/* Configuration structure */
typedef struct {
    char *portal_url;
    char *server_token_file;
    char *server_token;
    time_t server_token_mtime;    /* mtime of server_token_file at last load */
    int timeout;
    int verify_ssl;
    int cache_ttl;
    char *default_shell;
    char *force_shell;            /* login shell of EVERY user resolved here */
    char *default_home_base;
    uid_t min_uid;
    uid_t max_uid;
    gid_t min_gid;                /* policy range for a server-supplied gid */
    gid_t max_gid;
    gid_t default_gid;
    char *service_accounts_file;  /* Local service accounts config */
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

    /* An all-whitespace (or empty) string leaves nothing to trim: forming
     * `str + strlen(str) - 1` here would be a pointer before the start of the
     * object, which is undefined behaviour. Same shape as str_trim() in
     * src/str_utils.c. */
    if (*str == '\0') return str;

    char *end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
        *end-- = '\0';
    }
    return str;
}

/*
 * Parse a boolean configuration value, fail-closed (issue #183).
 *
 * The old code was `strcmp(value, "true") == 0 || strcmp(value, "1") == 0`,
 * so every unrecognised value — `TRUE`, `tru`, `yes`, an empty value — mapped
 * silently to 0. For `verify_ssl` that turned OFF TLS certificate verification
 * on every NSS call to the portal: a typo downgraded the module to plaintext-
 * equivalent trust without a word.
 *
 * Unlike pam_openbastion, the NSS module cannot refuse to start on a bad
 * config: it is dlopen'd into *every* process that resolves a name (sshd,
 * sudo, systemd, ls, ...). Failing the load would make every SSO user
 * unresolvable host-wide — getpwnam() would stop returning them and no one
 * could log in — turning a one-character typo into a full lockout with no
 * interactive error to guide the operator. Availability must not be the
 * casualty of a config typo here.
 *
 * So we fail closed on the *security property* rather than on availability:
 * an unrecognised value is loudly reported to syslog and the SAFE value is
 * used (verify_ssl = 1, verification ON). The worst case is then a lookup
 * failure against an untrusted certificate, which is exactly the behaviour an
 * administrator writing `verify_ssl = true` would have asked for.
 *
 * Returns safe_value when the value is not one of the documented tokens.
 */
static int nss_parse_bool_or_safe(const char *key, const char *value,
                                  int safe_value)
{
    bool parsed;

    if (str_parse_bool_strict(value, &parsed)) {
        return parsed ? 1 : 0;
    }

    syslog(LOG_ERR, "libnss_openbastion: invalid boolean value for '%s': '%s' "
           "(expected one of true/yes/1/on or false/no/0/off); "
           "keeping the safe value '%s'",
           key, value ? value : "", safe_value ? "true" : "false");

    return safe_value;
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
 * Not held to the portal's list of approved shells (the launcher is not on
 * it), only to being a plain absolute path. Anything else, the empty string
 * included, forces DEFAULT_FORCE_SHELL: only removing the line disables it.
 */
static void finalize_force_shell(nss_llng_config_t *config)
{
    if (!config->force_shell) {
        return;
    }
    if (path_validator_is_dangerous(config->force_shell)) {
        syslog(LOG_ERR, "libnss_openbastion: force_shell '%s' is not a plain "
               "absolute path; forcing %s instead",
               config->force_shell, DEFAULT_FORCE_SHELL);
        free(config->force_shell);
        config->force_shell = strdup(DEFAULT_FORCE_SHELL);
    }
}

/*
 * Applied where an entry is served (portal, service account, disk and memory
 * caches), not where it is stored: entries cached before force_shell was set
 * come out right without purging the cache.
 */
static const char *login_shell(const char *shell)
{
    return g_config.force_shell ? g_config.force_shell : shell;
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

    /*
     * Security: open with O_NOFOLLOW to prevent symlink attacks,
     * then verify ownership and permissions via fstat to avoid TOCTOU.
     * The token file contains a Bearer token granting API access to
     * the LLNG portal - it must be protected.
     * Matches the pattern used in pam_openbastion.c for token loading.
     */
    int fd = open(config->server_token_file, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ELOOP) {
            syslog(LOG_WARNING, "libnss_openbastion: token file %s is a symlink (rejected)",
                   config->server_token_file);
        }
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        syslog(LOG_WARNING, "libnss_openbastion: cannot stat token file %s: %s",
               config->server_token_file, strerror(errno));
        close(fd);
        return -1;
    }
    if (st.st_uid != 0) {
        syslog(LOG_WARNING, "libnss_openbastion: token file %s not owned by root",
               config->server_token_file);
        close(fd);
        return -1;
    }
    if (st.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) {
        syslog(LOG_WARNING, "libnss_openbastion: token file %s has insecure permissions",
               config->server_token_file);
        close(fd);
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        syslog(LOG_WARNING, "libnss_openbastion: token file %s is not a regular file",
               config->server_token_file);
        close(fd);
        return -1;
    }

    FILE *f = fdopen(fd, "r");
    if (!f) {
        close(fd);
        return -1;
    }

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

    /* Parse the NEW token into a local first; only swap it in on success so a
     * reload that hits a transiently bad/partial file keeps the old token. */
    char *new_token = NULL;
    struct json_object *json = json_tokener_parse(buffer);
    if (json) {
        struct json_object *token_obj;
        if (json_object_object_get_ex(json, "access_token", &token_obj)) {
            const char *token = json_object_get_string(token_obj);
            if (token) new_token = strdup(token);
        }
        json_object_put(json);
    }
    /* If JSON parsing failed or no access_token found, treat as plain token */
    if (!new_token && len > 0) {
        new_token = strdup(buffer);
    }

    /* Clear sensitive token from stack buffer */
    explicit_bzero(buffer, sizeof(buffer));

    if (!new_token) return -1;          /* keep any previously loaded token */
    free(config->server_token);
    config->server_token = new_token;
    /* Remember the file's mtime so callers can detect rotation by ob-heartbeat
     * and reload, instead of caching a stale (soon-expired) access token for
     * the whole process lifetime. */
    config->server_token_mtime = st.st_mtime;
    return 0;
}

/* Reload the server token if the token file changed on disk since last load
 * (ob-heartbeat rotates it every few minutes). Long-running NSS consumers like
 * nscd otherwise keep using the first token they loaded; once it expires the
 * LLNG calls 401 and users stop resolving until the consumer is restarted. */
static void maybe_reload_server_token(void)
{
    /* The whole stat() + mtime comparison + reload runs under g_init_lock:
     * server_token_mtime is written under that lock by load_server_token(), so
     * reading it (or the token pointer) outside the lock would be a data race,
     * and a pre-lock stat() could also miss a rotation that lands between the
     * stat() and acquiring the lock. stat() is cheap enough to hold the lock. */
    pthread_mutex_lock(&g_init_lock);
    if (g_config.server_token_file) {
        struct stat st;
        if (stat(g_config.server_token_file, &st) == 0 &&
            st.st_mtime != g_config.server_token_mtime) {
            load_server_token(&g_config);
        }
    }
    pthread_mutex_unlock(&g_init_lock);
}

/* Load configuration */
static int load_config(nss_llng_config_t *config)
{
    /*
     * Security: open with O_NOFOLLOW to prevent symlink attacks,
     * then check permissions on the opened fd to avoid TOCTOU.
     * Matches the pattern used in config.c for pam_openbastion.
     */
    int fd = open(NSS_OB_CONF, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ELOOP) {
            syslog(LOG_ERR, "libnss_openbastion: config file %s is a symlink (rejected)",
                   NSS_OB_CONF);
        }
        return -1;
    }

    /* Verify file ownership and permissions */
    struct stat st;
    if (fstat(fd, &st) != 0) {
        syslog(LOG_ERR, "libnss_openbastion: cannot stat config file %s: %s",
               NSS_OB_CONF, strerror(errno));
        close(fd);
        return -1;
    }
    if (st.st_uid != NSS_CONF_TRUSTED_UID) {
        syslog(LOG_ERR, "libnss_openbastion: config file %s not owned by root", NSS_OB_CONF);
        close(fd);
        return -1;
    }
    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        syslog(LOG_ERR, "libnss_openbastion: config file %s is group/world-writable", NSS_OB_CONF);
        close(fd);
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        syslog(LOG_ERR, "libnss_openbastion: config file %s is not a regular file", NSS_OB_CONF);
        close(fd);
        return -1;
    }

    FILE *f = fdopen(fd, "r");
    if (!f) {
        close(fd);
        return -1;
    }

    /* Set defaults */
    config->timeout = 5;
    config->verify_ssl = 1;
    config->cache_ttl = CACHE_TTL;
    config->min_uid = DEFAULT_MIN_UID;
    config->max_uid = DEFAULT_MAX_UID;
    config->min_gid = DEFAULT_MIN_GID;
    config->max_gid = DEFAULT_MAX_GID;
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
            /* Safe value is 1: never silently disable TLS verification. */
            config->verify_ssl = nss_parse_bool_or_safe("verify_ssl", value, 1);
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
        else if (strcmp(key, "force_shell") == 0) {
            free(config->force_shell);
            config->force_shell = strdup(value);
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
        else if (strcmp(key, "min_gid") == 0) {
            gid_t min_gid;
            if (safe_parse_gid(value, &min_gid) == 0) {
                config->min_gid = min_gid;
            }
        }
        else if (strcmp(key, "max_gid") == 0) {
            gid_t max_gid;
            if (safe_parse_gid(value, &max_gid) == 0) {
                config->max_gid = max_gid;
            }
        }
        else if (strcmp(key, "default_gid") == 0) {
            gid_t default_gid;
            if (safe_parse_gid(value, &default_gid) == 0) {
                config->default_gid = default_gid;
            }
        }
        else if (strcmp(key, "service_accounts_file") == 0) {
            free(config->service_accounts_file);
            config->service_accounts_file = strdup(value);
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
    finalize_force_shell(config);
    if (!config->default_home_base) {
        config->default_home_base = strdup(DEFAULT_HOME_BASE);
    }
    if (!config->service_accounts_file) {
        config->service_accounts_file = strdup(DEFAULT_SERVICE_ACCOUNTS_CONF_FILE);
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

            /* Expired - remove.
             * Null BOTH pointers (not just username): the slot stays within
             * [0, count) as a hole with its old timestamp, and cache_add may
             * later evict it as the "oldest" entry, freeing username and
             * pw_buffer again. Leaving pw_buffer dangling => double free.
             * Only ever reached in a long-lived consumer whose cache fills to
             * capacity (e.g. nscd); short-lived callers exit first. */
            free(g_cache.entries[i].username);
            free(g_cache.entries[i].pw_buffer);
            g_cache.entries[i].username = NULL;
            g_cache.entries[i].pw_buffer = NULL;
            g_cache.entries[i].valid = 0;
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

            /* Expired - remove. Null pw_buffer too (see cache_find): a hole
             * left with a dangling pw_buffer is double-freed on eviction. */
            free(g_cache.entries[i].username);
            free(g_cache.entries[i].pw_buffer);
            g_cache.entries[i].username = NULL;
            g_cache.entries[i].pw_buffer = NULL;
            g_cache.entries[i].valid = 0;
            return NULL;
        }
    }
    return NULL;
}

/*
 * File-based cache for cross-process persistence.
 * Format: username:uid:gid:gecos:home:shell:timestamp
 * Per-UID file:  /var/cache/nss_llng/<uid>
 * Per-name file: /var/cache/nss_llng/byname/<username>
 */

/*
 * Validate that a username is safe to use as a single path component.
 *
 * Usernames are already validated upstream (LLNG directory and
 * query_service_account() enforce `[a-z_][a-z0-9_-]*`), but the file cache
 * turns the name into a filesystem path, so this is defense in depth against
 * path traversal and unexpected bytes.
 *
 * This deliberately enforces EXACTLY the grammar validate_username() enforces
 * in src/pam_openbastion.c (`[a-z_][a-z0-9_-]{0,31}`). The two must not drift:
 * a name this function accepts but the PAM validator refuses would be written
 * to the cache and then never invalidated by the PAM side, leaving a stale
 * record no code path can clear. Concretely that means, on top of rejecting
 * NULL/empty, '/', a leading '.' and anything outside [a-z0-9_-]:
 *   - the first character must be [a-z_] (a leading digit or '-' is refused,
 *     as it is by validate_username);
 *   - the total length is capped at 32, the same conservative POSIX-ish limit.
 *
 * Returns 0 if the name is a safe filename, -1 otherwise.
 */
#define CACHE_NAME_MAX 32
static int valid_cache_name(const char *name)
{
    if (!name || name[0] == '\0') return -1;
    if (strlen(name) > CACHE_NAME_MAX) return -1;
    /* First character: lowercase letter or underscore (rejects '.', '-', and
     * any digit) — identical to validate_username()'s first-character rule. */
    if (!((name[0] >= 'a' && name[0] <= 'z') || name[0] == '_')) return -1;
    for (const char *c = name; *c; c++) {
        unsigned char ch = (unsigned char)*c;
        if (ch == '/') return -1;
        if (!((ch >= 'a' && ch <= 'z') ||
              (ch >= '0' && ch <= '9') ||
              ch == '_' || ch == '-')) {
            return -1;
        }
    }
    return 0;
}

/*
 * Open a cache directory without creating it, and verify it is trustworthy.
 *
 * SECURITY: the cache files are consumed by privileged callers (sshd, sudo,
 * cron) which act on the uid/gid we hand back. If an unprivileged user could
 * own or write the cache directory they could plant a file claiming
 * `root:0:0::/root:/bin/bash` and obtain uid 0. We therefore refuse to use a
 * directory that is not a real directory owned by CACHE_TRUSTED_UID (root in
 * production) and not group/world writable. All later file operations are
 * performed relative to this verified fd (openat/renameat/unlinkat) so the path
 * cannot be swapped under us (symlink/TOCTOU).
 *
 * O_PATH rather than O_RDONLY: the directories are 0711 (see CACHE_DIR_MODE),
 * so an unprivileged process has search but NOT read permission on them and
 * open(O_RDONLY|O_DIRECTORY) would fail with EACCES. An O_PATH fd needs only
 * search permission and is still a valid dirfd for openat()/unlinkat() and a
 * valid target for fstat(), which is all this module does with it.
 *
 * This is the READ path: it never creates anything and stays silent on the
 * ordinary "no cache yet" outcomes (ENOENT/EACCES). An unprivileged `ls -l`
 * resolving a uid must not mkdir() anything, and must not emit a syslog
 * warning on a host where the directory does not exist — that would turn every
 * lookup into a log line.
 *
 * Returns a directory fd on success (caller must close it), -1 otherwise.
 */
static int open_cache_dir_read(const char *dir)
{
    /* Both warnings below describe a PERMANENT misconfiguration, and this
     * function runs on every getpwnam()/getpwuid() in every process on the
     * host: logging per lookup would flood syslog for as long as the condition
     * lasts. Once per process is enough to diagnose it, and the process
     * lifetime bounds the flood. The atomic exchange keeps concurrent threads
     * from each emitting a copy. */
    static int warned_symlink = 0;
    static int warned_untrusted = 0;

    int dfd = open(dir, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0) {
        /* ENOENT: no cache yet. EACCES/EPERM: not ours to read. Both are
         * normal, silent outcomes — the caller simply falls through to LLNG. */
        if (errno == ELOOP &&
            __atomic_exchange_n(&warned_symlink, 1, __ATOMIC_RELAXED) == 0) {
            syslog(LOG_WARNING,
                   "libnss_openbastion: cache directory %s is a symlink (rejected)", dir);
        }
        return -1;
    }

    struct stat st;
    if (fstat(dfd, &st) != 0) {
        close(dfd);
        return -1;
    }
    if (!S_ISDIR(st.st_mode) || st.st_uid != CACHE_TRUSTED_UID ||
        (st.st_mode & (S_IWGRP | S_IWOTH))) {
        if (__atomic_exchange_n(&warned_untrusted, 1, __ATOMIC_RELAXED) == 0) {
            syslog(LOG_WARNING,
                   "libnss_openbastion: cache directory %s is untrusted "
                   "(wrong owner or group/world-writable) - ignoring cache "
                   "(further occurrences in this process are not logged)",
                   dir);
        }
        close(dfd);
        return -1;
    }

    return dfd;
}

/*
 * Open a cache directory for writing, creating it if missing, and verify it.
 *
 * This is the WRITE path, reached only from file_cache_save*(), i.e. only after
 * a successful LLNG query, which only the cache owner (root, holder of the
 * server token) can perform. Creating the directory and warning loudly on
 * failure is appropriate here and here only.
 *
 * mkdir()'s mode is masked by the caller's umask, and an NSS module runs inside
 * arbitrary processes with arbitrary umasks, so the mode is re-asserted through
 * the verified fd afterwards. Doing it with fchmod() on the fd rather than
 * chmod() on the path keeps the whole sequence TOCTOU-free, and makes an
 * upgrade tighten a 0755 directory left behind by an earlier version.
 *
 * Returns a directory fd on success (caller must close it), -1 otherwise.
 */
static int open_cache_dir_write(const char *dir)
{
    if (mkdir(dir, CACHE_DIR_MODE) == -1 && errno != EEXIST) {
        syslog(LOG_WARNING, "libnss_openbastion: cannot create cache directory %s: %s",
               dir, strerror(errno));
        return -1;
    }

    /* O_RDONLY rather than the read path's O_PATH: only the cache owner reaches
     * this function, and it always has read permission on its own 0711
     * directory. A real (non-O_PATH) fd is what lets fchmod() below re-assert
     * the mode without ever naming a path again. */
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0) {
        if (errno == ELOOP) {
            syslog(LOG_WARNING,
                   "libnss_openbastion: cache directory %s is a symlink (rejected)", dir);
        } else {
            syslog(LOG_WARNING, "libnss_openbastion: cannot open cache directory %s: %s",
                   dir, strerror(errno));
        }
        return -1;
    }

    struct stat st;
    if (fstat(dfd, &st) != 0) {
        syslog(LOG_WARNING, "libnss_openbastion: cannot stat cache directory %s: %s",
               dir, strerror(errno));
        close(dfd);
        return -1;
    }
    if (!S_ISDIR(st.st_mode) || st.st_uid != CACHE_TRUSTED_UID ||
        (st.st_mode & (S_IWGRP | S_IWOTH))) {
        syslog(LOG_WARNING,
               "libnss_openbastion: cache directory %s is untrusted "
               "(wrong owner or group/world-writable) - ignoring cache",
               dir);
        close(dfd);
        return -1;
    }

    /* Re-assert 0711: the umask may have masked mkdir()'s mode, or the
     * directory may have been created 0755 by an earlier version (or by the
     * packaging) and an upgrade must tighten it. fchmod() on the already
     * verified fd, never chmod() on the path — no TOCTOU window. Best effort:
     * a failure here does not make the directory unusable, and the ownership
     * and writability checks above have already vouched for it. */
    if ((st.st_mode & 07777) != CACHE_DIR_MODE && fchmod(dfd, CACHE_DIR_MODE) != 0) {
        syslog(LOG_WARNING,
               "libnss_openbastion: cannot set mode %04o on cache directory %s: %s",
               (unsigned)CACHE_DIR_MODE, dir, strerror(errno));
    }

    return dfd;
}

/*
 * Split a cache line into EXACTLY 7 fields on ':'.
 *
 * Unlike strtok_r() this does NOT collapse consecutive delimiters, so an
 * empty field (e.g. an empty GECOS in "name:uid:gid::home:shell:ts") is
 * preserved as an empty string instead of shifting later fields left. The
 * line is modified in place (':' overwritten by '\0'); `out[i]` point into it.
 * A trailing newline on the last field is stripped.
 *
 * Returns 0 if and only if there are exactly 7 fields (6 separators);
 * any other count is rejected (-1) so a malformed/truncated record can never
 * be partially interpreted.
 */
static int split_cache_line(char *line, char *out[7])
{
    int n = 0;
    char *field = line;
    for (char *p = line; ; p++) {
        if (*p == ':' || *p == '\0') {
            int end = (*p == '\0');
            if (n >= 7) return -1;     /* too many fields */
            *p = '\0';
            out[n++] = field;
            if (end) break;
            field = p + 1;
        }
    }
    if (n != 7) return -1;             /* too few fields */

    /* Strip a trailing CR/LF from the last field (timestamp). */
    char *last = out[6];
    size_t llen = strlen(last);
    while (llen > 0 && (last[llen - 1] == '\n' || last[llen - 1] == '\r')) {
        last[--llen] = '\0';
    }
    return 0;
}

/*
 * Open a leaf file inside an already-verified cache dir fd and verify it is a
 * trusted, root-owned, non-group/world-writable regular file before reading.
 *
 * Returns a FILE* opened for reading on success (caller fclose()s it), or NULL
 * on any failure or trust violation. Uses openat() relative to dirfd with
 * O_NOFOLLOW so the leaf cannot be a symlink and the path cannot be swapped.
 */
static FILE *open_cache_file_verified(int dirfd, const char *leaf)
{
    int fd = openat(dirfd, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return NULL;

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return NULL;
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != CACHE_TRUSTED_UID ||
        (st.st_mode & (S_IWGRP | S_IWOTH))) {
        syslog(LOG_WARNING,
               "libnss_openbastion: cache file '%s' is untrusted "
               "(not a root-owned regular file or group/world-writable) - ignoring",
               leaf);
        close(fd);
        return NULL;
    }

    FILE *f = fdopen(fd, "r");
    if (!f) {
        close(fd);
        return NULL;
    }
    return f;
}

/* True if `s` contains a byte that would break the one-record-per-line,
 * colon-separated on-disk format. */
static int field_breaks_format(const char *s)
{
    for (const char *c = s; *c; c++) {
        if (*c == ':' || *c == '\n' || *c == '\r') return 1;
    }
    return 0;
}

/*
 * Copy at most `budget` bytes of `src` into `dst`, NUL-terminating it, with
 * ':' and CR/LF folded to a space, and stopping on a UTF-8 character boundary
 * so a trimmed value never ends mid-sequence (gecos routinely holds accented
 * display names). Returns the number of bytes written.
 *
 * `dst` must have room for budget + 1 bytes.
 */
static size_t copy_sanitized_gecos(char *dst, const char *src, size_t budget)
{
    size_t i = 0;
    while (src[i] != '\0') {
        unsigned char c = (unsigned char)src[i];
        size_t clen = 1;
        if ((c & 0xE0) == 0xC0)      clen = 2;
        else if ((c & 0xF0) == 0xE0) clen = 3;
        else if ((c & 0xF8) == 0xF0) clen = 4;

        if (i + clen > budget) break;          /* would split the character */

        /* Malformed input: stop rather than copy half a sequence. */
        for (size_t k = 1; k < clen; k++) {
            if (((unsigned char)src[i + k] & 0xC0) != 0x80) { clen = 0; break; }
        }
        if (clen == 0) break;

        for (size_t k = 0; k < clen; k++) {
            char ch = src[i + k];
            dst[i + k] = (ch == ':' || ch == '\n' || ch == '\r') ? ' ' : ch;
        }
        i += clen;
    }
    dst[i] = '\0';
    return i;
}

/*
 * Serialize a passwd record into the cache's
 * "name:uid:gid:gecos:home:shell:timestamp" line format, refusing anything a
 * reader could not parse back.
 *
 * Two shapes of record are unreadable, and both used to be written blindly by
 * the fprintf() this replaces:
 *
 *   - a field containing ':' produces 8 fields, which split_cache_line()
 *     rejects outright;
 *   - a record longer than the readers' fgets() buffer comes back truncated,
 *     so its field count is wrong.
 *
 * Either one is written by root, then fails to parse on every subsequent
 * lookup, falls back to an HTTPS round trip to LLNG, and is rewritten
 * identically by that very lookup: a permanent miss for that user plus
 * sustained LLNG load. The read side now unlinks an unparsable entry, but
 * only refusing to produce one actually breaks the loop.
 *
 * gecos is cosmetic (a display name), so it is sanitized and, if the record
 * would otherwise be too long, trimmed to fit. name/home/shell are
 * load-bearing — a truncated home directory or shell is worse than no cache
 * entry at all — so a record that cannot be written faithfully is refused and
 * the lookup simply stays uncached (correct, just slower).
 *
 * Returns the record length on success, -1 if it must not be written.
 */
static int build_cache_line(char *out, size_t outlen, const struct passwd *pw,
                            time_t now)
{
    const char *name  = pw->pw_name;
    const char *gecos = pw->pw_gecos ? pw->pw_gecos : "";
    const char *home  = pw->pw_dir   ? pw->pw_dir   : "";
    const char *shell = pw->pw_shell ? pw->pw_shell : "";

    if (field_breaks_format(name) || field_breaks_format(home) ||
        field_breaks_format(shell)) {
        syslog(LOG_WARNING,
               "libnss_openbastion: refusing to cache uid %u: name, home or "
               "shell contains a field separator", (unsigned)pw->pw_uid);
        return -1;
    }

    char uidbuf[32], gidbuf[32], tsbuf[32];
    snprintf(uidbuf, sizeof(uidbuf), "%u", (unsigned)pw->pw_uid);
    snprintf(gidbuf, sizeof(gidbuf), "%u", (unsigned)pw->pw_gid);
    snprintf(tsbuf,  sizeof(tsbuf),  "%ld", (long)now);

    /* Everything except gecos, plus the 6 separators and the newline. */
    size_t fixed = strlen(name) + strlen(uidbuf) + strlen(gidbuf) +
                   strlen(home) + strlen(shell) + strlen(tsbuf) + 6 + 1;
    if (fixed > CACHE_LINE_MAX) {
        syslog(LOG_WARNING,
               "libnss_openbastion: refusing to cache uid %u: record too long "
               "(%zu bytes without gecos, limit %d)",
               (unsigned)pw->pw_uid, fixed, CACHE_LINE_MAX);
        return -1;
    }

    char gecos_buf[CACHE_LINE_MAX + 1];
    copy_sanitized_gecos(gecos_buf, gecos, CACHE_LINE_MAX - fixed);

    int len = snprintf(out, outlen, "%s:%s:%s:%s:%s:%s:%s\n",
                       name, uidbuf, gidbuf, gecos_buf, home, shell, tsbuf);
    if (len < 0 || (size_t)len >= outlen || len > CACHE_LINE_MAX) {
        syslog(LOG_ERR, "libnss_openbastion: cache record for uid %u did not fit",
               (unsigned)pw->pw_uid);
        return -1;
    }
    return len;
}

/*
 * Atomically write a passwd cache record into an already-verified dir fd.
 *
 * Once nscd is removed, many unprivileged processes read these files
 * concurrently with no daemon serializing them. A reader must never observe a
 * half-written line, so we write to a per-pid temp leaf, fchmod it 0644 while
 * it is still private, then renameat() it into place (rename is atomic on the
 * same filesystem). On any error the temp file is removed via unlinkat().
 *
 * All operations are relative to `dirfd` (a fd returned by
 * open_cache_dir_write) using O_NOFOLLOW, which closes the symlink/TOCTOU
 * vector: the path the dir fd refers to cannot be swapped out under us.
 */
static void file_cache_write_atomic_at(int dirfd, const char *leaf,
                                       const struct passwd *pw)
{
    /* Serialize FIRST: a record that cannot be read back must not reach the
     * directory at all, not even as a temp file we would then have to clean
     * up. build_cache_line() has already logged the reason. */
    char record[CACHE_LINE_MAX + 2];
    int reclen = build_cache_line(record, sizeof(record), pw, time(NULL));
    if (reclen < 0) return;

    char tmpleaf[128];
    int tlen = snprintf(tmpleaf, sizeof(tmpleaf), ".tmp.%s.%ld",
                        leaf, (long)getpid());
    if (tlen < 0 || (size_t)tlen >= sizeof(tmpleaf)) {
        syslog(LOG_ERR, "libnss_openbastion: cache temp leaf truncated for %s", leaf);
        return;
    }

    /* Create exclusively, relative to the verified dir, never following links.
     *
     * EEXIST needs a retry rather than a bail-out. The temp leaf is keyed on
     * the pid, so a process killed between openat() and renameat() leaves
     * `.tmp.<leaf>.<pid>` behind, and the next process that the kernel hands
     * that pid to would then get EEXIST here forever: caching for that entry
     * would be permanently dead with nothing but a syslog line to say why.
     * Unlink the stale leftover and retry exactly once — the directory is
     * writable only by the cache owner (verified above), so the file we remove
     * can only be our own crash debris, never an attacker's plant, and a
     * single retry cannot loop. */
    int fd = openat(dirfd, tmpleaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0 && errno == EEXIST) {
        unlinkat(dirfd, tmpleaf, 0);
        fd = openat(dirfd, tmpleaf,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    }
    if (fd < 0) {
        syslog(LOG_WARNING, "libnss_openbastion: cannot create cache file %s: %s",
               tmpleaf, strerror(errno));
        return;
    }

    FILE *f = fdopen(fd, "w");
    if (!f) {
        syslog(LOG_WARNING, "libnss_openbastion: cannot open cache file %s: %s",
               tmpleaf, strerror(errno));
        close(fd);
        unlinkat(dirfd, tmpleaf, 0);
        return;
    }

    /* Format: username:uid:gid:gecos:home:shell:timestamp, bounded by
     * build_cache_line() above so the readers' fgets() buffer always holds a
     * whole record. */
    fwrite(record, 1, (size_t)reclen, f);

    /*
     * File mode 0644, owned by the cache owner. It deliberately stays readable
     * by unprivileged processes and this cannot be tightened to 0600:
     *
     *   - an NSS module runs *inside the calling process*, so getpwuid() and
     *     getpwnam() are served to unprivileged programs by this very code;
     *   - an unprivileged process cannot read the root-only server token, so it
     *     can never query LLNG — this file cache is its ONLY source of passwd
     *     data (which is the whole point of the name-keyed cache: without it,
     *     dropping nscd would leave every `ls -l` and `id` unresolved);
     *   - openssh's client calls getpwuid(getuid()) at startup and refuses to
     *     run when it fails ("You don't exist, go away!").
     *
     * Handing an entry to its own user (0600 owned by pw_uid) is worse, not
     * better: the owner could then rewrite their own gid/home/shell and feed
     * attacker-chosen passwd data back to root. The content is passwd-shaped
     * and is what /etc/passwd exposes world-readably on every Unix; the real
     * exposure — bulk enumeration of the SSO user directory, made sharper here
     * because the byname filenames ARE the login names — is what the 0711
     * directory stops (refs #189). Genuinely sensitive service accounts are
     * already never written here (see _nss_openbastion_getpwnam_r).
     *
     * fchmod() on the temp fd before the rename closes the TOCTOU window and
     * normalises an entry created under a restrictive umask.
     */
    /* Checked one at a time, and errno captured immediately: a single
     * short-circuited condition would report strerror(errno) from whichever
     * call happened to leave a value behind, not from the one that failed
     * (ferror() in particular sets nothing). */
    const char *failed = NULL;
    int saved_errno = 0;
    if (fchmod(fileno(f), 0644) != 0) {
        failed = "fchmod"; saved_errno = errno;
    } else if (fflush(f) != 0) {
        failed = "fflush"; saved_errno = errno;
    } else if (ferror(f)) {
        failed = "write"; saved_errno = 0;
    }
    if (failed) {
        syslog(LOG_WARNING, "libnss_openbastion: %s failed on cache file %s: %s",
               failed, tmpleaf, saved_errno ? strerror(saved_errno) : "stream error");
        fclose(f);
        unlinkat(dirfd, tmpleaf, 0);
        return;
    }
    if (fclose(f) != 0) {
        syslog(LOG_WARNING, "libnss_openbastion: error closing cache file %s: %s",
               tmpleaf, strerror(errno));
        unlinkat(dirfd, tmpleaf, 0);
        return;
    }

    /* Atomic publish, relative to the verified dir. On failure leave nothing. */
    if (renameat(dirfd, tmpleaf, dirfd, leaf) != 0) {
        syslog(LOG_WARNING, "libnss_openbastion: cannot rename %s to %s: %s",
               tmpleaf, leaf, strerror(errno));
        unlinkat(dirfd, tmpleaf, 0);
        return;
    }
}

/* Save user info to per-UID file cache (atomically, via a verified dir fd). */
static void file_cache_save(const struct passwd *pw)
{
    if (!pw || !pw->pw_name) return;

    /*
     * Only the cache owner (root) writes this cache. An NSS module is loaded
     * into *every* process that resolves a user, so without this guard an
     * unprivileged process could be made to create or rewrite entries the whole
     * host then trusts. In practice only root ever gets here anyway (the LLNG
     * query needs the root-only server token), so this costs nothing and closes
     * the door.
     */
    if (geteuid() != CACHE_TRUSTED_UID) return;

    int dirfd = open_cache_dir_write(CACHE_DIR);
    if (dirfd < 0) return;  /* never fall back to path-based writes */

    char leaf[64];
    int len = snprintf(leaf, sizeof(leaf), "%u", (unsigned)pw->pw_uid);
    if (len < 0 || (size_t)len >= sizeof(leaf)) {
        syslog(LOG_ERR, "libnss_openbastion: cache leaf truncated for uid %u",
               (unsigned)pw->pw_uid);
        close(dirfd);
        return;
    }

    file_cache_write_atomic_at(dirfd, leaf, pw);
    close(dirfd);
}

/* Save user info to per-name file cache (atomically, via a verified dir fd).
 *
 * SECURITY: service accounts must NEVER reach this function — only the
 * LLNG-success path in getpwnam_r calls it. The byname directory is unlistable
 * (0711) but its entries are 0644, so persisting service-account metadata there
 * would still leak it to any unprivileged user who guesses the account name. */
static void file_cache_save_by_name(const struct passwd *pw)
{
    if (!pw || !pw->pw_name) return;

    /* Same owner-only rule as file_cache_save(); see the comment there. */
    if (geteuid() != CACHE_TRUSTED_UID) return;

    /* Defense in depth: never turn an unexpected name into a path. */
    if (valid_cache_name(pw->pw_name) != 0) {
        syslog(LOG_WARNING,
               "libnss_openbastion: refusing to cache user with unsafe name");
        return;
    }

    /* CACHE_DIR_BYNAME lives inside CACHE_DIR, so the parent must exist (and be
     * trusted) before the subdirectory can be created. getpwnam_r happens to
     * call file_cache_save() first, but do not depend on the call order. */
    int parentfd = open_cache_dir_write(CACHE_DIR);
    if (parentfd < 0) return;
    close(parentfd);

    int dirfd = open_cache_dir_write(CACHE_DIR_BYNAME);
    if (dirfd < 0) return;  /* never fall back to path-based writes */

    file_cache_write_atomic_at(dirfd, pw->pw_name, pw);
    close(dirfd);
}

/*
 * Shared body for the file loaders: given an already-read line and the
 * verified filepath (relative leaf is `leaf`, opened via dirfd), parse it,
 * enforce TTL (unlinking expired entries via unlinkat), and populate `pw`
 * into the caller buffer. On success, `*out_created` (when non-NULL) receives
 * the timestamp the record was WRITTEN at, not the time it was read, so a
 * caller promoting the record into a shorter-lived cache can preserve its age.
 * Returns 0 on success, -1 otherwise.
 *
 * A record that cannot be parsed is unlinked, exactly like an expired one. It
 * is not a transient miss: it can never become readable, so leaving it in
 * place would mean an HTTPS round trip to LLNG on every single lookup of that
 * user, forever. build_cache_line() no longer produces such a record, but one
 * can still be left by an older version, by a truncated write, or by an
 * attempt at cache poisoning. unlinkat() only succeeds for the cache owner;
 * an unprivileged reader just misses, exactly as it did before.
 */
static int file_cache_parse_into(char *line, int dirfd, const char *leaf,
                                 struct passwd *pw, char *buffer, size_t buflen,
                                 const uid_t *want_uid, const char *want_name,
                                 time_t *out_created)
{
    char *fields[7];
    char *username_str, *uid_str, *gid_str, *gecos_str;
    char *home_str, *shell_str, *timestamp_str;
    char *endptr;
    long timestamp;
    uid_t file_uid;
    gid_t file_gid;

    /* Split into EXACTLY 7 fields without collapsing empties. */
    if (split_cache_line(line, fields) != 0) {
        goto corrupt;
    }
    username_str  = fields[0];
    uid_str       = fields[1];
    gid_str       = fields[2];
    gecos_str     = fields[3];
    home_str      = fields[4];
    shell_str     = fields[5];
    timestamp_str = fields[6];

    if (username_str[0] == '\0' || uid_str[0] == '\0' ||
        gid_str[0] == '\0' || timestamp_str[0] == '\0') {
        goto corrupt;
    }

    /* Check TTL - use strtol for safe parsing. */
    errno = 0;
    timestamp = strtol(timestamp_str, &endptr, 10);
    while (*endptr != '\0' && isspace((unsigned char)*endptr)) {
        endptr++;
    }
    if (errno != 0 || endptr == timestamp_str || *endptr != '\0') {
        goto corrupt;  /* Invalid timestamp */
    }
    if (time(NULL) - timestamp > g_config.cache_ttl) {
        /* Expired - remove file relative to the verified dir. */
        unlinkat(dirfd, leaf, 0);
        return -1;
    }

    /* Parse UID */
    if (safe_parse_uid(uid_str, &file_uid) != 0) {
        goto corrupt;
    }
    /* Parse GID */
    if (safe_parse_gid(gid_str, &file_gid) != 0) {
        goto corrupt;
    }

    /* Key consistency checks: the stored record must match what was asked.
     * A record filed under the wrong key is as unusable as an unparsable one
     * (the key IS the filename), so it is cleared the same way. */
    if (want_uid && file_uid != *want_uid) {
        goto corrupt;
    }
    if (want_name && strcmp(username_str, want_name) != 0) {
        goto corrupt;
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
    if (safe_strcpy(&p, &remaining, gecos_str) != 0) return -1;

    pw->pw_dir = p;
    if (safe_strcpy(&p, &remaining, home_str) != 0) return -1;

    pw->pw_shell = p;
    if (safe_strcpy(&p, &remaining, login_shell(shell_str)) != 0) return -1;

    if (out_created) *out_created = (time_t)timestamp;
    return 0;

corrupt:
    /* Unreadable record: clear it so the next lookup can repopulate a valid
     * one instead of retrying LLNG forever. See the function comment. */
    unlinkat(dirfd, leaf, 0);
    return -1;
}

/* Load user info from file cache by UID (via a verified dir + file fd).
 * `out_created` (optional) receives the record's own write timestamp. */
static int file_cache_load_by_uid(uid_t uid, struct passwd *pw, char *buffer,
                                  size_t buflen, time_t *out_created)
{
    int dirfd = open_cache_dir_read(CACHE_DIR);
    if (dirfd < 0) return -1;

    char leaf[64];
    int len = snprintf(leaf, sizeof(leaf), "%u", (unsigned)uid);
    if (len < 0 || (size_t)len >= sizeof(leaf)) {
        close(dirfd);
        return -1;
    }

    FILE *f = open_cache_file_verified(dirfd, leaf);
    if (!f) {
        close(dirfd);
        return -1;
    }

    char line[1024];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        close(dirfd);
        return -1;
    }
    fclose(f);

    int rc = file_cache_parse_into(line, dirfd, leaf, pw, buffer, buflen,
                                   &uid, NULL, out_created);
    close(dirfd);
    return rc;
}

/* Load user info from file cache by name (via a verified dir + file fd).
 * Mirrors file_cache_load_by_uid() but keyed on the username file under
 * CACHE_DIR_BYNAME. `out_created` (optional) receives the record's own write
 * timestamp. Returns 0 on success, -1 otherwise. */
static int file_cache_load_by_name(const char *name, struct passwd *pw,
                                   char *buffer, size_t buflen,
                                   time_t *out_created)
{
    /* Defense in depth: validate the name as a filename BEFORE building a
     * path, so a hostile or malformed lookup can never escape the cache dir. */
    if (valid_cache_name(name) != 0) {
        return -1;
    }

    int dirfd = open_cache_dir_read(CACHE_DIR_BYNAME);
    if (dirfd < 0) return -1;

    FILE *f = open_cache_file_verified(dirfd, name);
    if (!f) {
        close(dirfd);
        return -1;
    }

    char line[1024];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        close(dirfd);
        return -1;
    }
    fclose(f);

    int rc = file_cache_parse_into(line, dirfd, name, pw, buffer, buflen,
                                   NULL, name, out_created);
    close(dirfd);
    return rc;
}

/*
 * Add to the in-memory cache with an explicit creation time.
 *
 * `created` is the moment the record was obtained from LLNG, which is NOT
 * always "now": a record promoted from the on-disk cache was written at some
 * earlier T0 and must keep that age. Stamping it with time(NULL) instead
 * would let a long-lived process serve it until T0 + 2*cache_ttl after the
 * last contact with LLNG, since the file's own TTL would already have been
 * spent before the memory copy started its own. The module's stated doctrine
 * is that it never serves data older than cache_ttl, so the age travels with
 * the record.
 */
static void cache_add_at(const char *username, const struct passwd *pw,
                         int valid, time_t created)
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
    entry->timestamp = created;
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

/* Add a record obtained right now (the LLNG and service-account paths). */
static void cache_add(const char *username, const struct passwd *pw, int valid)
{
    cache_add_at(username, pw, valid, time(NULL));
}

/* Maximum response size to prevent memory exhaustion.
 * Matches the limit used in ob_client.c.
 * NSS responses are typically under 10 KB. */
#define NSS_MAX_RESPONSE_SIZE (256 * 1024)

/* CURL write callback */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    /* Security: check for integer overflow in size calculation */
    if (nmemb > 0 && size > SIZE_MAX / nmemb) {
        return 0;  /* Overflow - abort transfer */
    }

    size_t realsize = size * nmemb;
    http_response_t *resp = (http_response_t *)userp;

    /* Security: enforce maximum response size */
    if (resp->size + realsize > NSS_MAX_RESPONSE_SIZE) {
        return 0;  /* Response too large - abort transfer */
    }

    char *ptr = realloc(resp->data, resp->size + realsize + 1);
    if (!ptr) return 0;

    resp->data = ptr;
    memcpy(&resp->data[resp->size], contents, realsize);
    resp->size += realsize;
    resp->data[resp->size] = '\0';

    return realsize;
}

/* Minimal in-place trim used by the .conf parser below. */
static char *sa_trim(char *s)
{
    if (!s) return s;
    while (*s && isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) end--;
    *end = '\0';
    return s;
}

/*
 * Service-account NSS lookup.
 *
 * Resolves a local service account (ansible, backup, deploy, ...) out of
 * /etc/open-bastion/service-accounts.conf without contacting LLNG. This
 * is what unblocks sshd's pre-auth getpwnam() check for usernames that
 * only ever live in the bastion's own config (they are deliberately
 * unknown to the LLNG directory).
 *
 * Returns 0 on success, -1 on any failure (file unreadable, user not
 * found, uid/gid missing or out of range, buffer too small, etc.).
 *
 * Only looks at the [uid] and [gid] numeric fields plus gecos/shell/home
 * strings. Authentication material (key_fingerprint, sudo_*, ...) is not
 * our business here: pam_openbastion still owns auth and authorization.
 */
static int query_service_account(const char *username, struct passwd *pw,
                                  char *buffer, size_t buflen)
{
    if (!username || !*username || !pw || !buffer) return -1;

    /* Length cap (matches MAX_SERVICE_ACCOUNT_NAME in service_account.h). */
    size_t ulen = strlen(username);
    if (ulen == 0 || ulen > 32) return -1;

    /* First char must be [a-z_]; remaining [a-z0-9_-]. Matches
     * validate_username() in service_account.c and the SSHD-side
     * ob-service-account-keys helper. */
    if (!(islower((unsigned char)username[0]) || username[0] == '_')) return -1;
    for (size_t i = 1; i < ulen; i++) {
        unsigned char c = (unsigned char)username[i];
        if (!islower(c) && !isdigit(c) && c != '_' && c != '-') return -1;
    }

    const char *conf_path = g_config.service_accounts_file
                            ? g_config.service_accounts_file
                            : DEFAULT_SERVICE_ACCOUNTS_CONF_FILE;

    int fd = open(conf_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;

    /*
     * Strict guard: must be a regular root:root file with exact 0600
     * permissions. Anything more permissive is refused — unprivileged
     * callers must NOT be able to pull service-account data out of this
     * file via a misconfigured mode, and pam_openbastion applies the
     * same contract on its side.
     */
    struct stat st;
    if (fstat(fd, &st) != 0 ||
        !S_ISREG(st.st_mode) ||
        st.st_uid != 0 ||
        st.st_gid != 0 ||
        (st.st_mode & 0777) != (S_IRUSR | S_IWUSR)) {
        close(fd);
        return -1;
    }

    FILE *f = fdopen(fd, "r");
    if (!f) {
        close(fd);
        return -1;
    }

    char line[1024];
    int in_target_section = 0;
    int found = 0;
    uid_t uid = 0;
    gid_t gid = 0;
    int have_uid = 0, have_gid = 0;
    char gecos[256] = "";
    char shell[128] = "";
    char home[256] = "";

    while (fgets(line, sizeof(line), f)) {
        char *t = sa_trim(line);
        if (*t == '\0' || *t == '#' || *t == ';') continue;

        if (*t == '[') {
            char *end = strchr(t, ']');
            if (!end) continue;
            *end = '\0';
            char *name = sa_trim(t + 1);
            if (in_target_section && found) break;  /* already captured */
            in_target_section = (strcmp(name, username) == 0);
            if (in_target_section) found = 1;
            continue;
        }

        if (!in_target_section) continue;

        char *eq = strchr(t, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = sa_trim(t);
        char *val = sa_trim(eq + 1);

        if (strcmp(key, "uid") == 0) {
            char *ep;
            errno = 0;
            unsigned long v = strtoul(val, &ep, 10);
            if (errno == 0 && ep != val && *ep == '\0' && v > 0 && v <= 65534) {
                uid = (uid_t)v;
                have_uid = 1;
            }
        } else if (strcmp(key, "gid") == 0) {
            char *ep;
            errno = 0;
            unsigned long v = strtoul(val, &ep, 10);
            if (errno == 0 && ep != val && *ep == '\0' && v > 0 && v <= 65534) {
                gid = (gid_t)v;
                have_gid = 1;
            }
        } else if (strcmp(key, "gecos") == 0 || strcmp(key, "description") == 0) {
            strncpy(gecos, val, sizeof(gecos) - 1);
            gecos[sizeof(gecos) - 1] = '\0';
        } else if (strcmp(key, "shell") == 0) {
            strncpy(shell, val, sizeof(shell) - 1);
            shell[sizeof(shell) - 1] = '\0';
        } else if (strcmp(key, "home") == 0 || strcmp(key, "home_dir") == 0) {
            strncpy(home, val, sizeof(home) - 1);
            home[sizeof(home) - 1] = '\0';
        }
    }
    fclose(f);

    if (!found || !have_uid || !have_gid) return -1;

    /* Fill in sensible defaults when optional fields are unset. */
    const char *shell_to_use = (*shell) ? shell : DEFAULT_SHELL;
    char home_default[320];
    const char *home_to_use;
    if (*home) {
        home_to_use = home;
    } else {
        snprintf(home_default, sizeof(home_default), "%s/%s",
                 DEFAULT_HOME_BASE, username);
        home_to_use = home_default;
    }

    /* Populate the passwd struct using the caller-provided buffer. */
    char *p = buffer;
    size_t remaining = buflen;

    pw->pw_name = p;
    if (safe_strcpy(&p, &remaining, username) != 0) return -1;

    pw->pw_passwd = p;
    if (safe_strcpy(&p, &remaining, "x") != 0) return -1;

    pw->pw_uid = uid;
    pw->pw_gid = gid;

    pw->pw_gecos = p;
    if (safe_strcpy(&p, &remaining, gecos) != 0) return -1;

    pw->pw_dir = p;
    if (safe_strcpy(&p, &remaining, home_to_use) != 0) return -1;

    pw->pw_shell = p;
    if (safe_strcpy(&p, &remaining, login_shell(shell_to_use)) != 0) return -1;

    return 0;
}

/*
 * Is a server-supplied primary GID acceptable?
 *
 * Returns 0 when the gid may be used verbatim, -1 when it must be replaced by
 * the locally configured default_gid. See DEFAULT_MIN_GID for why the bound is
 * a group policy of its own and not the synthetic [min_uid, max_uid] range.
 *
 * gid 0 and nogroup are refused whatever the configuration says: the whole
 * point of the check is that a compromised or misconfigured portal must not be
 * able to hand every SSO user a root-equivalent primary group.
 */
static int gid_in_policy(gid_t gid, gid_t min_gid, gid_t max_gid)
{
    if (gid == 0 || gid == (gid_t)NOBODY_GID) {
        return -1;
    }
    /* Unset or nonsensical configuration: fall back to the compiled policy
     * rather than to "reject everything" (config may not have been loaded). */
    if (max_gid == 0 || min_gid > max_gid) {
        min_gid = DEFAULT_MIN_GID;
        max_gid = DEFAULT_MAX_GID;
    }
    return (gid < min_gid || gid > max_gid) ? -1 : 0;
}

/*
 * Pick the primary GID for a user out of the portal's JSON answer.
 *
 * Deliberate asymmetry with the UID: an out-of-policy uid fails the whole
 * lookup, an out-of-policy gid falls back to default_gid *with a syslog
 * warning*. The uid is identity - a wrong one means wrong file ownership and
 * wrong audit attribution, so refusing to answer is right. The gid only selects
 * an access set: failing the lookup would turn one bad pamAccessExportedVars
 * entry into NSS_STATUS_NOTFOUND for every SSO user on the host (and OpenSSH
 * refuses to start at all when getpwuid() fails - "You don't exist, go away!").
 * Degrading to a locally-chosen group is strictly safer than a fleet lockout,
 * and the function already falls back for a missing or non-integer gid.
 * The fallback is never silent, which was the substance of the review.
 */
static gid_t select_primary_gid(struct json_object *json, const char *username)
{
    struct json_object *val;

    if (!json_object_object_get_ex(json, "gid", &val) ||
        !json_object_is_type(val, json_type_int)) {
        return g_config.default_gid;
    }

    gid_t gid = (gid_t)json_object_get_int(val);
    if (gid_in_policy(gid, g_config.min_gid, g_config.max_gid) == 0) {
        return gid;
    }

    syslog(LOG_WARNING,
           "libnss_openbastion: server-supplied gid %u for user %s is outside "
           "the allowed group range [%u, %u] (or is a reserved gid) - using "
           "default_gid %u instead; adjust min_gid/max_gid in "
           "nss_openbastion.conf if this gid is legitimate",
           (unsigned)gid, username,
           (unsigned)g_config.min_gid, (unsigned)g_config.max_gid,
           (unsigned)g_config.default_gid);
    return g_config.default_gid;
}

/* force_shell overrides the portal's shell even when it is approved. */
static const char *select_login_shell(struct json_object *json)
{
    struct json_object *val;
    const char *shell_to_use = g_config.default_shell;

    if (json && json_object_object_get_ex(json, "shell", &val)) {
        const char *shell = json_object_get_string(val);
        /* Only use server-provided shell if it passes validation */
        if (shell && *shell && validate_shell(shell) == 0) {
            shell_to_use = shell;
        }
        /* Otherwise fall back to default shell */
    }
    return login_shell(shell_to_use);
}

/* Query LLNG server for user info */
static int query_llng_userinfo(const char *username, struct passwd *pw,
                                char *buffer, size_t buflen)
{
    if (!g_config.portal_url) {
        return -1;
    }

    /* Snapshot the server token under g_init_lock. A concurrent
     * maybe_reload_server_token() can free and replace g_config.server_token at
     * any time (rotation by ob-heartbeat), so reading it directly across the
     * curl network I/O below would be a use-after-free in multi-threaded NSS
     * consumers such as nscd. Copy it under the lock, release the lock before
     * any I/O, and free the copy as soon as the header is built. portal_url is
     * set once at init and never reloaded, so it needs no such guard. */
    pthread_mutex_lock(&g_init_lock);
    char *server_token = g_config.server_token ? strdup(g_config.server_token) : NULL;
    pthread_mutex_unlock(&g_init_lock);
    if (!server_token) {
        return -1;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        free(server_token);
        return -1;
    }

    /* Build URL */
    char url[512];
    snprintf(url, sizeof(url), "%s/pam/userinfo", g_config.portal_url);

    /* Build request body */
    struct json_object *req_json = json_object_new_object();
    json_object_object_add(req_json, "user", json_object_new_string(username));
    const char *req_body = json_object_to_json_string(req_json);

    /* Build Authorization header from the snapshot, then drop the token copy:
     * auth_header now holds its own bytes and server_token is no longer needed.
     *
     * The header buffer must hold the WHOLE token: load_server_token() accepts
     * up to 8191 bytes, and a JWT access token can easily exceed the ~490
     * characters that used to fit here. A silently truncated Bearer value is
     * the worst outcome - LLNG answers 401 forever, the retry-once path burns
     * a token reload on every lookup, and nothing in the logs says why. Size
     * the buffer for the largest token we will ever load, and still check the
     * snprintf() return so a future overrun fails loudly instead of 401-ing. */
    char auth_header[8256];
    int hdr_len = snprintf(auth_header, sizeof(auth_header),
                           "Authorization: Bearer %s", server_token);
    explicit_bzero(server_token, strlen(server_token));
    free(server_token);
    server_token = NULL;
    if (hdr_len < 0 || (size_t)hdr_len >= sizeof(auth_header)) {
        syslog(LOG_ERR,
               "libnss_openbastion: server token too long for Authorization header "
               "(%d bytes needed) - refusing to send a truncated credential",
               hdr_len);
        explicit_bzero(auth_header, sizeof(auth_header));
        json_object_put(req_json);
        curl_easy_cleanup(curl);
        return -1;
    }

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
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    json_object_put(req_json);
    curl_easy_cleanup(curl);
    /* auth_header held the Bearer token; curl has its own copy and is done. */
    explicit_bzero(auth_header, sizeof(auth_header));

    /* Return convention: 0 = found, 1 = authoritatively not found (HTTP 200
     * with found=false), -1 = transient/unavailable (network error, 401/403
     * from a stale token, 5xx, unparseable). Only an authoritative not-found
     * may be negatively cached; -1 must NOT poison the cache and lets the
     * caller reload the token and retry. */
    if (res != CURLE_OK || !response.data) {
        free(response.data);
        return -1;
    }
    if (http_code != 200) {
        /* 401/403 = stale/invalid token, 5xx = server, 404/other = unexpected:
         * all transient from NSS's point of view. */
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
        return 1;    /* authoritative "no such user" → safe to negative-cache */
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
            syslog(LOG_WARNING, "libnss_openbastion: server returned non-integer uid for user %s, generating UID from hash", username);
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

    /* GID - an ordinary LDAP gidNumber must survive verbatim; only genuinely
     * dangerous groups are refused. See select_primary_gid(). */
    pw->pw_gid = select_primary_gid(json, username);

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
    if (safe_strcpy(&p, &remaining, select_login_shell(json)) != 0) {
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
NSS_VISIBLE enum nss_status _nss_openbastion_getpwnam_r(const char *name,
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
        const char *shell = login_shell(cached->pw.pw_shell);
        size_t needed = strlen(cached->pw.pw_name) + strlen(cached->pw.pw_passwd) +
                       strlen(cached->pw.pw_gecos) + strlen(cached->pw.pw_dir) +
                       strlen(shell) + 16;

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
        if (safe_strcpy(&p, &remaining, shell) != 0) goto cache_overflow;

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

    /*
     * Try the local service-accounts.conf first: these users are
     * deliberately unknown to LLNG and exist only on this host. We only
     * get an answer when the calling process can read the 0600 config
     * file (typically sshd during pre-auth getpwnam()).
     *
     * Deliberately skip file_cache_save() here: the shared file cache
     * lives under /var/cache/nss_llng with a 0711 dir and 0644 entries
     * (unlistable, but an entry is readable by any process that knows the
     * key — see file_cache_write_atomic_at for why entries cannot be 0600),
     * so persisting service-account metadata there would expose it to
     * unprivileged users on the host (including the uid → name reverse
     * lookup). Keeping it in the per-process in-memory cache only is
     * sufficient for the one-shot sshd pre-auth getpwnam() path.
     */
    if (query_service_account(name, result, buffer, buflen) == 0) {
        cache_add(name, result, 1);
        g_in_nss_lookup = 0;
        return NSS_STATUS_SUCCESS;
    }

    /*
     * Try the cross-process name file cache before going to the network.
     * With no nscd in front of us this is what keeps getpwnam() answers shared
     * between processes (sshd pre-auth, login, sudo, ...) without an HTTPS round
     * trip.
     * Only LLNG-resolved users land here (service accounts are kept
     * memory-only on purpose), so a hit is safe to promote into the in-memory
     * cache exactly like the getpwuid file-cache-hit path does.
     */
    time_t file_created = 0;
    if (file_cache_load_by_name(name, result, buffer, buflen, &file_created) == 0) {
        /* Promote with the record's ORIGINAL age, not time(NULL): the memory
         * copy must expire when the on-disk record would have. */
        cache_add_at(name, result, 1, file_created);
        g_in_nss_lookup = 0;
        return NSS_STATUS_SUCCESS;
    }

    /* Pick up a token rotated by ob-heartbeat before querying, so a long-lived
     * consumer (nscd) never queries LLNG with a stale, soon-401 token. */
    maybe_reload_server_token();

    /* Query LLNG server. On a transient failure (-1) the likeliest cause is a
     * token that rotated between the reload above and the call (or a brief
     * server hiccup): force a reload and retry once. Never negative-cache a
     * transient failure. */
    int qr = query_llng_userinfo(name, result, buffer, buflen);
    if (qr < 0) {
        pthread_mutex_lock(&g_init_lock);
        load_server_token(&g_config);
        pthread_mutex_unlock(&g_init_lock);
        qr = query_llng_userinfo(name, result, buffer, buflen);
    }

    if (qr == 0) {
        /* Add to memory cache */
        cache_add(name, result, 1);
        /* Also save to file cache for cross-process lookups: by UID (getpwuid)
         * and by name (getpwnam, which has no external cache in front of it). */
        file_cache_save(result);
        file_cache_save_by_name(result);
        g_in_nss_lookup = 0;
        return NSS_STATUS_SUCCESS;
    }

    if (qr == 1) {
        /* Authoritative "no such user" — safe to negative-cache. */
        cache_add(name, NULL, 0);
        g_in_nss_lookup = 0;
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }

    /* qr < 0: transient/unavailable (network, persistent 401, 5xx). Do NOT
     * cache, and return UNAVAIL rather than NOTFOUND: NOTFOUND is an
     * authoritative "no such user" that any caller (or a caching consumer, if
     * one is ever put in front of us) may treat as final, locking the user out
     * well past the outage. UNAVAIL keeps the failure transient.
     *
     * Note the deliberate asymmetry with the file cache: an entry past
     * cache_ttl is unlinked in file_cache_parse_into() and is NOT served here
     * as a fallback. The module never answers with stale data, so an LLNG
     * outage stops resolving users roughly cache_ttl after the last successful
     * lookup. Sites that need a longer buffer raise cache_ttl; see
     * "NSS cache and LLNG outages" in doc/admin-guide.rst. */
    g_in_nss_lookup = 0;
    *errnop = EAGAIN;
    return NSS_STATUS_UNAVAIL;
}

/* NSS entry point: getpwuid_r */
NSS_VISIBLE enum nss_status _nss_openbastion_getpwuid_r(uid_t uid,
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
        const char *shell = login_shell(cached->pw.pw_shell);
        size_t needed = strlen(cached->pw.pw_name) + strlen(cached->pw.pw_passwd) +
                       strlen(cached->pw.pw_gecos) + strlen(cached->pw.pw_dir) +
                       strlen(shell) + 16;

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
        if (safe_strcpy(&p, &remaining, shell) != 0) goto uid_cache_overflow;

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
    time_t file_created = 0;
    if (file_cache_load_by_uid(uid, result, buffer, buflen, &file_created) == 0) {
        /* Also add to memory cache for future lookups in this process, with
         * the record's original age so it does not outlive the on-disk TTL. */
        cache_add_at(result->pw_name, result, 1, file_created);
        g_in_nss_lookup = 0;
        return NSS_STATUS_SUCCESS;
    }

    /* UID not found in cache - cannot query LLNG by UID */
    g_in_nss_lookup = 0;
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}

/* NSS entry point: setpwent (start enumeration) */
NSS_VISIBLE enum nss_status _nss_openbastion_setpwent(void)
{
    /* We don't support enumeration */
    return NSS_STATUS_SUCCESS;
}

/* NSS entry point: endpwent (end enumeration) */
NSS_VISIBLE enum nss_status _nss_openbastion_endpwent(void)
{
    return NSS_STATUS_SUCCESS;
}

/* NSS entry point: getpwent_r (enumerate) */
NSS_VISIBLE enum nss_status _nss_openbastion_getpwent_r(struct passwd *result,
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
