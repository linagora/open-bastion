/*
 * test_nss_cache.c - Regression test for the in-memory LRU cache of the
 * NSS module (libnss_openbastion.c).
 *
 * Reproduces the double-free that crashed nscd (SIGABRT,
 * "double free or corruption (out)") roughly every 4-5h on bastions:
 *
 *   - cache_find()/cache_find_by_uid() free an expired entry's pw_buffer
 *     but (before the fix) leave the pointer dangling, only nulling username.
 *   - The slot stays within [0, count) as a hole with its old (oldest)
 *     timestamp.
 *   - cache_add(), once the cache is full, evicts the oldest entry and frees
 *     username + pw_buffer again => double free of the dangling pw_buffer.
 *
 * This only fires in a long-lived consumer whose cache reaches capacity
 * (nscd); short-lived callers (ls/id/sudo/sshd) exit first, which is why it
 * went unnoticed.
 *
 * We include the module source directly to drive the static cache helpers
 * (init_cache/cache_add/cache_find) against the real g_cache/g_config state.
 */

#include "../nss/libnss_openbastion.c"

#include <assert.h>

static struct passwd make_pw(const char *name, uid_t uid)
{
    struct passwd pw;
    pw.pw_name = (char *)name;
    pw.pw_passwd = (char *)"x";
    pw.pw_uid = uid;
    pw.pw_gid = uid;
    pw.pw_gecos = (char *)"";
    pw.pw_dir = (char *)"/home/x";
    pw.pw_shell = (char *)"/bin/bash";
    return pw;
}

/*
 * Fill the cache to capacity, expire+find one entry (creating a dangling
 * pw_buffer hole in the buggy code), then force an eviction that lands on
 * that hole. The buggy code double-frees here and aborts; the fixed code
 * survives because pw_buffer was nulled.
 */
static int test_expire_then_evict_no_double_free(void)
{
    if (init_cache() != 0) {
        fprintf(stderr, "init_cache failed\n");
        return 0;
    }
    /* Long TTL so entries don't expire on their own; we backdate manually. */
    g_config.cache_ttl = 1000000;

    char name[32];
    for (size_t i = 0; i < g_cache.capacity; i++) {
        snprintf(name, sizeof(name), "user%zu", i);
        struct passwd pw = make_pw(name, (uid_t)(100000 + i));
        cache_add(name, &pw, 1);
    }
    assert(g_cache.count == g_cache.capacity);

    /* Make slot 0 both expired and the oldest entry. */
    g_cache.entries[0].timestamp = time(NULL) - (g_config.cache_ttl + 100);

    /* Look it up: expired => freed. Buggy code leaves pw_buffer dangling. */
    cache_entry_t *e = cache_find("user0");
    assert(e == NULL);

    /* Adding one more triggers eviction of the oldest = slot 0. The buggy
     * code frees the dangling pw_buffer a second time -> SIGABRT here. */
    struct passwd extra = make_pw("newcomer", 200000);
    cache_add("newcomer", &extra, 1);

    /* If we reach this line, no double free occurred. */
    return 1;
}

/* Same scenario through the UID lookup path. */
static int test_expire_by_uid_then_evict_no_double_free(void)
{
    if (init_cache() != 0) {
        fprintf(stderr, "init_cache failed\n");
        return 0;
    }
    g_config.cache_ttl = 1000000;

    char name[32];
    for (size_t i = 0; i < g_cache.capacity; i++) {
        snprintf(name, sizeof(name), "u%zu", i);
        struct passwd pw = make_pw(name, (uid_t)(300000 + i));
        cache_add(name, &pw, 1);
    }
    assert(g_cache.count == g_cache.capacity);

    g_cache.entries[0].timestamp = time(NULL) - (g_config.cache_ttl + 100);

    cache_entry_t *e = cache_find_by_uid(300000);
    assert(e == NULL);

    struct passwd extra = make_pw("uidnewcomer", 400000);
    cache_add("uidnewcomer", &extra, 1);

    return 1;
}

int main(void)
{
    int ok = 1;

    printf("  Testing expire_then_evict_no_double_free... ");
    if (test_expire_then_evict_no_double_free()) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
        ok = 0;
    }

    printf("  Testing expire_by_uid_then_evict_no_double_free... ");
    if (test_expire_by_uid_then_evict_no_double_free()) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
        ok = 0;
    }

    printf("%s\n", ok ? "All NSS cache tests passed" : "NSS cache tests FAILED");
    return ok ? 0 : 1;
}
