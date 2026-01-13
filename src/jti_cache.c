/*
 * jti_cache.c - JWT ID (jti) cache for replay detection
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include "jti_cache.h"

/* Default configuration values */
#define DEFAULT_MAX_ENTRIES 10000
#define DEFAULT_CLEANUP_INTERVAL 60

/* Hash table entry */
typedef struct jti_entry {
    char *jti;
    time_t exp;
    struct jti_entry *next;
} jti_entry_t;

/* Hash table size (prime number for better distribution) */
#define HASH_TABLE_SIZE 1009

/* JTI cache structure */
struct jti_cache {
    jti_entry_t *buckets[HASH_TABLE_SIZE];
    size_t count;
    size_t max_entries;
    int cleanup_interval;
    time_t last_cleanup;
    char *persist_path;
    pthread_mutex_t lock;

    /* Statistics */
    size_t hits;   /* Replay detections */
    size_t misses; /* New JTIs added */
};

/* Simple hash function (djb2) */
static unsigned int hash_jti(const char *jti)
{
    unsigned int hash = 5381;
    int c;

    while ((c = (unsigned char)*jti++)) {
        hash = ((hash << 5) + hash) + c;
    }

    return hash % HASH_TABLE_SIZE;
}

/* Find entry in bucket */
static jti_entry_t *find_entry(jti_entry_t *bucket, const char *jti)
{
    while (bucket) {
        if (strcmp(bucket->jti, jti) == 0) {
            return bucket;
        }
        bucket = bucket->next;
    }
    return NULL;
}

/* Create a new entry */
static jti_entry_t *create_entry(const char *jti, time_t exp)
{
    jti_entry_t *entry = calloc(1, sizeof(jti_entry_t));
    if (!entry) return NULL;

    entry->jti = strdup(jti);
    if (!entry->jti) {
        free(entry);
        return NULL;
    }

    entry->exp = exp;
    entry->next = NULL;
    return entry;
}

/* Free an entry */
static void free_entry(jti_entry_t *entry)
{
    if (entry) {
        if (entry->jti) {
            explicit_bzero(entry->jti, strlen(entry->jti));
            free(entry->jti);
        }
        free(entry);
    }
}

/* Internal cleanup (caller must hold lock) */
static size_t cleanup_expired_locked(jti_cache_t *cache, time_t now)
{
    size_t removed = 0;

    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        jti_entry_t **pp = &cache->buckets[i];
        while (*pp) {
            if ((*pp)->exp <= now) {
                jti_entry_t *expired = *pp;
                *pp = expired->next;
                free_entry(expired);
                cache->count--;
                removed++;
            } else {
                pp = &(*pp)->next;
            }
        }
    }

    cache->last_cleanup = now;
    return removed;
}

jti_cache_t *jti_cache_create(const jti_cache_config_t *config)
{
    jti_cache_t *cache = calloc(1, sizeof(jti_cache_t));
    if (!cache) return NULL;

    /* Initialize with defaults or config values */
    cache->max_entries = config && config->max_entries > 0
                             ? config->max_entries
                             : DEFAULT_MAX_ENTRIES;
    cache->cleanup_interval = config && config->cleanup_interval > 0
                                  ? config->cleanup_interval
                                  : DEFAULT_CLEANUP_INTERVAL;

    if (config && config->persist_path) {
        cache->persist_path = strdup(config->persist_path);
        if (!cache->persist_path) {
            /* Log warning but continue - persistence is optional */
            fprintf(stderr, "jti_cache: persistence disabled (memory allocation failed)\n");
        }
        /* Note: persistence not implemented yet, reserved for future */
    }

    cache->last_cleanup = time(NULL);

    if (pthread_mutex_init(&cache->lock, NULL) != 0) {
        free(cache->persist_path);
        free(cache);
        return NULL;
    }

    return cache;
}

void jti_cache_destroy(jti_cache_t *cache)
{
    if (!cache) return;

    pthread_mutex_lock(&cache->lock);

    /* Free all entries */
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        jti_entry_t *entry = cache->buckets[i];
        while (entry) {
            jti_entry_t *next = entry->next;
            free_entry(entry);
            entry = next;
        }
        cache->buckets[i] = NULL;
    }

    pthread_mutex_unlock(&cache->lock);
    pthread_mutex_destroy(&cache->lock);

    free(cache->persist_path);
    free(cache);
}

jti_cache_result_t jti_cache_check_and_add(jti_cache_t *cache,
                                           const char *jti,
                                           time_t exp)
{
    if (!cache || !jti || !*jti) {
        return JTI_CACHE_INVALID_PARAM;
    }

    time_t now = time(NULL);

    /* Don't cache already expired JTIs */
    if (exp <= now) {
        return JTI_CACHE_OK;
    }

    pthread_mutex_lock(&cache->lock);

    /* Periodic cleanup - handle clock adjustments */
    if (now < cache->last_cleanup ||
        now - cache->last_cleanup >= (time_t)cache->cleanup_interval) {
        cleanup_expired_locked(cache, now);
    }

    unsigned int idx = hash_jti(jti);
    jti_entry_t *existing = find_entry(cache->buckets[idx], jti);

    if (existing) {
        /* Check if the existing entry has expired */
        if (existing->exp <= now) {
            /* Entry expired, update it */
            existing->exp = exp;
            cache->misses++;
            pthread_mutex_unlock(&cache->lock);
            return JTI_CACHE_OK;
        }

        /* Replay detected! */
        cache->hits++;
        pthread_mutex_unlock(&cache->lock);
        return JTI_CACHE_REPLAY_DETECTED;
    }

    /* Check if cache is full */
    if (cache->count >= cache->max_entries) {
        /* Try to cleanup expired entries */
        cleanup_expired_locked(cache, now);

        if (cache->count >= cache->max_entries) {
            pthread_mutex_unlock(&cache->lock);
            return JTI_CACHE_FULL;
        }
    }

    /* Add new entry */
    jti_entry_t *entry = create_entry(jti, exp);
    if (!entry) {
        pthread_mutex_unlock(&cache->lock);
        return JTI_CACHE_INTERNAL_ERROR;
    }

    entry->next = cache->buckets[idx];
    cache->buckets[idx] = entry;
    cache->count++;
    cache->misses++;

    pthread_mutex_unlock(&cache->lock);
    return JTI_CACHE_OK;
}

bool jti_cache_contains(jti_cache_t *cache, const char *jti)
{
    if (!cache || !jti || !*jti) {
        return false;
    }

    time_t now = time(NULL);

    pthread_mutex_lock(&cache->lock);

    unsigned int idx = hash_jti(jti);
    jti_entry_t *entry = find_entry(cache->buckets[idx], jti);

    bool found = entry && entry->exp > now;

    pthread_mutex_unlock(&cache->lock);
    return found;
}

size_t jti_cache_cleanup(jti_cache_t *cache)
{
    if (!cache) return 0;

    time_t now = time(NULL);

    pthread_mutex_lock(&cache->lock);
    size_t removed = cleanup_expired_locked(cache, now);
    pthread_mutex_unlock(&cache->lock);

    return removed;
}

void jti_cache_stats(jti_cache_t *cache,
                     size_t *count,
                     size_t *max_entries,
                     size_t *hits,
                     size_t *misses)
{
    if (!cache) {
        if (count) *count = 0;
        if (max_entries) *max_entries = 0;
        if (hits) *hits = 0;
        if (misses) *misses = 0;
        return;
    }

    pthread_mutex_lock(&cache->lock);

    if (count) *count = cache->count;
    if (max_entries) *max_entries = cache->max_entries;
    if (hits) *hits = cache->hits;
    if (misses) *misses = cache->misses;

    pthread_mutex_unlock(&cache->lock);
}

const char *jti_cache_result_str(jti_cache_result_t result)
{
    switch (result) {
    case JTI_CACHE_OK:
        return "OK";
    case JTI_CACHE_REPLAY_DETECTED:
        return "Replay detected";
    case JTI_CACHE_FULL:
        return "Cache full";
    case JTI_CACHE_INVALID_PARAM:
        return "Invalid parameter";
    case JTI_CACHE_INTERNAL_ERROR:
        return "Internal error";
    default:
        return "Unknown error";
    }
}
