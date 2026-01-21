/*
 * str_utils.h - String utility functions for Open Bastion
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#ifndef STR_UTILS_H
#define STR_UTILS_H

#include <stdbool.h>

/*
 * Trim leading and trailing whitespace from string in-place.
 * Returns pointer to trimmed string (may be offset from input).
 * Returns NULL if input is NULL.
 */
char *str_trim(char *str);

/*
 * Parse boolean value from string.
 * Returns true for: "true", "yes", "1", "on"
 * Returns false for: "false", "no", "0", "off", NULL, and any other value
 */
bool str_parse_bool(const char *value);

/*
 * Safely extract a string from a json-c object and duplicate it.
 * Returns NULL if the object is NULL or the string is NULL.
 * Caller must free the returned string.
 *
 * Note: Requires json-c to be included before using this function.
 */
#ifdef JSON_C_VERSION
static inline char *str_json_strdup(struct json_object *obj)
{
    const char *str = json_object_get_string(obj);
    return str ? strdup(str) : NULL;
}
#endif

#endif /* STR_UTILS_H */
