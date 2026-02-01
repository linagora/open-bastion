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

/*
 * Convert bytes to hex string using lookup table.
 * out must have space for at least (len * 2 + 1) bytes.
 */
static inline void str_bytes_to_hex(const unsigned char *bytes, size_t len,
                                     char *out)
{
    static const char hex_table[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hex_table[bytes[i] >> 4];
        out[i * 2 + 1] = hex_table[bytes[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

/*
 * Base64url decode (RFC 4648 section 5).
 * input: base64url-encoded string
 * input_len: length of input (0 = use strlen)
 * out_len: output parameter for decoded length
 * Returns malloc'd buffer on success, NULL on failure.
 * Caller must free the returned buffer.
 */
unsigned char *str_base64url_decode(const char *input, size_t input_len, size_t *out_len);

#endif /* STR_UTILS_H */
