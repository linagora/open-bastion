/*
 * str_utils.c - String utility functions for Open Bastion
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "str_utils.h"

char *str_trim(char *str)
{
    if (!str) return NULL;

    /* Trim leading whitespace */
    while (isspace((unsigned char)*str)) str++;

    if (*str == '\0') return str;

    /* Trim trailing whitespace */
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';

    return str;
}

bool str_parse_bool_strict(const char *value, bool *out)
{
    if (!value || !out) return false;

    if (strcmp(value, "true") == 0 ||
        strcmp(value, "yes") == 0 ||
        strcmp(value, "1") == 0 ||
        strcmp(value, "on") == 0) {
        *out = true;
        return true;
    }

    if (strcmp(value, "false") == 0 ||
        strcmp(value, "no") == 0 ||
        strcmp(value, "0") == 0 ||
        strcmp(value, "off") == 0) {
        *out = false;
        return true;
    }

    /* Unrecognised (empty string, "TRUE", "tru", ...): not a boolean. */
    return false;
}

bool str_parse_bool(const char *value)
{
    bool result = false;

    /* Legacy lenient behaviour: anything unrecognised is false. */
    (void)str_parse_bool_strict(value, &result);

    return result;
}

unsigned char *str_base64url_decode(const char *input, size_t input_len, size_t *out_len)
{
    if (!input || !out_len) return NULL;

    if (input_len == 0) input_len = strlen(input);
    if (input_len == 0 || input_len > 8192) return NULL;

    static const unsigned char b64_table[256] = {
        ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,  ['F'] = 5,
        ['G'] = 6,  ['H'] = 7,  ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11,
        ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17,
        ['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
        ['Y'] = 24, ['Z'] = 25, ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29,
        ['e'] = 30, ['f'] = 31, ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35,
        ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41,
        ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47,
        ['w'] = 48, ['x'] = 49, ['y'] = 50, ['z'] = 51, ['0'] = 52, ['1'] = 53,
        ['2'] = 54, ['3'] = 55, ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59,
        ['8'] = 60, ['9'] = 61, ['-'] = 62, ['_'] = 63,
    };

    /* Strip padding if present */
    size_t padding = 0;
    while (input_len > 0 && input[input_len - 1] == '=') {
        padding++;
        input_len--;
    }

    size_t out_size = ((input_len + 3) / 4) * 3;
    if (out_size < padding) return NULL;
    out_size -= padding;

    unsigned char *out = malloc(out_size + 1);
    if (!out) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < input_len; i += 4) {
        unsigned int val = 0;
        size_t k;
        for (k = 0; k < 4 && i + k < input_len; k++) {
            unsigned char c = (unsigned char)input[i + k];
            if (c > 127 || (b64_table[c] == 0 && c != 'A')) {
                free(out);
                return NULL;
            }
            val = (val << 6) | b64_table[c];
        }
        for (; k < 4; k++) {
            val <<= 6;
        }

        size_t remaining = out_size - j;
        if (remaining >= 1) out[j++] = (val >> 16) & 0xff;
        if (remaining >= 2) out[j++] = (val >> 8) & 0xff;
        if (remaining >= 3) out[j++] = val & 0xff;
    }

    out[j] = '\0';
    *out_len = j;
    return out;
}

/*
 * Security: Validate certificate pin format (fixes #47)
 * Valid formats:
 * - sha256//base64hash (44 chars of base64 after sha256//)
 * - Path to DER or PEM file (starts with / or .)
 * Multiple pins can be separated by ';'
 * Returns 1 if valid, 0 if invalid
 *
 * Here rather than in ob_client.c because every portal client checks it: the
 * PAM module (config.c and ob_client.c), the NSS module and ob-cert-daemon
 * (#332).
 */
int str_cert_pin_valid(const char *pin)
{
    if (!pin || !*pin) {
        return 0;
    }

    /* Work on a copy to handle multiple pins */
    char *pin_copy = strdup(pin);
    if (!pin_copy) {
        return 0;
    }

    int valid = 1;
    char *saveptr = NULL;
    char *token = strtok_r(pin_copy, ";", &saveptr);

    while (token && valid) {
        /* Skip leading whitespace */
        while (*token == ' ') token++;

        /* Strip trailing whitespace */
        size_t token_len = strlen(token);
        while (token_len > 0 && token[token_len - 1] == ' ') {
            token[token_len - 1] = '\0';
            token_len--;
        }

        if (strncmp(token, "sha256//", 8) == 0) {
            /* SHA256 hash format: "sha256//" followed by base64 of 32 bytes
             * Standard base64 encoding of 32 bytes is 44 characters (with padding);
             * we also accept 43-character encodings when the trailing padding is omitted.
             */
            const char *hash = token + 8;
            size_t len = strlen(hash);
            /* Accept standard base64 length for 32 bytes (44 chars) and the
             * no-padding variant (43 chars). Only the standard base64 alphabet
             * (+ and /, not - or _) is allowed by the character check below.
             */
            if (len < 43 || len > 44) {
                valid = 0;
            } else {
                /* Validate base64 characters */
                for (size_t i = 0; i < len && valid; i++) {
                    char c = hash[i];
                    if (!((c >= 'A' && c <= 'Z') ||
                          (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') ||
                          c == '+' || c == '/' || c == '=')) {
                        valid = 0;
                    }
                }
            }
        } else if (token[0] == '/' || token[0] == '.') {
            /* File path - check if it looks like a valid path */
            /* Basic check: not empty after prefix, no control characters */
            if (strlen(token) < 2) {
                valid = 0;
            } else {
                for (const char *p = token; *p && valid; p++) {
                    if ((unsigned char)*p < 32) {
                        valid = 0;
                    }
                }
            }
        } else {
            /* Unknown format */
            valid = 0;
        }

        token = strtok_r(NULL, ";", &saveptr);
    }

    free(pin_copy);
    return valid;
}
