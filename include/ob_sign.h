/*
 * ob_sign.h - Request signing for the LLNG /pam/<endpoint> endpoints
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 *
 * One wire format, one implementation. The portal (LLNG pam-access,
 * _checkRequestSignature) verifies every /pam/<endpoint> call the same way, so every
 * caller on this side has to produce the bytes the same way:
 *
 *     message = <timestamp>.<nonce>.<method>.<path>.<body>
 *     HMAC-SHA256, key = the raw bytes of request_signing_secret
 *
 *     X-Timestamp      unix seconds, decimal
 *     X-Nonce          <unix_ms>-<uuid-v4>
 *     X-Signature-256  sha256=<64 lowercase hex>
 *
 * The four '.' separators are always present: a bodyless request signs the
 * empty string, so the message still ends with a trailing '.'. <path> carries
 * no scheme, host or query string, and <body> is the raw bytes as sent.
 *
 * This header exists because the fleet has several callers of /pam/<endpoint>
 * -- the PAM and NSS modules, ob-cert-daemon, and the shell scripts through
 * ob-sign-request -- and pamAccessRequestSigningMode=required refuses any of
 * them that gets it wrong (#247, #332).
 */

#ifndef OB_SIGN_H
#define OB_SIGN_H

#include <stddef.h>

/* Sizes a caller must provide. Both include the terminating NUL. */
#define OB_SIGN_NONCE_SIZE     80   /* <unix_ms>-<uuid-v4>, generously */
#define OB_SIGN_SIGNATURE_SIZE 65   /* 64 hex characters */

/*
 * Generate a nonce: "<timestamp_ms>-<uuid v4>", from OpenSSL's CSPRNG.
 *
 * The nonce is the portal's replay key, and it is covered by the signature
 * (see ob_sign_compute) so it cannot be swapped for a fresh value on a
 * replayed request. `size` must be at least OB_SIGN_NONCE_SIZE; on a smaller
 * buffer the nonce is set empty, which ob_sign_compute then refuses.
 */
void ob_sign_generate_nonce(char *nonce, size_t size);

/*
 * HMAC-SHA256 over <timestamp>.<nonce>.<method>.<path>.<body>, hex-encoded.
 *
 * `body` may be NULL, which signs the empty string. `sig_size` must be at
 * least OB_SIGN_SIGNATURE_SIZE. On any failure `signature` is set empty --
 * callers must treat an empty signature as "do not send", never as "send
 * unsigned", since the portal reads a partially signed request as malformed.
 */
void ob_sign_compute(const char *secret,
                     long timestamp,
                     const char *nonce,
                     const char *method,
                     const char *path,
                     const char *body,
                     char *signature,
                     size_t sig_size);

/*
 * Read request_signing_secret out of an openbastion.conf-style file.
 *
 * Returns 0 and sets *secret (caller frees) when the key is present and
 * non-empty, 1 when the file parsed but has no secret in it -- signing is
 * optional, so that is not an error -- and -1 when the file cannot be read or
 * is not adequately protected.
 *
 * Protection means: a regular file, not a symlink, unreadable by group and
 * other, owned by root or by the effective uid. The euid clause is what makes
 * this testable without root; in production every caller runs as root, where
 * it says exactly "owned by root" (see check_file_permissions_fd in config.c,
 * which is the same policy for the PAM module's own load).
 *
 * The value is taken the way config.c takes an opaque secret: everything after
 * the first '=', trimmed, minus at most one layer of matching quotes, and no
 * inline-comment stripping -- '#' is an ordinary character in a generated
 * secret (see key_holds_opaque_secret in config.c).
 */
int ob_sign_load_secret(const char *conf_path, char **secret);

/*
 * Read request_signing_secret and cert_pin out of an openbastion.conf-style
 * file in one pass, for the portal clients that do not go through config.c:
 * the NSS module and ob-cert-daemon (#332). Either output may be NULL to skip
 * that key.
 *
 * Returns 0 when the file was read -- each requested value is then set
 * (caller frees) or left NULL when the key is absent or empty -- and -1, with
 * both outputs NULL, when the file cannot be read, is not adequately
 * protected (same policy as ob_sign_load_secret), or carries one of the two
 * keys on a line too long to read whole. The pin is returned as written: check
 * it with str_cert_pin_valid() before handing it to libcurl.
 */
int ob_sign_load_settings(const char *conf_path, char **secret, char **cert_pin);

#endif /* OB_SIGN_H */
