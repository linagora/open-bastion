ob-verify-response
==================

Synopsis
--------

::

   ob-verify-response verify --jwks FILE --issuer ISS --endpoint NAME
                             --nonce NONCE --http-status CODE
                             --body-file FILE [--audience CLIENT_ID]
                             [--token-file FILE] [--jwks-out FILE]
                             [--skew SECONDS]
   ob-verify-response check-jwks [--anchor] [--quiet] FILE|-
   ob-verify-response nonce

Description
-----------

Asked with ``Accept: application/ob-pam-response+jwt`` and an
``X-Nonce``, LemonLDAP::NG's ``pam-access`` plugin answers its ``/pam/``
endpoints with a compact JWS bound to the request instead of plain JSON
(see "Signed answers" in the security reference). The PAM and NSS modules
check those answers in-process; ``ob-verify-response`` is the same check
for the shell callers — :doc:`ob-heartbeat(8) <ob-heartbeat>`,
:doc:`ob-session-monitor(8) <ob-session-monitor>` and
:doc:`ob-bastion-id(1) <ob-bastion-id>`. They reach it through
``ob_pam_post`` in ``/usr/lib/open-bastion/ob-sign-lib.sh``, which reads
``response_signing``, ``sso_jwks_file``, ``sso_issuer`` and ``client_id``
from :doc:`openbastion.conf(5) <openbastion.conf>`, not directly.

Nothing secret is passed on the command line: the request body, which
for :doc:`ob-heartbeat(8) <ob-heartbeat>` carries the host's
``refresh_token``, is read from a file (a pipe, through the shell's
process substitution), and the answer, which carries the new access
token, from standard input. The arguments are the issuer, the
``client_id``, the endpoint, the nonce sent and the status received: all
of them are on the wire or published by the portal anyway.

Commands
--------

``verify``
   Verify the signed answer read on standard input (or ``--token-file``)
   and print its ``resp`` object, the plain JSON answer, on standard
   output. The answer is refused unless: its ``typ`` is
   ``ob-pam-response+jwt``; its ``kid`` names a key of the JWKS that suits
   its ``alg`` (``none`` and ``HS*`` are never accepted); the signature
   verifies; ``iss``, ``endpoint``, ``req_nonce`` and ``req_sha256`` (the
   SHA-256 of the body file) match; it is not expired; its ``aud``, when
   present, is the ``--audience``; and its ``http_status`` is the one
   given. Trailing whitespace after the token is ignored.

``check-jwks``
   Parse a JWKS (``-`` reads standard input) and report the keys the
   verifier can use: RSA of 2048 bits or more, P-256/P-384/P-521, Ed25519,
   with ``use`` ``sig`` or none. ``oct`` keys and unsupported curves are
   skipped. Prints::

      keys=N
      key=<thumbprint> <kid>       (one line per usable key)

   ``N`` counts the usable keys. Each ``<thumbprint>`` is the RFC 7638
   JWK thumbprint of one key (SHA-256 of its required members, base64url):
   it names the key material, whatever the ``kid``, so two key sets can
   be compared key by key. The lines are sorted by thumbprint.

   This is not the JWKS fingerprint. That one is the SHA-256 of the
   document in canonical form, the value ``ob-builder``, the
   ``PORTAL-CHECKLIST``, :doc:`ob-bastion-setup(8) <ob-bastion-setup>`
   (``--sso-jwks-sha256``) and :doc:`ob-heartbeat(8) <ob-heartbeat>`'s
   rotation log all use::

      jq -S -c . sso-jwks.json | sha256sum

   or, for the portal's current one,
   ``curl --tlsv1.3 -s '<portal>/oauth2/jwks?client_id=<client_id>' | jq -S -c . | sha256sum``.

``nonce``
   Print a fresh ``X-Nonce`` (``<unix_ms>-<uuid v4>``, from OpenSSL's
   random generator), the format :doc:`ob-sign-request(8) <ob-sign-request>`
   uses. The shell callers use it when no ``request_signing_secret`` is
   configured; otherwise the request signature's own nonce serves both.

Options of verify
-----------------

.. option:: --jwks FILE

   The trust anchor, normally ``sso_jwks_file``
   (``/var/lib/open-bastion/jwks/sso-jwks.json``). It is checked as the
   PAM module checks it: a regular file, not a symlink, owned by root (or
   the caller), writable by nobody else.

.. option:: --issuer ISS

   The expected ``iss``: ``sso_issuer``, by default ``portal_url`` without
   its trailing ``/``.

.. option:: --audience CLIENT_ID

   The expected ``aud``, the host's ``client_id``. Without it (or empty)
   an answer that names any client is refused.

.. option:: --endpoint NAME

   ``authorize``, ``verify``, ``userinfo``, ``whoami`` or ``heartbeat``.

.. option:: --nonce NONCE

   The ``X-Nonce`` the request carried.

.. option:: --http-status CODE

   The HTTP status received; it must equal the signed ``http_status``.

.. option:: --body-file FILE

   The request body exactly as sent (``/dev/null`` for none). ``-`` reads
   standard input, in which case the answer must come from
   ``--token-file``.

.. option:: --token-file FILE

   Read the answer from FILE instead of standard input.

.. option:: --jwks-out FILE

   Write the ``jwks`` claim (compact JSON, mode ``0600``) to FILE — only
   when the answer verified **and** carries an ``aud``, i.e. with exit
   status 0. FILE is left untouched otherwise.
   :doc:`ob-heartbeat(8) <ob-heartbeat>` uses it to follow a key rotation.

.. option:: --skew SECONDS

   Clock skew tolerated on ``exp`` and ``iat``. Default: 60.

Options of check-jwks
---------------------

.. option:: --anchor

   Also apply the trust-anchor checks of ``--jwks`` (ownership, mode, no
   symlink), as the modules will when they load the file.

.. option:: --quiet

   Print nothing; only the exit status tells.

Exit status
-----------

``verify``:

``0``
   Verified, and the answer names this client (``aud``). ``resp`` was
   printed.

``4``
   Verified, but the answer carries no ``aud``: the portal gives such
   answers before it has identified the caller, and anyone can obtain one
   for a nonce and body of their choice. ``resp`` was printed; the caller
   must only take it as a refusal. ``ob_pam_post`` refuses any such answer
   with a ``2xx`` status.

``1``
   The answer does not verify. A diagnostic is on standard error, nothing
   on standard output.

``3``
   The JWKS file is missing, unsafe, or holds no usable key.

``2``
   Usage error.

``check-jwks``: ``0`` at least one usable key, ``1`` none (or the file
cannot be read, or fails ``--anchor``), ``2`` usage error.

``nonce``: ``0``, or ``1`` when no random nonce could be generated.

Nothing is written to standard error on success, so callers may capture
both streams together.

Examples
--------

What ``ob_pam_post`` runs for a heartbeat::

   printf '%s' "$answer" |
   ob-verify-response verify --jwks /var/lib/open-bastion/jwks/sso-jwks.json \
       --issuer https://auth.example.com --audience my-client \
       --endpoint heartbeat --nonce "$nonce" --http-status 200 \
       --body-file <(printf '%s' "$body") --jwks-out "$claim"

Check a JWKS before installing it, list its keys, and show its
fingerprint::

   ob-verify-response check-jwks /tmp/sso-jwks.json
   jq -S -c . /tmp/sso-jwks.json | sha256sum

See also
--------

:doc:`openbastion.conf(5) <openbastion.conf>`,
:doc:`ob-heartbeat(8) <ob-heartbeat>`,
:doc:`ob-session-monitor(8) <ob-session-monitor>`,
:doc:`ob-bastion-id(1) <ob-bastion-id>`,
:doc:`ob-sign-request(8) <ob-sign-request>`
