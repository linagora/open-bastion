ob-client-jwt
=============

Synopsis
--------

::

   ob-client-jwt --client-id ID --audience URL < secret

Description
-----------

Reads an OIDC client secret on standard input and prints a
``client_secret_jwt`` client assertion (RFC 7523) for it on standard
output, signed HMAC-SHA256.

:doc:`ob-enroll(8) <ob-enroll>` used to build this assertion in shell,
ending in

::

   openssl dgst -sha256 -hmac "$client_secret" -binary

:manpage:`openssl(1)` takes the HMAC key as a command-line argument and
offers no form that reads it from a file, a descriptor or the
environment. ``/proc/<pid>/cmdline`` is world-readable, so for the
lifetime of that process the host's OIDC client secret was readable by
any local user — the same defect issue #247 fixed for the request-signing
secret, and the same reason :doc:`ob-sign-request(8) <ob-sign-request>`
exists.

It was not a one-shot exposure. The call sits inside the device-grant
polling loop: one assertion every ``POLL_INTERVAL`` seconds for up to the
device-code lifetime, of the order of sixty times over five minutes —
during exactly the interval when an operator has been sent to a browser
to approve the grant.

Where the secret comes from
~~~~~~~~~~~~~~~~~~~~~~~~~~~

:doc:`ob-sign-request(8) <ob-sign-request>` reads its secret from
``openbastion.conf``, which is right for it: the request-signing secret
is only ever configured there. This helper deliberately does not, because
:doc:`ob-enroll(8) <ob-enroll>` may hold the client secret from any of
three places — ``OB_CLIENT_SECRET`` in the environment,
``--client-secret`` on the command line, or ``client_secret`` in a
configuration file that on a first enrolment does not exist yet.

Re-deriving that precedence here would mean keeping two implementations
of it in agreement forever. So this helper does not decide:
:doc:`ob-enroll(8) <ob-enroll>` already knows which secret it is using
and hands it over on standard input. A pipe has no ``/proc`` entry and no
name in the filesystem.

``--client-id`` and ``--audience`` are public. Both are echoed verbatim
in the assertion's own payload, which is base64url of plaintext and goes
on the wire; only the key has to be kept off ``argv``.

Options
-------

.. option:: --client-id ID

   The OIDC client identifier. Becomes the ``iss`` and ``sub`` claims.

.. option:: --audience URL

   The endpoint the assertion is for, normally
   ``<portal>/oauth2/token``. Becomes the ``aud`` claim.

Input
-----

The client secret on standard input. Every trailing CR and LF is
stripped, so ``printf``, ``echo`` and a secret read from a CRLF file all
produce the same key; nothing else is stripped, and leading or interior
spaces are part of the secret. A secret containing a NUL byte is refused
rather than silently truncated, since the HMAC is keyed by string length.

Exit status
-----------

``0``
   the assertion was printed

``1``
   signing failed, or the secret could not be read

``2``
   usage error

See also
--------

:doc:`ob-sign-request(8) <ob-sign-request>`,
:doc:`ob-enroll(8) <ob-enroll>`,
:doc:`ob-heartbeat(8) <ob-heartbeat>`

Author
------

Xavier Guimard <xguimard@linagora.com>
