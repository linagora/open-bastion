ob-sign-request
===============

Synopsis
--------

::

   ob-sign-request --method METHOD --path PATH [--config FILE]

The request body is read from standard input. The headers are written
to standard output, one per line.

Description
-----------

LemonLDAP::NG's ``pam-access`` plugin verifies a signature on every
``/pam/`` endpoint it serves, and its ``pamAccessRequestSigningMode`` =
``required`` refuses any call that carries none. ``ob-sign-request`` is
how the shell callers on this side sign: :doc:`ob-heartbeat(8)
<ob-heartbeat>`, :doc:`ob-bastion-id(1) <ob-bastion-id>`,
:doc:`ob-enroll(8) <ob-enroll>` and ``ob-session-monitor``. They reach
it through ``/usr/lib/open-bastion/ob-sign-lib.sh``, not directly.

It reads ``request_signing_secret`` from
``/etc/open-bastion/openbastion.conf``, computes

::

   HMAC-SHA256(secret, "timestamp.nonce.METHOD.PATH.body")

and prints ``X-Timestamp``, ``X-Nonce`` and ``X-Signature-256``. The C
clients (the PAM module and :doc:`ob-cert-daemon(8) <ob-cert-daemon>`)
compute the same bytes in-process; this program exists only because the
shell callers cannot.

Why not OpenSSL
---------------

``openssl dgst -sha256 -hmac`` takes the HMAC key as a command-line
argument, and OpenSSL offers no form that reads it from a file or the
environment. ``/proc/<pid>/cmdline`` is world-readable, so on a bastion
— a host whose purpose is to give other people a shell — signing that
way would publish the fleet-wide signing secret to any user who polls,
every time :doc:`ob-heartbeat(8) <ob-heartbeat>` runs. A secret an
attacker can read is a signature an attacker can forge.

Here the secret is read from a root-only file and never leaves the
process, and the body arrives on standard input — which matters as
well: :doc:`ob-heartbeat(8) <ob-heartbeat>` signs a body containing
this host's ``refresh_token``. What reaches standard output is the MAC
and its inputs, which are about to go over the wire anyway.

Options
-------

.. option:: --method METHOD

   The HTTP method, uppercase. The portal signs ``uc(method)``, so
   anything else is refused rather than signed into a mismatch.

.. option:: --path PATH

   The absolute request path, with no scheme, host or query string —
   the portal strips the query before hashing, so a path containing one
   is refused.

.. option:: --config FILE

   The configuration file to read the secret from. Defaults to
   ``/etc/open-bastion/openbastion.conf``. It must be a regular file,
   unreadable by group and other, and owned by root.

Exit status
-----------

``0``
   The three headers were printed.

``3``
   No ``request_signing_secret`` is configured. Nothing is printed, and
   the caller should send the request unsigned: the portal's ``off``
   and ``optional`` modes accept it. This is the state to be in while
   the secret is rolled out.

``1``
   Anything else, with a diagnostic on standard error.

Files
-----

``/etc/open-bastion/openbastion.conf``
   Read for ``request_signing_secret``. The value is taken literally: a
   '#' in it is part of the secret, not the start of a comment.

Security
--------

The signature is defence in depth on top of TLS, not a substitute for
it. Do not relax ``verify_ssl`` because of it.

Turning the portal to ``required`` before every host holds the secret
takes the fleet down — not at the moment of the change, but hours
later, as access tokens expire and ``/pam/heartbeat`` stops renewing
them. The order is: ``optional``, roll the secret out, confirm every
host signs, then ``required``.

See also
--------

:doc:`openbastion.conf(5) <openbastion.conf>`,
:doc:`ob-heartbeat(8) <ob-heartbeat>`,
:doc:`ob-bastion-id(1) <ob-bastion-id>`,
:doc:`ob-enroll(8) <ob-enroll>`,
:doc:`ob-cert-daemon(8) <ob-cert-daemon>`

Author
------

Xavier Guimard <xguimard@linagora.com>
