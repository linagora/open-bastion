ob-cert-daemon
==============

Synopsis
--------

::

   ob-cert-daemon

Not run directly. Activated per-connection by :manpage:`systemd(1)`
through ``ob-cert.socket`` (``/run/open-bastion/cert.sock``).

Description
-----------

``ob-cert-daemon`` mints the short-lived, LLNG-signed certificate that
:doc:`ob-ssh(1) <ob-ssh>` and :doc:`ob-scp(1) <ob-scp>` use to hop from
the bastion to a backend. It replaces the former
``sudo ob-bastion-cert-helper`` bridge: minting a machine certificate is
no longer coupled to the interactive ``sudo`` policy (which, under
maximum security, requires an LLNG token and therefore broke
non-interactive hops).

It is socket-activated (one short-lived instance per connection, run as
root) and reached through the unprivileged
:doc:`ob-cert-request(1) <ob-cert-request>` client. For each connection
it:

1. derives the calling user from the connection's ``SO_PEERCRED``
   (kernel-verified, never taken from the request body), so a caller can
   only mint a certificate for itself;
2. reads the bastion's root-only server token (which never leaves the
   process);
3. POSTs the request to LLNG ``/pam/bastion-cert`` with that token as
   Bearer;
4. relays the LLNG JSON response back over the socket.

Protocol
--------

The connected socket carries a newline-delimited request:

::

   line 1: target_host
   line 2: target_group   (empty -> "default")
   line 3: voucher
   line 4: ephemeral SSH public key

The user is NOT part of the request; it is the SO_PEERCRED identity. The
response is the raw LLNG JSON (certificate, or a structured error).

Security
--------

The certificate's user is the kernel-verified connecting uid, and LLNG
binds the voucher to the ``(bastion_id, user)`` pair, so a stolen voucher
is useless and a caller cannot mint for another user. The socket is
world-connectable (``mode 0666``): connecting alone grants nothing
without a valid voucher. The server token never leaves the daemon. No
``sudo``, no setuid. Request inputs are length-bounded and a read/write
timeout drops a stalled peer.

Files
-----

``/run/open-bastion/cert.sock``
   The activation socket (see ``ob-cert.socket``).

``/etc/open-bastion/openbastion.conf``
   Source of ``portal_url`` and ``verify_ssl``.

``/etc/open-bastion/ssh-proxy.conf``
   Optional overrides (``PORTAL_URL``, ``SERVER_TOKEN_FILE``,
   ``VERIFY_SSL``, ``TIMEOUT``); honoured only when root-owned and not
   group/world-writable.

``/var/lib/open-bastion/token``
   The bastion's server token (root-only).

See also
--------

:doc:`openbastion.conf(5) <openbastion.conf>`,
:doc:`ob-cert-request(1) <ob-cert-request>`,
:doc:`ob-ssh(1) <ob-ssh>`,
:doc:`ob-scp(1) <ob-scp>`,
:doc:`ob-bastion-setup(8) <ob-bastion-setup>`
