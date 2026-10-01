ob-cert-request
===============

Synopsis
--------

::

   ob-cert-request [socket-path]

Description
-----------

``ob-cert-request`` is the unprivileged half of the bastion
hop-certificate flow. It is invoked by :doc:`ob-ssh(1) <ob-ssh>` and
:doc:`ob-scp(1) <ob-scp>` (running as the logged-in bastion user); you do
not normally run it by hand.

It connects to the local Unix socket served by
:doc:`ob-cert-daemon(8) <ob-cert-daemon>` (default
``/run/open-bastion/cert.sock``, or ``socket-path`` if given), forwards
the request read from standard input, and writes the LLNG
``/pam/bastion-cert`` JSON response to standard output.

It carries no privilege and holds no secret: the daemon derives the
certificate's user from the connection's ``SO_PEERCRED``
(kernel-verified), so the request cannot be used to mint a certificate
for another user.

Protocol
--------

Standard input is a newline-delimited request:

::

   line 1: target_host
   line 2: target_group   (may be empty)
   line 3: voucher        (from $LLNG_BASTION_VOUCHER)
   line 4: ephemeral SSH public key

Standard output is the raw LLNG JSON response.

Exit status
-----------

``0``
   The response was relayed.

``1``
   Could not reach the socket, or an I/O error occurred.

``2``
   Usage or socket-setup error.

Files
-----

``/run/open-bastion/cert.sock``
   The bastion certificate socket (``ob-cert.socket``).

See also
--------

:doc:`ob-cert-daemon(8) <ob-cert-daemon>`,
:doc:`ob-ssh(1) <ob-ssh>`,
:doc:`ob-scp(1) <ob-scp>`

Author
------

Linagora
