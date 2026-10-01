ob-fp-submit
============

Synopsis
--------

::

   ob-fp-submit < request

Description
-----------

The unprivileged half of the SSH fingerprint spool, in the same shape as
:doc:`ob-cert-request(1) <ob-cert-request>` is for
:doc:`ob-cert-daemon(8) <ob-cert-daemon>`.

The ``AuthorizedPrincipalsCommand`` helper (``ob-ssh-principals``) runs
as the unprivileged ``AuthorizedPrincipalsCommandUser`` and, since issue
#249, no longer writes ``/run/open-bastion/ssh-fp/`` itself. It pipes the
fingerprint here instead, and this connects to
``/run/open-bastion/ssh-fp.sock`` where
:doc:`ob-fp-daemon(8) <ob-fp-daemon>` writes the drop as root.

There is deliberately nothing to configure and no identity to assert. The
daemon takes the depositing uid from ``SO_PEERCRED`` and derives the sshd
anchor from this process's own ``/proc`` ancestry, so a caller cannot
name the session it is writing for. That is why running this binary is
harmless, and why it is **not** setuid and needs no privilege of its own.

Input
-----

Three newline-delimited lines on standard input:

**line 1**
   the fingerprint, ``SHA256:<base64>``

**line 2**
   the key algorithm (sshd's ``%t``, may be empty)

**line 3**
   the key blob (sshd's ``%k``, may be empty)

Exit status
-----------

``0``
   the daemon accepted the deposit

``1``
   the daemon refused it, or the socket is unreachable

``2``
   usage or local error

Callers must treat every non-zero status the same way and **carry on.**
Losing the binding removes an additional check; it must never fail an
authentication that sshd has already accepted. ``pam_openbastion``
reports the missing drop itself (issue #192).

Environment
-----------

``OB_FP_SOCKET``
   Overrides the socket path. For the test suite only — on a real host the
   daemon's socket is the one systemd created, and pointing this elsewhere
   simply means no drop is written.

See also
--------

:doc:`ob-fp-daemon(8) <ob-fp-daemon>`,
:doc:`ob-cert-request(1) <ob-cert-request>`,
:doc:`ob-bastion-setup(8) <ob-bastion-setup>`,
:doc:`ob-backend-setup(8) <ob-bastion-setup>`

Author
------

Linagora
