ob-fp-daemon
============

Synopsis
--------

::

   ob-fp-daemon

Not run directly. Activated per-deposit by :manpage:`systemd(1)` through
``ob-fp.socket`` (``/run/open-bastion/ssh-fp.sock``).

Description
-----------

``pam_openbastion`` needs to know which SSH key authenticated a session,
and OpenSSH does not export ``SSH_USER_AUTH`` to the PAM environment
during ``pam_acct_mgmt``. The ``AuthorizedPrincipalsCommand`` helper
(``ob-ssh-principals``) therefore records the fingerprint out of band, in
``/run/open-bastion/ssh-fp/<anchor>.fp``, where ``<anchor>`` is the pid of
the per-connection ``sshd-session`` monitor.

sshd requires ``AuthorizedPrincipalsCommandUser`` to be unprivileged, so
before issue #249 that helper wrote the spool itself and the directory was
``0700 nobody``. The integrity of the whole fingerprint binding then
rested on ``nobody``: a shared, low-trust account that several daemons run
under. Code execution as that user could read every deposited fingerprint
and write a well-formed drop at any pid.

``ob-fp-daemon`` takes the deposit instead. It runs as root, keeps the
spool ``0700 root``, and writes the drops itself, so nothing unprivileged
can create, list or read anything there.

What the socket checks
----------------------

The depositing user
~~~~~~~~~~~~~~~~~~~

``SO_PEERCRED``, which the kernel fills in at :manpage:`connect(2)` time
and no client can forge, must be the owner of the listening socket — or
root.

That owner comes from ``SocketUser`` in ``ob-fp.socket``, which ships as
``nobody`` to match the ``AuthorizedPrincipalsCommandUser`` both setup
scripts configure. There is no configuration key for it: the socket unit
is the single place the answer is written, so an administrator who changes
the principals user and overrides ``SocketUser`` in a drop-in gets a
daemon that follows rather than one that locks them out.

With ``SocketMode=0600`` the kernel already refuses anyone else, so this
check is defence in depth — it keeps holding if a drop-in loosens the
mode.

The session, which is derived and not received
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is the check that carries the weight. The anchor pid is derived from
the **depositing process's own** ``/proc`` ancestry — it is never taken
from the request. A client therefore cannot name the session it deposits
for.

To place a drop on a given anchor you must already be a descendant of that
anchor, and the anchor must be a live ``sshd-session`` monitor whose
**real** uid is root. The effective uid is not used: sshd switches it to
the helper user while the principals command runs, which is when the
deposit happens. sshd puts exactly one unprivileged thing in that
position: the principals helper. A daemon started from init descends from
pid 1, not from an ``sshd-session``, and cannot re-parent itself into one;
a logged-in user's shell is under an ``sshd-session`` but runs as the
user, which the uid check rejects.

Forging a binding therefore requires code execution as the helper user
*inside the target connection's own process tree* — strictly smaller than
"code execution as nobody anywhere on the host", which was enough before
#249.

Protocol
--------

Three newline-delimited lines on the connected socket, at most 20480
bytes:

**line 1**
   the fingerprint, ``SHA256:<base64>`` (required)

**line 2**
   the key algorithm, sshd's ``%t`` (may be empty)

**line 3**
   the key blob, sshd's ``%k`` in base64 (may be empty)

The reply is one line, ``OK`` or ``ERR <reason>``.

A malformed algorithm or blob costs the ``.key`` metadata drop but never
the fingerprint: the ``.fp`` drop is what the LLNG binding needs, and
losing it would remove a security control over a cosmetic input error.

Files
-----

``/run/open-bastion/ssh-fp.sock``
   The activation socket. ``0600``, owned by the principals helper user.

``/run/open-bastion/ssh-fp/``
   The spool. ``0700 root:root``; the daemon re-asserts owner and mode on
   every deposit, so a host upgraded from the pre-#249 ``nobody``-owned
   directory is migrated on first use rather than left on the old trust
   root while appearing fixed.

Diagnostics
-----------

Every refusal is logged to ``LOG_AUTHPRIV`` and returned to the caller,
which sshd writes to the authentication log. If the socket is not enabled
the helper cannot deposit at all: logins still succeed, but with no
fingerprint binding — ``pam_openbastion`` reports the missing drop (issue
#192), and :doc:`ob-bastion-setup(8) <ob-bastion-setup>` or
:doc:`ob-backend-setup(8) <ob-bastion-setup>` enables ``ob-fp.socket``
when re-run.

See also
--------

:doc:`ob-fp-submit(8) <ob-fp-submit>`,
:doc:`ob-cert-daemon(8) <ob-cert-daemon>`,
:doc:`ob-bastion-setup(8) <ob-bastion-setup>`,
:doc:`ob-backend-setup(8) <ob-bastion-setup>`,
``pam_openbastion``

Author
------

Linagora
