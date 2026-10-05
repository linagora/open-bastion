ob-ssh
======

Synopsis
--------

::

   ob-ssh [OPTIONS] [user@]backend [port] [command ...]

Description
-----------

``ob-ssh`` runs on a bastion server, invoked by a user already
authenticated to the bastion, to reach a backend WITHOUT any SSH key of
their own on the bastion and without agent forwarding. The bastion
mints a short-lived, LemonLDAP::NG-signed SSH certificate for this user
and re-originates the SSH connection to the backend with it.

This replaces the former JWT-over-SendEnv transport (which never worked,
because SendEnv/AcceptEnv do not populate the PAM environment the
backend reads). See :doc:`/references/bastion-cert-vouching`, shipped as
``/usr/share/doc/open-bastion-doc/html/references/bastion-cert-vouching.html``
in the HTML documentation.

Flow
~~~~

1. Reads the per-session bastion voucher from ``$LLNG_BASTION_VOUCHER``
   (set by ``pam_openbastion`` at bastion login; it proves THIS user
   connected to THIS bastion).
2. Generates an ephemeral keypair in tmpfs (the private key never leaves
   the bastion and is wiped on exit).
3. POSTs the ephemeral public key plus the voucher to LemonLDAP::NG
   ``/pam/bastion-cert`` and receives a short-lived user certificate
   (principal = user, pinned to the bastion's source address, bastion_id
   in the key-id).
4. Connects to the backend with that certificate.

With no trailing *command* an interactive shell is opened on the
backend. When a *command* is given it is run non-interactively (no pty
is requested, mirroring :manpage:`ssh(1)` *host command*) and its output
is returned verbatim, so it pipes and captures cleanly.

Modes
~~~~~

**Direct mode**
   Called with a target host argument (the common case), optionally
   followed by a command to run on the backend.

**ForceCommand mode**
   When ``SSH_ORIGINAL_COMMAND`` is set (used as an sshd ForceCommand).

**Interactive mode**
   When neither a target argument nor SSH_ORIGINAL_COMMAND is set,
   prompts for one.

Options
-------

.. option:: -c, --config FILE

   Use alternate configuration file (default:
   /etc/open-bastion/ssh-proxy.conf)

.. option:: -p, --port PORT

   Backend SSH port; overrides the legacy positional *port* argument.

.. option:: -l, --login USER

   Backend login user; overrides ``$USER`` for a bare (user-less) host.

.. option:: -o OPTION

   Pass an :manpage:`ssh(1)` ``-o`` option through to the backend
   connection (e.g. ``-o ServerAliveInterval=30``). May be repeated;
   appended after the config's ``SSH_OPTIONS``.

.. option:: --

   End option parsing; the host and command follow.

.. option:: -d, --debug

   Enable debug output to stderr

.. option:: -h, --help

   Show help message and exit

.. option:: -V, --version

   Show version and exit

Configuration
-------------

The command reads configuration from
``/etc/open-bastion/ssh-proxy.conf`` (written by
:doc:`ob-bastion-setup(8) <ob-bastion-setup>`):

::

   # LemonLDAP::NG portal URL (required)
   PORTAL_URL="https://auth.example.com"

   # Server token file (from ob-enroll); root-only by design
   SERVER_TOKEN_FILE="/var/lib/open-bastion/token"

   # Target server group for backends
   TARGET_GROUP="default"

   # HTTP timeout (seconds)
   TIMEOUT=10

   # Verify SSL certificates
   VERIFY_SSL=true

   # Additional SSH options (passed through to ssh)
   SSH_OPTIONS=""

   # Enable debug output
   DEBUG=false

The server token is never read by ``ob-ssh``: the single privileged call
is delegated to :doc:`ob-cert-daemon(8) <ob-cert-daemon>`, a
socket-activated service reached through the unprivileged
:doc:`ob-cert-request(1) <ob-cert-request>` client, which reads
``SERVER_TOKEN_FILE`` from this same configuration file. The daemon
derives the certificate's user from the connection's SO_PEERCRED, so it
always mints for the connecting user. No sudo, no setuid, and root takes
the same path as everyone else.

Host key policy
~~~~~~~~~~~~~~~

The bastion→backend hop uses ``StrictHostKeyChecking=accept-new`` unless
``SSH_OPTIONS`` sets the option itself. That is trust-on-first-use: the
first connection to a backend accepts the host key it presents, later
ones are pinned by ``known_hosts``. To refuse unknown keys instead,
pre-seed the host keys over a trusted channel and set

::

   SSH_OPTIONS="-o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/etc/ssh/ssh_known_hosts"

``SSH_OPTIONS`` is passed to ``ssh`` before the default and ``ssh``
keeps the first value given for an option, so this wins.

TTY handling
------------

When standard input is a terminal, ``ob-ssh`` forces a remote pty
(``ssh -tt``) so the bastion-side terminal is put into raw mode: input
is echoed once (by the backend), and Ctrl-C or a failing command act on
the remote shell rather than tearing down the connector. When stdin is
not a terminal (piped input), no pty is requested (``ssh -T``).

Security
--------

The vouched certificate provides cryptographic proof that the user
authenticated to this bastion. It is short-lived, carries the user as
its only principal, and is pinned to the bastion's source address, so it
cannot be replayed from elsewhere. The backend enforces acceptance via
``TrustedUserCAKeys``, an ``AuthorizedPrincipalsCommand`` that checks
the bastion_id in the key-id against its allow-list, and the
certificate's source-address restriction. No ``AcceptEnv`` is required.

Files
-----

``/etc/open-bastion/ssh-proxy.conf``
   Configuration file (world-readable; contains no secret)

``/usr/lib/open-bastion/ob-cert-lib.sh``
   Shared cert-vouching library sourced by ob-ssh and ob-scp

``/var/lib/open-bastion/token``
   Server authentication token (root-only, from ob-enroll)

Environment
-----------

``LLNG_BASTION_VOUCHER``
   The per-session voucher set by pam_openbastion at bastion login.

``SSH_ORIGINAL_COMMAND``
   Used in ForceCommand mode to determine the target host.

``OB_CERT_LIB``
   Override the path to the shared cert-vouching library (testing).

Exit status
-----------

``0``
   Success

``1``
   Error (configuration, network, authentication, or no valid voucher)

Otherwise the exit status of the underlying :manpage:`ssh(1)`.

Examples
--------

::

   # Connect from the bastion to a backend as the same user:
   $ ob-ssh backend-web01

   # Different remote user and port:
   $ ob-ssh admin@backend-web01 2222

   # Run a single command on the backend (non-interactive, output captured):
   $ ob-ssh backend-web01 uptime
   $ ob-ssh admin@backend-web01 -p 2222 -- systemctl status nginx

   # From a workstation through an ssh_config "RemoteCommand ob-ssh ..." entry,
   # override RemoteCommand to append the backend command (ssh forbids combining a
   # command-line command with a configured RemoteCommand):
   $ ssh -o RemoteCommand="ob-ssh 10.0.0.5 ls -la" backend1

See also
--------

:doc:`ob-scp(1) <ob-scp>`,
:doc:`ob-sftp(1) <ob-sftp>`,
:doc:`ob-cert-request(1) <ob-cert-request>`,
:doc:`ob-cert-daemon(8) <ob-cert-daemon>`,
:doc:`ob-bastion-setup(8) <ob-bastion-setup>`,
:doc:`ob-backend-setup(8) <ob-bastion-setup>`,
:doc:`ob-enroll(8) <ob-enroll>`,
:manpage:`ssh(1)`,
:manpage:`sshd_config(5)`
