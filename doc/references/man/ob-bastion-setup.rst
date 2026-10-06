ob-bastion-setup
================

Synopsis
--------

::

   ob-bastion-setup --portal URL [OPTIONS]
   ob-backend-setup --portal URL [OPTIONS]
   ob-backend-setup --allowed-bastions IDS [--yes] [--dry-run]
   ob-standalone-setup --portal URL [OPTIONS]

Description
-----------

One command configures the three Open Bastion node roles.
``ob-backend-setup`` and ``ob-standalone-setup`` are symbolic links to
``ob-bastion-setup``: the name the command is invoked under chooses the
default role, and ``--node-role`` overrides it. Every role-specific step
follows the role in effect once all options are read, so
``ob-bastion-setup --node-role backend`` configures exactly what
``ob-backend-setup`` does.

**bastion**
   (default of ``ob-bastion-setup``) The SSH entry point. Accepts SSH
   certificates signed by the LemonLDAP::NG CA, records every session
   through :doc:`ob-session-recorder(8) <ob-session-recorder>` (sshd
   ``ForceCommand``), allows agent forwarding, and enables the
   ``ob-cert.socket`` through which :doc:`ob-ssh(1) <ob-ssh>` obtains the
   hop certificate for a backend.

**standalone**
   (default of ``ob-standalone-setup``) A host that users log in to
   directly, with no backend behind it. It gets the bastion stack
   unchanged; only the role recorded in ``openbastion.conf`` and reported
   by :doc:`ob-heartbeat(8) <ob-heartbeat>` differs.

**backend**
   (default of ``ob-backend-setup``) A server reached through a bastion.
   Accepts only certificates vouched by a bastion (the certificate key-id
   names it) and, when a list is configured, only by the bastions in
   ``/etc/open-bastion/allowed_bastions``. Creates Unix accounts on first
   login from LemonLDAP::NG attributes, authorizes sudo through
   LemonLDAP::NG rules, and records no session (the bastion in front of it
   does). Agent forwarding is disabled.

All roles configure PAM for authorization by LemonLDAP::NG
(certificate-aware, authentication refused on the password path), the NSS
module for user and group resolution, and enroll the server with
LemonLDAP::NG unless a token is provided or already present.

Options
-------

Common options
~~~~~~~~~~~~~~

.. option:: -p, --portal URL

   LemonLDAP::NG portal URL. Required, except to update the allowed
   bastions of a configured backend (see `Updating the allowed
   bastions`_).

.. option:: -g, --server-group NAME

   Server group name; must match a group defined in LemonLDAP::NG.
   Prompted for if omitted; required with ``--yes``.

.. option:: --node-role ROLE

   Role to configure: ``bastion``, ``standalone`` or ``backend``.
   Defaults to the role of the command name. Written to
   ``openbastion.conf`` and reported to the SSO.

.. option:: -t, --token-file FILE

   Read the server token from ``FILE`` (``-`` for standard input) instead
   of enrolling.

.. option:: -c, --client-id ID

   OIDC client_id used for enrollment. Prompted for if omitted; required
   with ``--yes``.

.. option:: -S, --client-secret-file FILE

   Read the OIDC client_secret from ``FILE`` (``-`` for standard input).
   The ``OB_CLIENT_SECRET`` environment variable is an alternative.
   Needed for a confidential client.

.. option:: -y, --yes

   Non-interactive mode. Requires ``--token-file`` unless a server token
   already exists, in which case it is reused.

.. option:: -k, --insecure

   Skip TLS certificate verification. Required for an ``http://`` portal:
   without it the setup refuses such a portal, which the PAM module would
   reject with TLS verification on. Test setups only.

.. option:: --max-security

   SSO-signed certificates only, sudo only with a LemonLDAP::NG temporary
   token, key revocation list refreshed periodically by
   :doc:`ob-krl-refresh(8) <ob-krl-refresh>` from
   ``ob-krl-refresh.timer``, every 30 minutes by default.

.. option:: --krl-refresh-interval minutes

   With ``--max-security``: refresh the key revocation list every
   *minutes* (1 to 60) instead, through the drop-in
   ``/etc/systemd/system/ob-krl-refresh.timer.d/schedule.conf``. Without
   it, a new run keeps the schedule the host already has, including the
   interval of a 0.6 ``/etc/cron.d/open-bastion-krl`` job, which the run
   replaces with the timer.

.. option:: --enable-service-keys

   Write the sshd drop-in that serves service-account keys from
   ``/etc/open-bastion/service-accounts.d/`` (AuthorizedKeysCommand, plus
   ExposeAuthInfo). Off by default; a run without it removes a drop-in it
   generated earlier.

.. option:: --enable-sudo-fresh-otp

   Require a fresh LemonLDAP::NG token on every sudo for SSO users
   (``Defaults:%open-bastion-sudo timestamp_timeout=0``). Off by default.

.. option:: --enable-hardening

   Apply session containment hardening (logind KillUserProcesses, nproc
   limit, at/cron allow-lists, atd masked). Off by default.

.. option:: --enable-audit-trace

   Enable the primary audit trace based on :manpage:`auditd(8)`: installs
   ``/etc/audit/rules.d/open-bastion.rules``, enables
   ``ob-audit-rotate.timer`` (daily rotation; it replaces the
   ``/etc/cron.daily/open-bastion-audit-rotate`` script of 0.6), loads
   the rules and restarts auditd. ``/etc/audit/auditd.conf`` is not
   modified. Requires the auditd package. Off by default.

.. option:: -n, --dry-run

   Show what would be done without making changes.

.. option:: -h, --help

   Show the help for the role in effect and exit.

.. option:: -V, --version

   Show version and exit.

Bastion and standalone options
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Refused when the role is ``backend``.

.. option:: --disable-session-recorder

   Do not configure the session recorder and do not force it through
   ``ForceCommand``. Recording is on by default; use this only when
   sessions are recorded by other means.

Backend options
~~~~~~~~~~~~~~~

Refused when the role is ``bastion`` or ``standalone``.

.. option:: --allowed-bastions IDS

   Comma- or space-separated list of the bastion ids (as printed by
   :doc:`ob-bastion-id(1) <ob-bastion-id>` on each bastion) allowed to
   hop to this backend. Prompted for if omitted in an interactive run. An
   empty list accepts a hop from any bastion enrolled in the project.
   Without ``--portal``, it replaces the list of a backend already set
   up and changes nothing else (see `Updating the allowed bastions`_).

.. option:: --allow-any-bastion

   Answer that prompt with "any bastion" up front. Non-interactive runs
   already default to it.

.. option:: --no-sudo

   Do not configure sudo through LemonLDAP::NG. Refused together with
   ``--max-security``, which always replaces the sudo PAM stack.

.. option:: --no-create-user

   Do not create Unix accounts automatically.

Configuration
-------------

The script works in three phases, so that a failed enrollment never
leaves the host locked down:

1. Inert preparation, rolled back on failure: downloads the SSH CA public
   key (/ssh/ca), installs the principals helper (and, on a backend, the
   allowed-bastions list), writes ``openbastion.conf``, and on a bastion
   configures the session recorder.
2. Checks the portal and enrolls the server.
3. Lockdown: sshd drop-in, PAM for SSH, sudo (backend: LLNG rules; Mode
   E: token only), ob-ssh configuration (bastion), NSS, optional
   hardening and audit trace, then restarts sshd.

Changing a host's role
----------------------

Running the command under the other role switches the host between the
bastion stack (bastion, standalone) and a backend. The other role's sshd
drop-in is removed (backed up), and the principals helper is replaced
only at the end of the run, right before sshd is restarted; until then
either helper denies a login made through the other role's sshd
configuration. A backend disables ``ob-cert.socket`` and
``ob-record.socket`` and removes ``/etc/open-bastion/ssh-proxy.conf``. A
bastion leaves a backend's LLNG sudo stack (``/etc/pam.d/sudo``,
``/etc/pam.d/sudo-i``, ``/etc/sudoers.d/open-bastion``) in place and
warns about it. On an sshd without ``/etc/ssh/sshd_config.d``, where the
configuration is a block appended to ``sshd_config``, a switch is
refused: remove the old block first.

Invoked under a name other than the three above, the command configures a
bastion unless ``--node-role`` is given, and a ``--yes`` run then
requires ``--node-role``.

Updating the allowed bastions
-----------------------------

On a backend already set up (by this command, the self-extracting
installer or Ansible), ``ob-backend-setup --allowed-bastions IDS``
without ``--portal`` replaces ``/etc/open-bastion/allowed_bastions`` and
nothing else: no questionnaire, no enrollment, and sshd, PAM and
``openbastion.conf`` are left as they are. The principals helper reads
the file at every hop, so the new list applies from the next connection,
without restarting sshd.

The ids given replace the whole list; they are not added to it, so name
every bastion that must keep hopping to the host. They are checked as in
a full setup. ``--allowed-bastions ""`` asks for ids as a full setup
does, and keeps the list empty only on an explicit answer; with
``--yes``, or as ``--allow-any-bastion``, the empty list is written
without asking. The
previous list is printed and the file is copied to a
``/var/backup/open-bastion-setup-*`` directory; a list identical to the
current one is not rewritten. ``--yes`` and ``--dry-run`` are the only
other options that act on the update; ``--insecure`` is accepted and has
no effect, since the update contacts no portal. Any other option belongs
to the full setup, which takes ``--portal``.

The update is refused on a host whose sshd is not configured as an Open
Bastion backend, or that has no ``/etc/open-bastion/openbastion.conf``:
set it up with ``--portal`` first.

User creation
-------------

On a backend, when an authorized user does not exist locally,
``pam_openbastion`` creates the account from LemonLDAP::NG attributes
during the PAM session: username from the certificate principal, GECOS,
shell and group memberships from LemonLDAP::NG, home directory created.

Files
-----

``/etc/ssh/open-bastion_ca.pub``
   SSH CA public key downloaded from LemonLDAP::NG.

``/etc/ssh/sshd_config.d/00-open-bastion-bastion.conf``
   sshd configuration of a bastion or standalone host.

``/etc/ssh/sshd_config.d/00-open-bastion-backend.conf``
   sshd configuration of a backend. Writing either drop-in removes the
   other.

``/usr/local/sbin/ob-ssh-principals``
   AuthorizedPrincipalsCommand helper (bastion or backend variant).

``/etc/open-bastion/allowed_bastions``
   Backend only: bastion ids allowed to hop to this host.

``/etc/pam.d/sshd``
   PAM configuration for SSH.

``/etc/pam.d/sudo``, ``/etc/pam.d/sudo-i``, ``/etc/sudoers.d/open-bastion``
   sudo configuration (backend, or any role under maximum security).

``/etc/open-bastion/openbastion.conf``
   PAM module configuration, including ``node_role``.

``/etc/open-bastion/nss_openbastion.conf``, ``/etc/nsswitch.conf``
   NSS module configuration. On a bastion or standalone host that records
   sessions it sets ``force_shell = /usr/sbin/ob-login-shell``: sshd runs
   the ``ForceCommand`` through the login shell, and
   :doc:`ob-login-shell(8) <ob-login-shell>` is the one that reads nothing
   of the user's before the recorder starts. ``default_shell`` is then the
   shell of the recorded session. A backend, and
   ``--disable-session-recorder``, keep bash. The launcher is also listed
   in ``/etc/shells``, :manpage:`nscd(8)` is restarted if it runs, and the
   sshd drop-in pins ``PermitUserEnvironment no`` next to the
   ``ForceCommand``.

``/etc/open-bastion/session-recorder.conf``
   Bastion only: session recorder configuration.

``/var/lib/open-bastion/sessions/``
   Bastion only: session recordings.

Examples
--------

Bastion, interactive:

::

   sudo ob-bastion-setup --portal https://auth.example.com --server-group bastion

Backend accepting hops from two bastions, non-interactive, with a
pre-obtained token:

::

   sudo ob-backend-setup --portal https://auth.example.com \
       --server-group production --client-id pam-access \
       --allowed-bastions bastion-01,bastion-02 \
       --token-file /root/server-token.json --yes

Replace the allowed bastions of a backend already set up, for instance
after enrolling a new bastion:

::

   sudo ob-backend-setup --allowed-bastions bastion-01,bastion-03

Standalone host, dry run:

::

   sudo ob-standalone-setup --portal https://auth.example.com --dry-run

Exit status
-----------

``0``
   Setup completed successfully.

``1``
   Setup failed, or an option does not apply to the role in effect.

See also
--------

:doc:`openbastion.conf(5) <openbastion.conf>`,
:doc:`ob-bastion-id(1) <ob-bastion-id>`,
:doc:`ob-enroll(8) <ob-enroll>`,
:doc:`ob-heartbeat(8) <ob-heartbeat>`,
:doc:`ob-krl-refresh(8) <ob-krl-refresh>`,
:doc:`ob-login-shell(8) <ob-login-shell>`,
:doc:`ob-post-upgrade(8) <ob-post-upgrade>`,
:doc:`ob-session-recorder(8) <ob-session-recorder>`,
:doc:`ob-ssh(1) <ob-ssh>`,
:manpage:`nsswitch.conf(5)`,
:manpage:`sshd_config(5)`

LemonLDAP::NG documentation: https://lemonldap-ng.org/
