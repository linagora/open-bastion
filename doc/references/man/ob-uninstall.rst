ob-uninstall
============

Synopsis
--------

::

   ob-uninstall [-n|--dry-run] [-y|--yes] [--no-revoke] [--force]

Description
-----------

``ob-uninstall`` un-configures a host set up by
:doc:`ob-bastion-setup(8) <ob-bastion-setup>` under any of its names and
roles (``ob-bastion-setup``, ``ob-standalone-setup``,
``ob-backend-setup``), and leaves it ready for
``apt purge open-bastion`` or ``dnf remove open-bastion``.

Removing the package alone is not a way back. It does not know about the
setup's backups, so on a set-up host it leaves the sshd drop-in, whose
``ForceCommand`` names a session recorder that no longer exists, and a
PAM stack that *requires* a module that no longer exists: every SSH login
is refused. It also leaves the NSS source, the sudoers rule, the KRL and
audit schedules and a server token that the portal still honours.

``ob-uninstall`` first prints what it is going to do, then asks. It
decides everything before changing anything, so a run that has to refuse
does so before its first write.

What it undoes
--------------

In this order. The point of the order is that at no moment is an LLNG
certificate accepted without the checks that normally vet it: sshd stops
trusting the certificate authority *before* the PAM stack stops asking
the portal.

**1. sshd**
   ``sshd_config.d/00-open-bastion-bastion.conf``,
   ``00-open-bastion-backend.conf``, their legacy ``50-`` names;
   ``09-open-bastion-service-keys.conf`` and ``60-max-security.conf``
   only when they carry the Open Bastion header. On a host without
   ``sshd_config.d``, where the setup appended its blocks to
   ``sshd_config``, that file is restored from the oldest setup backup
   that does not contain them; failing that (a single run with
   ``--max-security`` keeps
   only a copy that already has the first block), the blocks are cut out
   along the exact lines the setup wrote, and the rest of the file is
   kept. If a block does not have the expected shape, or anything of Open
   Bastion's remains once they are cut, the command refuses. Then
   ``sshd -t``: if sshd rejects its configuration, the sshd files are put
   back and the command stops with everything else untouched. Otherwise
   the CA key and ``/usr/local/sbin/ob-ssh-principals`` are removed (each
   only when no remaining sshd file refers to it) and sshd is reloaded,
   with ``reload-or-restart``; existing sessions survive.

**2. PAM**
   ``/etc/pam.d/sshd``, ``sudo``, ``sudo-i``, when they load
   ``pam_openbastion`` (or ``pam_llng``): restored from the oldest copy
   that does not, taken from ``/var/backups/open-bastion/<name>.orig``
   (debconf) and then ``/var/backup/open-bastion-setup-<timestamp>/`` in
   chronological order. With no such copy, a generic stack for the
   distribution family is written (Debian: ``common-*``; RHEL:
   ``password-auth``, ``system-auth``), marked
   ``# Restored by ob-uninstall``. A ``sudo-i`` that the setup created is
   removed instead. A debconf ``.orig`` that itself loads the module
   is removed, or the package's purge would copy it back. On a dpkg host
   whose debconf ``open-bastion/pam-mode`` is not ``none``, it is set to
   ``none``: otherwise the next ``dpkg --configure`` of the package
   writes the module back into ``/etc/pam.d/sshd``. The previous value is
   saved in the backup as ``debconf-selections``.

**3. sudo**
   ``/etc/sudoers.d/open-bastion`` (only if it contains one of the two
   headers the setup writes: the maximum-security one, or the backend's
   LLNG sudo rule),
   the legacy ``ob-bastion-cert-helper``, and the group
   ``open-bastion-sudo``.

**4. NSS**
   the ``openbastion`` source is removed from the ``passwd``, ``group``
   and ``shadow`` lines of ``/etc/nsswitch.conf`` — an edit, not a
   restore, so later changes survive — and ``nss_openbastion.conf`` is
   removed. On an authselect host, where the setup had replaced the
   symlink with a file, the symlink is put back instead when its target
   exists.

**5. units**
   ``ob-heartbeat.timer``, ``ob-cert.socket``, ``ob-record.socket``,
   ``ob-fp.socket``, ``ob-session-prune.timer``, ``ob-krl-refresh.timer``,
   ``ob-audit-rotate.timer`` are disabled and stopped. The timers'
   schedule drop-ins the setup wrote,
   ``/etc/systemd/system/<timer>.d/schedule.conf``, are removed — only
   when their first line is ``# Open Bastion timer schedule``; an
   administrator's drop-in stays — and systemd is reloaded.

**6. opt-in features**
   Hardening: the logind and limits drop-ins; ``/etc/at.allow`` and
   ``/etc/cron.allow`` only if byte-identical to the shipped templates;
   atd is unmasked if masked (there is no telling whether an administrator
   masked it too); systemd-logind is reloaded, never restarted. Audit
   trace: the rules, then ``augenrules --load``. Under maximum security:
   ``/etc/ssh/revoked_keys`` when nothing left in the sshd configuration
   refers to it. On a host still running the KRL and audit cron jobs
   instead of the timers (see :doc:`ob-post-upgrade(8)
   <ob-post-upgrade>`): ``/etc/cron.d/open-bastion-krl``,
   ``/etc/cron.daily/open-bastion-audit-rotate`` (or its ``cron.weekly``
   copy), and ``/usr/local/bin/open-bastion-refresh-krl`` when it is the
   script the setup generated.

**7. generated files**
   The tmpfiles rule, ``openbastion.conf``, ``ssh-proxy.conf``,
   ``session-recorder.conf``, ``allowed_bastions``; the contents of
   ``/var/cache/open-bastion`` and ``/var/cache/nss_llng``.

**8. server token**
   Its refresh token and its access token are revoked at the portal's
   ``/oauth2/revoke`` endpoint, then the token file is deleted. A
   confidential client authenticates with a ``client_secret_jwt``
   assertion built by :doc:`ob-client-jwt(8) <ob-client-jwt>`; the client
   secret itself is never sent, and when that helper is missing the
   tokens are not revoked rather than sent without it. A public client
   sends its client_id alone. Nothing sensitive is put on a command line.
   The portal answers 200 even for a token it does not know, so success
   means the request was accepted. Revocation is best effort: when it
   fails, the command says so and carries on.

Safety
------

**Everything it touches is backed up first**
   to ``/var/backup/open-bastion-uninstall-<timestamp>/``, mode 0700,
   under each file's full path. The uninstall can be undone by copying
   the tree back. Two exceptions: the caches (derived data, holding
   encrypted credentials) and the server token (a live credential), which
   are deleted without a copy.

**Session recordings are never deleted.**
   ``/var/lib/open-bastion/sessions`` is left as it is and its location
   printed at the end. Note that ``apt purge open-bastion`` currently
   deletes ``/var/lib/open-bastion`` with the recordings in it: move them
   first if you need them.

**It refuses to lock you out.**
   Run through :manpage:`sudo(8)` by a user who looks like an SSO user of
   the host, it refuses unless ``--force`` is given, and says which of
   these matched: not in ``/etc/passwd``; a uid inside the NSS module's
   range (``min_uid..max_uid`` in ``nss_openbastion.conf``, 10000..60000
   by default), which is where ``create_user`` puts SSO users it writes
   into ``/etc/passwd``; a member of
   ``open-bastion-sudo``; or no usable password in ``/etc/shadow`` and no
   ``~/.ssh/authorized_keys``. Whoever runs it: afterwards, LemonLDAP::NG
   certificates are no longer trusted and only local accounts can log in,
   through ``authorized_keys`` or a password as the restored sshd
   defaults allow. Keep console access.

**The client secret is not copied.**
   The backup copy of ``openbastion.conf`` has its secrets
   (``client_secret`` and the other secret keys) replaced by
   ``<redacted by ob-uninstall>``: the client secret is the project's,
   shared by every host. The setup's own backups keep it in clear; the
   summary lists them so they can be shredded.

What it does not do
-------------------

It does not delete recordings, ``service-accounts.conf`` or
``service-accounts.d/`` (operator data, inert once sshd and PAM are
restored), SSO users' home directories, or the package. It does not
revert ``ob-desktop-setup``: a display-manager stack that still loads
``pam_openbastion`` is listed and the exit status is 2. It does not touch
the LemonLDAP::NG Manager: delete the host's device entry there. Leave
``pamAccessServerGroups`` alone: it is keyed by the project's client_id,
which every host of the project shares. On a bastion, remove its id from
the backends' ``allowed_bastions``.

Options
-------

.. option:: -n, --dry-run

   Print the plan and change nothing. Reports the same refusals a real
   run would hit. It runs without root, but then cannot read
   ``openbastion.conf``, the sudoers drop-in, the token or
   ``/etc/shadow``; it lists what it could not read and says the plan is
   partial. Use ``sudo ob-uninstall --dry-run`` for the full plan.

.. option:: -y, --yes

   Do not ask for confirmation.

.. option:: --no-revoke

   Do not contact the portal. The token file is still deleted; revoke it,
   or delete the host, in the LLNG Manager.

.. option:: --force

   Proceed even when invoked by an SSO-only user.

.. option:: -h, --help

   Usage.

.. option:: -V, --version

   Version.

Exit status
-----------

``0``
   done, or nothing to do (the host was never set up)

``1``
   refused, aborted, or failed; the reason is on standard error

``2``
   done, but a stack under ``/etc/pam.d`` still loads
   ``pam_openbastion``

Files
-----

``/var/backup/open-bastion-uninstall-<timestamp>/``
   this command's backup

``/var/backup/open-bastion-setup-<timestamp>/``
   the setup's backups (basenames only), read to restore the PAM stacks,
   ``sshd_config`` and the authselect symlink

``/var/backups/open-bastion/*.orig``
   the debconf backups of the PAM stacks

Environment
-----------

``OB_ROOT``
   For the test suite only: a directory prepended to every path, so a
   real uninstall can run against a fake root. Setting it also skips the
   root check, and keeps the caller's ``PATH`` (so the tests can
   substitute sshd, systemctl and the rest). Without it, ``PATH`` is set
   to ``/usr/sbin:/usr/bin:/sbin:/bin``.

See also
--------

:doc:`ob-bastion-setup(8) <ob-bastion-setup>`,
:doc:`ob-post-upgrade(8) <ob-post-upgrade>`,
:doc:`ob-krl-refresh(8) <ob-krl-refresh>`,
:doc:`ob-bastion-id(1) <ob-bastion-id>`,
:doc:`ob-client-jwt(8) <ob-client-jwt>`

Author
------

Xavier Guimard <xguimard@linagora.com>
