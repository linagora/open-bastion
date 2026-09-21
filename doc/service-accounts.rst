Service Accounts
================

Service accounts (ansible, backup, deploy, etc.) are local accounts that authenticate via SSH key only, without OIDC authentication. They are defined in a local configuration file on each server.

Why Service Accounts?
---------------------

Some accounts don't correspond to real users and can't authenticate via OIDC:

- **Automation tools**: Ansible, Puppet, Chef
- **Backup systems**: rsync, borg, restic
- **CI/CD pipelines**: GitLab Runner, GitHub Actions
- **Monitoring agents**: Prometheus, Zabbix

These accounts need:

- SSH key authentication (no interactive login)
- Fine-grained sudo permissions
- Automatic account creation
- Full audit logging

Configuration
-------------

Create ``/etc/open-bastion/service-accounts.conf``:

.. code:: ini

   # Ansible automation account
   [ansible]
   key_fingerprint = SHA256:abc123def456...
   sudo_allowed = true
   sudo_nopasswd = true
   gecos = Ansible Automation
   shell = /bin/bash
   home = /var/lib/ansible

   # Backup service account
   [backup]
   key_fingerprint = SHA256:xyz789...
   sudo_allowed = false
   gecos = Backup Service Account
   shell = /bin/sh
   home = /var/lib/backup

..

   **⚠️ ``home`` and ``shell`` must be within the approved lists, or the account is silently dropped.** ``pam_openbastion`` validates each account at load and **discards** any whose ``home`` is not under ``approved_home_prefixes`` (default ``/home:/var/home``) or whose ``shell`` is not in ``approved_shells`` (default: ``/bin/bash``, ``/bin/sh``, ``/bin/zsh``, ``/bin/dash``, ``/bin/fish`` and their ``/usr/bin`` variants). A dropped account is not recognized as a service account, so its login falls through to LLNG and is refused with "user not found". The ``/var/lib/...`` homes above therefore require widening the prefix list:

   .. code:: ini

      # /etc/open-bastion/openbastion.conf
      approved_home_prefixes = /home:/var/home:/var/lib

   Either keep service-account homes under ``/home`` (works out of the box) or set ``approved_home_prefixes`` accordingly.

**Security requirements for this file:**

- Owned by root (uid 0)
- Permissions 0600
- Not a symlink

**SSH server requirement:** The SSH server must have ``ExposeAuthInfo yes`` in ``/etc/ssh/sshd_config`` for fingerprint validation to work. This allows the PAM module to verify that the SSH key used matches the configured fingerprint. See also :ref:`SSH Key Policy <security-ssh-key-policy>` for restricting allowed key types.

.. code:: bash

   # /etc/ssh/sshd_config
   ExposeAuthInfo yes

**Mode E compatibility:** In Mode E deployments (``AuthorizedKeysFile none``) an ``authorized_keys`` file is never consulted, so the key has to reach sshd some other way — through the ``AuthorizedKeysCommand`` helper described below. Set that up first; the rest of this section assumes it.

Once sshd has accepted the key, the PAM module **re-validates** its SHA256 fingerprint against ``service-accounts.conf``, using ``SSH_USER_AUTH`` (which needs ``ExposeAuthInfo yes``). That check is a second gate, not the first one: it can refuse a key sshd accepted, but it cannot make sshd accept a key it has no record of. Without the helper, sshd rejects at the protocol layer and ``pam_openbastion`` is never reached (#263).

Get the SSH key fingerprint:

.. code:: bash

   ssh-keygen -lf /path/to/key.pub
   # Output: 256 SHA256:abc123def456 user@host (ED25519)
   # Use the "SHA256:abc123def456" part

Configuration Options
---------------------

+---------------------+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Option              | Required | Description                                                                                                                                                                          |
+=====================+==========+======================================================================================================================================================================================+
| ``key_fingerprint`` | Yes      | SSH key fingerprint (SHA256:... or MD5:...)                                                                                                                                          |
+---------------------+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``public_key``      | No†      | The account's SSH public key. Deployed to ``service-accounts.d/<name>.pub``; ``key_fingerprint`` is derived from it                                                                  |
+---------------------+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``public_key_file`` | No†      | Path to that key, resolved against the config file's directory and read at build time. Mutually exclusive with ``public_key``                                                        |
+---------------------+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``sudo_allowed``    | No       | Allow sudo access (default: false)                                                                                                                                                   |
+---------------------+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``sudo_nopasswd``   | No       | Sudo without re-proving the key (default: false) — see :ref:`Sudo and the key check <service-accounts-sudo-and-the-key-check>`                                                       |
+---------------------+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``gecos``           | No       | User description                                                                                                                                                                     |
+---------------------+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``shell``           | No       | Login shell — must be in ``approved_shells`` (default: common shells) or the account is dropped                                                                                      |
+---------------------+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``home``            | No       | Home directory — must be under ``approved_home_prefixes`` (default ``/home:/var/home``) or the account is dropped                                                                    |
+---------------------+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``uid``             | See note | Fixed UID. **Required (with ``gid``) for SSH-reachable accounts** — NSS resolves them only when both are set; ``0`` = auto-assign (works only if the account already exists locally) |
+---------------------+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``gid``             | See note | Fixed GID. See ``uid``                                                                                                                                                               |
+---------------------+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

† Not required by the file format, but one of the two is what makes the account usable: without a key the bundle deploys no ``.pub`` and ``sshd`` has nothing to offer.

How It Works
------------

1. Service account connects via SSH with its configured key
2. PAM module resolves the SSH key fingerprint — from ``SSH_USER_AUTH`` when sshd exposes it, otherwise from the principals spool ``/run/open-bastion/ssh-fp``
3. PAM module checks if user is in ``service-accounts.conf``
4. If found, the SSH key fingerprint is validated against the configured value
5. If fingerprint matches, account is authorized locally (no LLNG call needed)
6. Account is created automatically if it doesn't exist
7. sudo permissions are enforced based on configuration

..

   **Reusing an existing account is allowed — but its own shell/home apply.** ``shell``, ``home``, ``uid`` and ``gid`` from ``service-accounts.conf`` are applied only when ``pam_openbastion`` **creates** the account. If the name already exists locally, it is matched by fingerprint and authorized, but the **existing** passwd entry is used unchanged. So:

   - A **dedicated new name** (e.g. ``obdeploy``, ``obbackup``, ``ci-runner``) with a fixed ``uid``/``gid`` is the simplest, self-contained choice.
   - An **existing account** (e.g. attaching a key to a real functional account) works **only if it already has a usable login shell**. Most Debian system users (``backup``, ``www-data``, ``nobody``, …) ship with ``/usr/sbin/nologin``, so a login is refused ("This account is currently not available."). To use such a name, give the account a real shell yourself (e.g. ``usermod -s /bin/sh backup``) — Open Bastion will not modify an existing system account for you. ``ob-builder`` warns when a name matches a well-known system account.

Generating with ob-builder
--------------------------

Instead of hand-writing ``service-accounts.conf`` on each server, you can declare service accounts once in ` <https://github.com/linagora/open-bastion/blob/main/admin-builder/README.md>`__ and have them baked into the generated shell installer and/or Ansible role.

**Interactive:** the questionnaire asks whether to define service accounts and loops over name / fingerprint / sudo / shell / home for each. It does not ask for a public key, so a bundle built this way deploys no ``.pub`` and warns about it; use ``--config`` when you want the SSH layer handled for you.

**Non-interactive (``--config``):** add a ``service_accounts:`` list to the YAML:

.. code:: yaml

   service_accounts:
     - name: ci-ansible # avoid system names like 'ansible' only if they exist; use a dedicated name
       public_key_file: keys/ci-ansible.pub # key_fingerprint is derived from it
       sudo_allowed: true
       sudo_nopasswd: true
       shell: /bin/bash
       home: /home/ci-ansible # under an approved prefix (/home, /var/home)
       gecos: Ansible Automation
       uid: 6001 # fixed uid+gid → NSS-resolvable → reachable over SSH
       gid: 6001
     - name: obbackup
       public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… backup@ops"
       sudo_allowed: false
       shell: /bin/sh
       home: /home/obbackup
       uid: 6002
       gid: 6002

ob-builder validates each entry (name, fingerprint format, absolute shell/home paths) at build time — and **warns** when a ``home``/``shell`` falls outside the module defaults (it would otherwise be silently dropped on the target; see the warning above) — then:

- the **shell installer** writes ``/etc/open-bastion/service-accounts.conf`` (``0600 root:root``) and sets ``service_accounts_file`` in ``openbastion.conf``;
- the **Ansible role** carries the accounts as ``ob_service_accounts_content`` (overridable per host/group via ``host_vars`` / ``group_vars`` to vary which accounts reach which servers) and deploys the file when ``ob_service_accounts_enabled`` is true.

Service accounts apply to every role (bastion, backend, standalone).

   **Give each account its ``public_key``, or the SSH layer is left to you.** With a key, ``ob-builder`` derives the fingerprint, writes ``service-accounts.conf`` **and** deploys ``/etc/open-bastion/service-accounts.d/<name>.pub`` — see :ref:`Letting ob-builder deploy the key <service-accounts-letting-ob-builder-deploy-the-key>` below. With ``key_fingerprint`` alone the bundle carries no key, ``sshd`` has nothing to accept, and the account cannot log in until you deploy one by hand: that is what ``pam_openbastion`` checks, and it is **not** what lets the connection in. The build warns when an account is in that state.

Authorizing the public key at the SSH layer
-------------------------------------------

``pam_openbastion`` validates the fingerprint **after** ``sshd`` has already accepted the public key. So ``sshd`` must be told the key is acceptable, by one of:

- **``authorized_keys`` (PAM modes A–D).** Put the public key in ``~<name>/.ssh/authorized_keys`` (mode ``0600``, owned by the account). Because the service account is auto-created only on first login, you must **pre-create the account and its ``~/.ssh/authorized_keys``** (e.g. ``useradd -m``, then drop the key) — there is no home directory to read the file from otherwise.

- **``AuthorizedKeysCommand`` (required for Mode E, works in all modes).** Mode E sets ``AuthorizedKeysFile none``, so ``authorized_keys`` is ignored. Use the ``ob-service-account-keys`` helper — shipped at ``/usr/sbin/ob-service-account-keys`` since #263 — which serves a public key from ``/etc/open-bastion/service-accounts.d/<name>.pub`` (``root:root 0644``) and does **not** depend on the account already existing:

  ::

     # /etc/ssh/sshd_config.d/09-open-bastion-service-keys.conf
     AuthorizedKeysCommand /usr/sbin/ob-service-account-keys %u
     AuthorizedKeysCommandUser nobody
     ExposeAuthInfo yes

  All three lines. Without ``ExposeAuthInfo yes`` sshd accepts the key and the fingerprint check below never runs — the half-configuration this section exists to prevent.

  Drop each account's public key at ``/etc/open-bastion/service-accounts.d/<name>.pub`` and reload ``sshd``.

.. _service-accounts-letting-ob-builder-deploy-the-key:

Letting ob-builder deploy the key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Since #263 a ``service_accounts:`` entry can carry the key itself, and then the generated bundle writes ``/etc/open-bastion/service-accounts.d/<name>.pub`` for you:

.. code:: yaml

   service_accounts:
     - name: ci-ansible
       public_key_file: keys/ci.pub # or public_key: "ssh-ed25519 AAAA… ci@host"
       uid: 6001
       gid: 6001

``key_fingerprint`` is **derived** from the key. Supply it as well only if you want it cross-checked — a value that does not describe the key stops the build, rather than producing a bundle that installs cleanly and refuses the login with a key that looks correct in every listing.

The bundle still cannot turn on the ``AuthorizedKeysCommand``: that is a host-wide sshd change, so it stays with ``--enable-service-keys``. The generated installer and the Ansible role both say so when they find no such command configured.

What actually enforces the fingerprint, and when it does not
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Read this before relying on ``key_fingerprint``.

The ``.pub`` file is what lets ``sshd`` accept the key. ``pam_openbastion`` is meant to re-validate its SHA256 fingerprint against ``service-accounts.conf`` (``0600``, and so unreadable by the ``AuthorizedKeysCommandUser``) — but for a **plain public key** on a current OpenSSH, that second check often does not run at all:

- ``sshd`` does not call ``pam_authenticate()`` for a public-key login, so the authentication-phase check never fires there (``pam_openbastion.c:3766``);
- the account-phase check resolves the fingerprint from ``SSH_USER_AUTH`` **or** the principals spool. Without ``ExposeAuthInfo yes`` there is no ``SSH_USER_AUTH``, and the spool is empty too — ``sshd`` runs ``AuthorizedPrincipalsCommand`` only for certificate sessions (``pam_openbastion.c:2458``);
- with no fingerprint from either source, the check is skipped rather than failed: absence is not fatal by default (``pam_openbastion.c:3774``).

So on such a host an orphan ``.pub`` is accepted by ``sshd`` and **not** rejected by PAM, and ``key_fingerprint`` is decorative. Two settings turn it back into a control, and you want both:

+---------------------------------+------------------------+-----------------------------------------------------------+
| setting                         | where                  | effect                                                    |
+=================================+========================+===========================================================+
| ``ExposeAuthInfo yes``          | the sshd drop-in above | gives PAM a fingerprint to check                          |
+---------------------------------+------------------------+-----------------------------------------------------------+
| ``fingerprint_required = true`` | ``openbastion.conf``   | refuses the login when there is none, instead of skipping |
+---------------------------------+------------------------+-----------------------------------------------------------+

The setup scripts write both of the sshd settings above, but only when asked:

- ``ob-bastion-setup --enable-service-keys`` (same flag on ``ob-backend-setup``) writes the whole drop-in — ``AuthorizedKeysCommand``, ``AuthorizedKeysCommandUser`` and ``ExposeAuthInfo yes`` — and creates ``service-accounts.d``. This is the flag to use; it exists because #263 showed the manual assembly is easy to get half-right.
- ``--max-security`` (Mode E) writes ``ExposeAuthInfo yes`` on its own, but **not** the ``AuthorizedKeysCommand``. Mode E alone therefore still leaves a service account unable to log in.

Neither is on by default: both change sshd for every session on the host, and this project's convention is that such changes are opted into. On a host set up without either, write the drop-in above by hand.

``fingerprint_required = true`` is a separate decision and applies to **every** SSH login on the host, not only to service accounts. ``--enable-service-keys`` reports whether it is set, in its output and in the end-of-run summary, rather than setting it.

Set it in ``openbastion.conf`` by hand. The setup scripts rewrite that file wholesale on every run, so until this release the setting was silently dropped by the next run; it is now carried over.

The account must be resolvable (fixed ``uid``/``gid``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``sshd`` runs ``getpwnam(<user>)`` **before** authentication and refuses unknown users ("Invalid user"). A brand-new service account therefore has to be resolvable up front, which ``nss_openbastion`` does — **but only when the account has a fixed ``uid`` and ``gid``** (``nss/libnss_openbastion.c``); otherwise NSS skips it and the login is refused before PAM ever runs. So, for an SSH-reachable service account that does not already exist as a local user:

- set both ``uid`` and ``gid`` (also gives stable, fleet-consistent ownership), **or**
- pre-create the account locally (``useradd``), in which case the ``files`` NSS source resolves it.

``ob-builder`` warns at build time when a service account lacks ``uid``/``gid``. The auto-create-on-first-login behaviour fills in the home directory etc. during the session phase, but it cannot help sshd's pre-auth lookup — hence this requirement.

Reaching servers through a bastion (no ProxyJump recording)
-----------------------------------------------------------

Service accounts authenticate by **direct SSH key**, independently of the bastion certificate-vouching used by human users. Consequences:

- A service account does **not** use ``ob-ssh``: that path needs an SSO-issued bastion voucher, which a key-only account never obtains. So the seamless, recorded bastion→backend hop is **not** available to service accounts.
- The intended pattern is therefore to point service accounts **directly at the servers they automate** (where their account is configured), not to relay through the bastion.
- A native ``ssh -J bastion backup@backend`` (ProxyJump) *can* work if ``backup`` is a configured service account on **both** the bastion and the backend and the bastion permits TCP forwarding. **But the bastion's session recorder (``ForceCommand``) does not cover the forwarded ``direct-tcpip`` channel**, so such a hop is **not recorded**. Treat this as a deliberate audit bypass: if you need service-account activity audited, run it against the target directly (the target's own logs/auditd apply) rather than tunnelling through the bastion.

.. _service-accounts-sudo-and-the-key-check:

Sudo and the key check
----------------------

With ``sudo_nopasswd = false``, a service account's ``sudo`` must re-prove the SSH key that opened the session. That check reads the fingerprint from the principals spool (``/run/open-bastion/ssh-fp``), which the account's SSH session populated and which ``sudo`` inherits through the process tree.

Until 0.6.2 it read ``SSH_USER_AUTH`` only. That variable does not exist in a ``sudo`` PAM handle, so the check could never succeed and ``sudo_nopasswd = false`` was unusable — leaving ``sudo_nopasswd = true``, which grants sudo with no proof of identity at all, as the only configuration that worked. That is fixed; both settings now do what they say.

``sudo_nopasswd = false`` requires the host to run the ``AuthorizedPrincipalsCommand`` helper (the certificate modes), since that is what writes the spool. On a host without it there is no fingerprint to recover in either context, and a service account's ``sudo`` is refused.

Sudo bypasses the SSO token (including in Mode E)
-------------------------------------------------

A service account's sudo rights come **entirely** from ``service-accounts.conf`` (``sudo_allowed`` / ``sudo_nopasswd``): ``pam_openbastion`` grants them locally and returns success **without any LLNG call** — even in Mode E, where human users must present a fresh LLNG token to use sudo. A service key with ``sudo_allowed`` (especially ``sudo_nopasswd``) is therefore a **standing local privilege that escapes the SSO-gated sudo model**. Grant it sparingly, prefer no sudo or tightly-scoped ``sudoers`` rules, and rotate/inventory these keys like any other long-lived credential. (You still need a ``sudoers`` entry permitting the account; PAM authorizes the *attempt*, ``sudoers`` authorizes *which commands*.)

Per-Server Control
------------------

Since the configuration file is local to each server, you control which service accounts can access which servers:

- Server ``web01`` has ``[ansible]`` and ``[backup]`` → both can connect
- Server ``db01`` has only ``[backup]`` → only backup can connect
- Server ``dev01`` has no service accounts → none can connect

Use configuration management (Ansible, Puppet) to deploy the appropriate configuration to each server.

Specifying the Configuration File
---------------------------------

In ``/etc/open-bastion/openbastion.conf``:

.. code:: ini

   service_accounts_file = /etc/open-bastion/service-accounts.conf

See Also
--------

- :doc:`Access & Permissions </permissions>` - Which controls live SSO-side vs server-side
- :doc:`Configuration Reference </configuration>` - All configuration options
- :doc:`PAM Authentication Modes </pam-modes>` - PAM configurations
- :doc:`Security Features </security>` - SSH key policies
