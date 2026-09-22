Security features
=================

Security Considerations
-----------------------

1. **Protect configuration files**: ``/etc/open-bastion/openbastion.conf`` and ``token`` should be readable only by root
2. **Use TLS**: Always use HTTPS for portal_url
3. **Server tokens**: Server tokens are automatically rotated via refresh token mechanism (``token_rotate_refresh = true`` by default). If you suspect compromise, re-enroll the server with ``ob-enroll``
4. **Backup access**: Keep a root password or console access as fallback

.. _security-ssh-key-policy:

SSH Key Policy
--------------

Open Bastion can optionally restrict which SSH key types and sizes are allowed for authentication. This is useful for enforcing security policies that require modern key types or minimum key sizes.

Configuration
~~~~~~~~~~~~~

.. code:: ini

   # Enable SSH key policy enforcement
   ssh_key_policy_enabled = true

   # Only allow Ed25519 and ECDSA keys (no RSA)
   ssh_key_allowed_types = ed25519,ecdsa

   # Require at least 3072-bit RSA keys (if RSA is allowed)
   ssh_key_min_rsa_bits = 3072

   # Require at least P-384 for ECDSA (if ECDSA is allowed)
   ssh_key_min_ecdsa_bits = 384

Allowed Key Types
~~~~~~~~~~~~~~~~~

=========== =====================================
Type        Description
=========== =====================================
``ed25519`` Ed25519 keys (recommended, 256-bit)
``ecdsa``   ECDSA keys (P-256, P-384, P-521)
``rsa``     RSA keys (variable size)
``dsa``     DSA keys (deprecated, 1024-bit)
``sk``      FIDO2/Security keys (hardware tokens)
``all``     All types except DSA
=========== =====================================

Example Policies
~~~~~~~~~~~~~~~~

**Strict Modern (Ed25519 only):**

.. code:: ini

   ssh_key_policy_enabled = true
   ssh_key_allowed_types = ed25519

**FIPS-like (ECDSA P-384+ or RSA 3072+):**

.. code:: ini

   ssh_key_policy_enabled = true
   ssh_key_allowed_types = ecdsa,rsa
   ssh_key_min_ecdsa_bits = 384
   ssh_key_min_rsa_bits = 3072

**No RSA (modern keys only):**

.. code:: ini

   ssh_key_policy_enabled = true
   ssh_key_allowed_types = ed25519,ecdsa,sk

Configuration Options
~~~~~~~~~~~~~~~~~~~~~

========================== ========= =================================
Option                     Default   Description
========================== ========= =================================
``ssh_key_policy_enabled`` ``false`` Enable SSH key policy enforcement
``ssh_key_allowed_types``  (all)     Comma-separated allowed types
``ssh_key_min_rsa_bits``   ``2048``  Minimum RSA key size in bits
``ssh_key_min_ecdsa_bits`` ``256``   Minimum ECDSA key size in bits
========================== ========= =================================

Requirements and failure mode
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The module learns which key was presented from the ``ob-ssh-principals`` helper installed by ``ob-bastion-setup`` / ``ob-backend-setup``, which sshd calls as ``AuthorizedPrincipalsCommand ... %u %f %t %k``. sshd does not export ``SSH_USER_AUTH`` to the PAM environment during ``pam_acct_mgmt`` on current OpenSSH, so this spool is the channel. Check that the installed helper is recent enough:

.. code:: bash

   grep -q 'spool-format: v1' /usr/local/sbin/ob-ssh-principals && echo OK

The check is **fail-closed**: with ``ssh_key_policy_enabled = true``, a key whose type or size cannot be determined is **denied**, and the reason is logged. Consequences:

- Enable the policy only on a host whose setup script has been re-run with the version that installs the v1 helper. A package upgrade alone replaces the PAM module but not the helper in ``/usr/local/sbin``; the postinst warns about that combination.
- ``ssh_key_min_rsa_bits`` is enforced from the RSA modulus decoded out of the key blob. An RSA key whose size cannot be measured is rejected.
- With the policy disabled (the default), none of this runs and behaviour is unchanged.

``ExposeAuthInfo yes`` in ``sshd_config`` remains useful as a fallback for sshd variants that do propagate the information, and is required for :doc:`Service Accounts </service-accounts>` fingerprint validation.

.. _security-cache-brute-force-protection:

Cache Brute-Force Protection
----------------------------

When the LLNG server is unavailable, Open Bastion uses cached authorization data (offline mode). This feature adds rate limiting to cache lookups to prevent brute-force attacks against the cache.

.. _security-configuration-1:

Configuration
~~~~~~~~~~~~~

.. code:: ini

   # Enable cache rate limiting
   cache_rate_limit_enabled = true

   # Lock out after 3 failed cache lookups (default)
   cache_rate_limit_max_attempts = 3

   # Initial lockout: 60 seconds (uses exponential backoff)
   cache_rate_limit_lockout_sec = 60

   # Maximum lockout: 1 hour
   cache_rate_limit_max_lockout_sec = 3600

How It Works
~~~~~~~~~~~~

1. When the LLNG server is unreachable, cache lookups are attempted
2. Every cache lookup attempt is counted (hits and misses) to prevent enumeration
3. After ``max_attempts`` attempts, the user is locked out from cache lookups
4. Lockout duration doubles on each subsequent violation (exponential backoff)
5. Only authorized cache hits reset the failure counter (prevents attackers from resetting by finding cached users)

.. _security-configuration-options-1:

Configuration Options
~~~~~~~~~~~~~~~~~~~~~

+--------------------------------------+-----------+--------------------------------------+
| Option                               | Default   | Description                          |
+======================================+===========+======================================+
| ``cache_rate_limit_enabled``         | ``false`` | Enable cache lookup rate limiting    |
+--------------------------------------+-----------+--------------------------------------+
| ``cache_rate_limit_max_attempts``    | ``3``     | Cache lookup attempts before lockout |
+--------------------------------------+-----------+--------------------------------------+
| ``cache_rate_limit_lockout_sec``     | ``60``    | Initial lockout duration in seconds  |
+--------------------------------------+-----------+--------------------------------------+
| ``cache_rate_limit_max_lockout_sec`` | ``3600``  | Maximum lockout duration in seconds  |
+--------------------------------------+-----------+--------------------------------------+

.. _security-rate-limiting:

Rate Limiting
-------------

Open Bastion includes rate limiting to protect against brute-force attacks:

.. code:: ini

   # Rate limiting
   rate_limit_enabled = true
   rate_limit_max_attempts = 5
   rate_limit_initial_lockout = 30
   rate_limit_max_lockout = 3600

After ``max_attempts`` failed authentication attempts, the user is locked out. The lockout duration uses exponential backoff, starting at ``initial_lockout`` seconds and doubling up to ``max_lockout`` seconds.

Audit Logging
-------------

Structured JSON audit logging with correlation IDs:

.. code:: ini

   # Audit logging
   audit_enabled = true
   audit_log_file = /var/log/open-bastion/audit.json
   audit_to_syslog = true
   audit_level = 1  # 0=critical, 1=auth events, 2=all

With ``audit_to_syslog``, events go to the ``auth`` facility under the ``pam_openbastion`` ident, so they show up alongside the module's own messages:

.. code:: bash

   sudo journalctl -t pam_openbastion
   sudo grep pam_openbastion /var/log/auth.log

Permissions and rotation of the JSON log
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The module creates ``audit_log_file`` as ``0640`` and refuses to write to it if it is world- or group-writable, is a symlink, or is not owned by the effective user. It sets the mode **only when it creates the file**, so if you deliberately tighten an existing log to ``0600`` it stays ``0600``.

The module does not rotate the log itself: every ``sshd`` and ``sudo`` process on the host appends to it concurrently, and a renaming or truncating writer would race with its peers. It only warns once per process, via syslog, when the file passes 100 MB. Install the shipped template instead:

.. code:: bash

   sudo cp /usr/share/open-bastion/logrotate/open-bastion /etc/logrotate.d/open-bastion
   # then adjust the path inside it if audit_log_file is not the default

Webhook Notifications
---------------------

Get notified of security events:

.. code:: ini

   # Webhook notifications
   notify_enabled = true
   notify_url = https://alerts.example.com/webhook
   notify_secret = your-hmac-secret


.. _security-dos-prevention-via-crowdsec-whitelist:

DoS Prevention via Crowdsec Whitelist
-------------------------------------

**Problem**: When multiple users share a single public IP (e.g., corporate VPN exit node, NAT gateway), legitimate authentication failures from different users can trigger CrowdSec's auto-ban, effectively causing a Denial of Service for all users behind that IP.

**Solution**: Add shared IPs to ``crowdsec_whitelist``:

.. code:: ini

   # VPN exit nodes that serve many users
   crowdsec_whitelist = 203.0.113.10, 198.51.100.0/24

**Best practices**:

1. Only whitelist IPs you control and trust
2. Monitor whitelisted IPs separately (e.g., via SIEM or separate CrowdSec scenario)
3. Consider using ``crowdsec_action = warn`` instead of whitelist for partial protection
4. Document whitelisted IPs and review periodically

Fail-Open vs Fail-Closed
~~~~~~~~~~~~~~~~~~~~~~~~

The ``crowdsec_fail_open`` setting determines behavior when CrowdSec LAPI is unavailable:

- ``crowdsec_fail_open = true`` (default): Allow authentication if CrowdSec is down
- ``crowdsec_fail_open = false``: Deny authentication if CrowdSec is down

**Recommendation**: Use ``fail_open = true`` for most deployments to avoid self-inflicted DoS when CrowdSec is temporarily unavailable. Use ``fail_open = false`` only in high-security environments where blocking access is preferable to allowing potentially malicious IPs.

Preventing recording bypass
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Session recording captures only what goes through the session's terminal.
An authenticated user could try to run commands outside of it, for example
with ``setsid nohup … &`` (the process survives logout), ``at``,
``crontab``, or ``systemd --user``. Open Bastion provides two complementary
protections.

**Session containment.** ``ob-bastion-setup`` deploys system configuration
drop-ins that close these channels:

- ``KillUserProcesses=yes`` in ``systemd-logind`` kills all of a user's
  processes when their last session ends, including detached ones.
- An empty ``at.allow`` and a root-only ``cron.allow`` prevent non-sudo
  users from scheduling jobs, and ``atd`` is masked.
- An ``nproc`` limit of 256 processes per user (unlimited for root), set in
  ``/etc/security/limits.d/``, contains fork bombs.

After deployment, verify that no user has lingering enabled, which would
keep their processes running after logout:

.. code:: bash

   loginctl show-user <user> | grep Linger    # expected: Linger=no

For the full rationale and how to re-enable these features, see
:doc:`/hardening`.

**Audit trace.** For a tamper-evident, kernel-level record of activity,
enable the optional ``auditd``-based trace with
``ob-bastion-setup --enable-audit-trace``. It logs command executions,
outbound connections, and writes to sensitive paths, including the
recordings directory, so a process that escapes session recording still
leaves a trace. See :doc:`/audit`.

.. _ssh-session-recording-login-shell:

The login shell: nothing of the user's before the recorder
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

sshd does not execute a ``ForceCommand`` itself: it runs it through the user's **login shell**, as ``$SHELL -c /usr/sbin/ob-session-recorder``. A shell reads startup files before it runs that command, and some of them belong to the user. Debian's and Ubuntu's ``bash`` source ``/etc/bash.bashrc`` and ``~/.bashrc`` for ``bash -c`` whenever ``SSH_CLIENT`` is set, and ``zsh`` reads ``~/.zshenv`` for every invocation. With such a login shell, the user's own files run **before** the recorder starts, and outside the recording (#293).

On a host that records, the login shell of SSO users is therefore ``/usr/sbin/ob-login-shell`` (see ``ob-login-shell(8)``):

- ``libnss_openbastion`` hands it out to every user it resolves when ``nss_openbastion.conf`` sets ``force_shell = /usr/sbin/ob-login-shell``. It wins over the shell the portal supplies and over ``default_shell``, and it applies to entries served from the NSS caches too, including ones written before the key was set. ``ob-bastion-setup`` writes the key on the bastion and standalone roles when recording is on, and ``ob-post-upgrade`` adds it to a recording host set up before. A backend (no ``ForceCommand``, nothing recorded) and ``--disable-session-recorder`` (no recorder) keep bash.
- The launcher reads no file the user controls and starts no shell. It execs the recorder with an environment it builds itself: identity from the passwd entry, a fixed ``PATH``, and only ``SSH_CLIENT``, ``SSH_CONNECTION``, ``SSH_TTY``, ``SSH_ORIGINAL_COMMAND``, ``TERM``, ``SSH_AUTH_SOCK``, locale names and the ``XDG_SESSION_*`` variables, each validated. ``BASH_ENV``, ``ENV``, exported functions, ``LD_*`` and ``OB_*`` never reach it.
- The recorder then starts the user's **real** shell inside ``script(1)``: ``default_shell`` from ``nss_openbastion.conf`` (``/bin/bash`` as the setup writes it). The recorded session is an ordinary bash, and reading ``~/.bashrc`` there is harmless: it is recorded.
- The setup also pins ``PermitUserEnvironment no`` next to the ``ForceCommand``: ``~/.ssh/environment`` is a file the user writes, which sshd would read into the launcher's environment before it runs.

Every way into the launcher ends in the recorder. ``ob-login-shell -c COMMAND`` for anything other than the recorder (``su -c``, ``sudo -i -u USER COMMAND``, an sshd ``Match`` block that exempts the user from the ``ForceCommand``) does not run ``COMMAND``: it hands it to the recorder, which records it. An interactive login -- the console, ``su -``, ``sudo -i`` -- is a recorded session too.

Two consequences to know:

- **Exempting an SSO user from recording with a ``Match`` block no longer works**: the launcher records them anyway. Exemptions apply to local accounts only.
- **A per-user shell from the portal is not honoured on a recording host**: everyone's recorded session runs ``default_shell``. The portal's shell still applies on backends.

Local accounts in ``/etc/passwd`` are not resolved by ``libnss_openbastion`` and keep the shell you gave them. Any of them that logs in over SSH on a recording host goes through the same ``ForceCommand``, with the same exposure; give it the launcher with ``chsh -s /usr/sbin/ob-login-shell <user>``.

Availability: fail-closed recording requires out-of-band rescue access
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Recording is **fail-closed**, and ``ob-bastion-setup`` forces **every** session through the recorder (a global ``ForceCommand``, root included — Option C above). The consequence is an availability trade-off you must plan for: **anything that prevents a session from being recorded prevents the session itself.**

In particular, **a full disk is a lockout risk**. The recordings are written by the root sink under ``/var/lib/open-bastion/sessions``; when that filesystem fills up (including the root-reserved blocks the sink can use), writes fail with ``ENOSPC``. Depending on timing, a new connection is then either refused (fail-closed) or its recording is lost — and this applies to **interactive shells and ``scp``/``sftp`` transfers** (file transfers are fail-closed too). You can therefore be locked out of SSH exactly when you need to log in to free space.

**Always keep an administrative path that does not transit sshd's ``ForceCommand``** — a serial console, BMC/IPMI, or hypervisor / cloud-provider console (e.g. OVH KVM). Open Bastion only wires the recorder into sshd's ``ForceCommand``, and only reconfigures the ``sshd`` / ``sudo`` / ``sudo-i`` PAM stacks — it does **not** touch ``/etc/pam.d/login`` or ``/etc/pam.d/su``. A console login **as a local account such as root** (and ``su -`` to another local account from it) therefore bypasses recording and remains usable to free space, restart ``ob-record.socket``, or otherwise recover. An **SSO user's** console login, like their ``su -`` or ``sudo -i``, now goes through the recorder (see :ref:`ssh-session-recording-login-shell`) and fails with it: the rescue path has to be a local account. (The in-SSH alternative — exempting an admin account with ``Match User …,!admin``, Option A — leaves that account's sessions **unrecorded**, an audit/trust trade-off, and is not what ``ob-bastion-setup`` configures.)

Operational recommendations:

- **Monitor free space** on the recordings filesystem and alert well before full.
- Recordings are compressed and expired automatically — see :ref:`Retention and disk management <session-recording-retention-and-disk-management>` below.
- Put ``/var/lib/open-bastion/sessions`` on a **dedicated partition** so a full recordings store cannot also take down the host's root filesystem.

**Concurrency.** Each recorded session holds one connection on ``ob-record.socket`` for its whole lifetime. ``ob-record.socket`` ships with ``MaxConnections=1024`` and ``MaxConnectionsPerSource=16`` (connections per source uid) so that neither the total nor any single user's share of concurrent sessions can exhaust the socket and, because recording is fail-closed, lock logins out. Two caveats:

- ``MaxConnectionsPerSource`` is honoured only by **systemd v256 or newer**. On older systemd — Debian bookworm (252), RHEL/Rocky/Alma 9 (252), Ubuntu noble (255) — it is **ignored**, and only the total ``MaxConnections=1024`` applies; there a single local user can hold all 1024 slots. On those hosts, rely on the total cap and on session containment (``--enable-hardening``, which kills a user's processes at logout).
- Where it *is* honoured, a user's **17th** concurrent recorded session is refused (fail-closed: that session cannot start). Raise ``MaxConnectionsPerSource`` if your users legitimately open more than 16 simultaneous sessions from one account. Raise ``MaxConnections`` for more than 1024 host-wide. Both with ``systemctl edit ob-record.socket``.

.. _session-recording-retention-and-disk-management:

Retention and disk management
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Because recording is fail-closed, unbounded recordings are an availability risk. ``ob-session-prune`` bounds the recordings store and runs daily from ``ob-session-prune.timer`` (enabled at install time; it no-ops on hosts without recordings). It has two stages, both configured in ``/etc/open-bastion/session-recorder.conf``:

+-----------------------------------+---------+------------------------------------------------------------------------------------------------------+
| Key                               | Default | Effect                                                                                               |
+===================================+=========+======================================================================================================+
| ``recording_compress_after_days`` | ``1``   | ``gzip`` closed recording payloads older than N days (typescripts compress ~10–20×). ``0`` disables. |
+-----------------------------------+---------+------------------------------------------------------------------------------------------------------+
| ``recording_retention_days``      | ``365`` | Delete recordings (payload + ``.json``) older than N days. ``0`` keeps them forever.                 |
+-----------------------------------+---------+------------------------------------------------------------------------------------------------------+

Notes:

- The ``.json`` metadata is left **uncompressed** so the index stays greppable; the recording payload (``.typescript``/``.cast``/``.ttyrec``) is what gets gzipped. ``gzip`` preserves the file mtime, so expiry still sees the true age.
- Deletion drops audit evidence, so every run that deletes anything is logged at ``notice`` level (``journalctl -t ob-session-prune``). The retention default is deliberately long; in a regulated context (e.g. SecNumCloud) set ``recording_retention_days`` to match your log-retention obligation, or ``0`` to never auto-delete and rely on capacity planning / archival instead.
- The job runs as root from a sandboxed oneshot service and only writes under ``/var/lib/open-bastion/sessions``, preserving the tamper-evident layout.

See ` <https://github.com/linagora/open-bastion/blob/main/man/ob-session-prune.8>`__.
