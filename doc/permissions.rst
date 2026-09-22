.. _permissions-access--permissions-what-you-can-control-and-where:

Access & Permissions: what you can control, and where
=====================================================

Open Bastion enforces access on **two layers**. Knowing which layer owns a given decision is the key to operating it well:

- **SSO side (LemonLDAP::NG)** — *who* may connect to which servers and *who* may ``sudo``, driven by **groups**. Centralized, applies fleet-wide, changes take effect in minutes.
- **Open Bastion side (per server)** — *how* authentication and authorization are enforced locally: the PAM mode, the sudo policy, key-only service accounts, user provisioning, containment hardening, and any ``sshd``/PAM tweaks.

The recommended posture is **"the SSO decides"**: keep per-server files minimal and drive everything from LLNG groups. But every local knob below remains available for defense-in-depth or for hosts that need a local exception (see :ref:`Dual management <permissions-dual-management>`).

.. _permissions-quick-map--i-want-to-control-x-where:

Quick map — "I want to control X. Where?"
-----------------------------------------

+-------------------------------------------------+------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Goal                                            | Layer            | How                                                                                                                                                                                             |
+=================================================+==================+=================================================================================================================================================================================================+
| Who can SSH into which servers                  | **SSO**          | :ref:`Server groups <llng-configuration-server-groups>` + ``pam-access`` rules                                                                                                                  |
+-------------------------------------------------+------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Who can ``sudo``                                | **SSO** (+local) | LLNG group → sudo authorization; optionally local ``sudoers``                                                                                                                                   |
+-------------------------------------------------+------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Make ``sudo`` require a fresh SSO token         | **OB**           | :doc:`PAM Mode E </pam-modes>` (max-security); see :ref:`sudo's timestamp cache <pam-modes-how-often-you-are-actually-prompted-sudos-timestamp-cache>` for how often a prompt is actually shown |
+-------------------------------------------------+------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Which SSH **key types/sizes** are allowed       | **OB**           | ``ssh_key_policy_enabled``, ``ssh_key_allowed_types`` (:ref:`security <security-ssh-key-policy>`)                                                                                               |
+-------------------------------------------------+------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Auth method (token / SSH key / password)        | **OB**           | :doc:`PAM mode A–E </pam-modes>`                                                                                                                                                                |
+-------------------------------------------------+------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Non-SSO automation logins (ansible, backup, CI) | **OB**           | :doc:` </service-accounts>`                                                                                                                                                                     |
+-------------------------------------------------+------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Auto-created home / shell / UID-GID range       | **OB**           | provisioning keys in :doc:` </configuration>`                                                                                                                                                   |
+-------------------------------------------------+------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Which Unix groups are synced from LLNG          | **both**         | LLNG ``managed_groups`` + local ``allowed_managed_groups`` whitelist                                                                                                                            |
+-------------------------------------------------+------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Process containment (kill on logout, at/cron)   | **OB**           | :doc:` </hardening>`                                                                                                                                                                            |
+-------------------------------------------------+------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Bastion → backend connection trust              | **both**         | LLNG signs the hop cert; backend ``allowed_bastions`` (:doc:`architecture </bastion-architecture>`)                                                                                             |
+-------------------------------------------------+------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Revoke an admin everywhere                      | **SSO**          | remove from the group / close the account (see below)                                                                                                                                           |
+-------------------------------------------------+------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Onboard an admin                                | **SSO**          | add to the right group; they self-serve their SSH cert                                                                                                                                          |
+-------------------------------------------------+------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

SSO side (LemonLDAP::NG)
------------------------

Configured once in the portal, applied to the whole fleet. See :doc:`LemonLDAP::NG Configuration </llng-configuration>` for the setup.

- **Server groups** — tag each enrolled server with a group; access rules are written per group, not per host. See :ref:`Server groups <llng-configuration-server-groups>`.
- **Access rules (``pam-access``)** — for a given server group, decide which LLNG user groups may open an SSH session and which may ``sudo``. This is the primary "who can do what, where" control.
- **SSH CA (``ssh-ca``)** — LLNG signs users' SSH certificates (validity window, principals). Users self-serve a cert with ``ob-ssh-cert``; closing their account or letting the cert expire removes access. See the SSH CA section of :doc:`llng-configuration </llng-configuration>`.
- **Group synchronization** — LLNG advertises a user's ``managed_groups``; the PAM module maps them to Unix supplementary groups on login (creating groups when needed). Pair with the local whitelist below.
- **Lifecycle**

  - *Onboarding*: add the user to a group → rights apply on next login.
  - *Role change*: change their groups → old rights drop and new ones apply within minutes (bounded by the :doc:`offline cache </offline-mode>` TTL).
  - *Offboarding*: remove from the group or close the SSO account. See the detailed :doc:`offboarding procedure </security/03-offboarding>`.

Open Bastion side (per server)
------------------------------

Written into ``/etc/open-bastion/`` by ``ob-bastion-setup`` / ``ob-backend-setup`` / ``ob-standalone-setup`` (or the `ob-builder <https://github.com/linagora/open-bastion/blob/main/admin-builder/README.md>`__ artefacts).

- **PAM mode (A–E)** — the strictness of authentication and whether ``sudo`` is token-gated. Mode E (max-security) accepts only SSO-signed certs, requires a fresh LLNG token for ``sudo``, and enforces a KRL. See :doc:`PAM Authentication Modes </pam-modes>`.
- **sudo policy** — token-gated via ``pam_openbastion`` (Mode E), and/or a local rule: the setups create the ``open-bastion-sudo`` group and ``/etc/sudoers.d/open-bastion``. A host can also keep its own classic ``sudoers`` in parallel.
- **Service accounts** — key-only local accounts that bypass OIDC, with a local sudo grant. Powerful and local: see the trade-offs (sudo without token, reachability requirements) in :doc:`Service Accounts </service-accounts>`.
- **User provisioning** — shell, home, UID/GID ranges, skeleton dir, plus the ``approved_shells`` / ``approved_home_prefixes`` allow-lists that bound what a provisioned (or service) account may use. See :doc:`Configuration </configuration>`.
- **Group-sync whitelist** — ``allowed_managed_groups`` limits which LLNG-managed groups may be created/modified locally (defense-in-depth); groups outside the pool are never touched. See :doc:`Configuration </configuration>`.
- **Offline resilience** — ``auth_cache_enabled`` turns the authorization cache on or off, and ``auth_cache_force_online`` forces every check online; how long a cached authorization survives an SSO outage is decided by the server. See :doc:`Offline mode </offline-mode>` and :doc:`cache administration </offline-cache-admin>`.
- **Containment hardening** — opt-in ``--enable-hardening`` adds logind ``KillUserProcesses``, an ``nproc`` cap and ``at``/``cron`` allow-lists. See :doc:`Hardening </hardening>`.

.. _permissions-tuning-the-generated-sshd--pam-configuration:

Tuning the generated ``sshd`` / PAM configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The setups own two things you may want to extend:

- **``sshd`` drop-ins** under ``/etc/ssh/sshd_config.d/`` (e.g. ``00-open-bastion-*.conf``, and ``60-max-security.conf`` in Mode E). You can layer **additional** drop-ins for site policy — for example an ``AuthorizedKeysCommand`` to serve :doc:`service-account keys </service-accounts>` in Mode E, or ``AllowTcpForwarding no`` to close the port-forward channel. Mind ``sshd``'s "first value wins" rule for single-valued keywords (the ``00-`` prefix makes the Open Bastion settings win over distro drop-ins).
- **``/etc/pam.d/sshd``** (and ``/etc/pam.d/sudo``, ``sudo-i``) — the PAM stacks that invoke ``pam_openbastion``. You can add stock PAM modules around them. Note that ``pam_systemd`` and ``pam_mkhomedir`` are **not** optional extras you may add: both setups already write them, and both are required (:ref:`full stack <pam-modes-pam-configuration-for-sshd>`). Dropping ``pam_systemd`` makes sessions invisible to ``who`` / ``w`` / ``loginctl`` and to the heartbeat's connected-users report; dropping the ``session pam_openbastion`` line breaks Mode E ``sudo``.

..

   **Re-running a setup regenerates these files.** Keep site additions in separate, higher-numbered ``sshd_config.d`` drop-ins where possible, and re-apply PAM changes after an upgrade (re-running ``ob-*-setup`` is the supported path — see the upgrade notes in the `CHANGELOG <https://github.com/linagora/open-bastion/blob/main/CHANGELOG.md>`__).

.. _permissions-dual-management:

Dual management
---------------

The two layers are complementary, not exclusive:

- **SSO-only (recommended)** — no local sudoers, no service accounts; every decision comes from LLNG groups. Simplest to reason about and audit.
- **SSO + local** — keep specific local exceptions alongside the SSO: a break-glass :doc:`service account </service-accounts>`, a host-local ``sudoers`` rule, or a stricter PAM mode on a sensitive host. Local grants are **not** visible to the SSO, so inventory and review them deliberately (see the EBIOS risks for service accounts in :doc:`risk reduction </security/99-risk-reduce>`).

See also
--------

- :doc:`PAM Authentication Modes </pam-modes>` — the A–E matrix
- :doc:`LemonLDAP::NG Configuration </llng-configuration>` — server-side setup
- :doc:`Configuration Reference </configuration>` — every ``openbastion.conf`` key
- :doc:`Service Accounts </service-accounts>` — key-only local accounts
- :doc:`Bastion Architecture </bastion-architecture>` — bastion→backend trust
