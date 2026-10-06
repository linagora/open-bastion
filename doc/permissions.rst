Access & permissions
====================

Open Bastion enforces access on two layers. Knowing which layer owns a
given decision is the key to operating it well:

- SSO side (LLNG) — who may connect to which servers and who may
  ``sudo``, driven by groups. Centralized, applies fleet-wide, changes
  take effect in minutes.

- Open Bastion side (per server) — how authentication and
  authorization are enforced locally: the security scenario, the sudo
  policy, key-only service accounts, user provisioning, containment
  hardening, and any ``sshd``/PAM tweaks.

.. tip::

   The recommended posture is "the SSO decides". Keep per-server
   files minimal and drive everything from LLNG groups. But every
   local knob below remains available for defense-in-depth or for
   hosts that need a local exception — see :ref:`Dual management
   <permissions-dual-management>`.

What you can control and where
------------------------------

.. list-table::
   :header-rows: 1
   :widths: 32 16 52

   * - Goal
     - Layer
     - How
   * - Who can SSH into which servers
     - **SSO**
     - Through :ref:`Server groups <llng-configuration-server-groups>`
       and :ref:`LLNG pamAccessSSHRules
       <llng-configuration-configure-in-lemonldap-ngini>`
   * - Who can ``sudo``
     - **SSO** (+local)
     - Through :ref:`LLNG pamAccessSudoRules
       <llng-configuration-configure-in-lemonldap-ngini>`, and optionally
       a local ``sudoers`` policy
   * - Make ``sudo`` require a fresh SSO token
     - **OB**
     - See :doc:`maximum security
       </security-scenarios/max-security-scenario>` and
       :ref:`the sudo timestamp cache
       <pam-modes-how-often-you-are-actually-prompted-sudos-timestamp-cache>`
   * - Which SSH key types/sizes are allowed
     - **OB**
     - See ``ssh_key_policy_enabled`` and ``ssh_key_allowed_types`` in
       :ref:`the SSH key policy <security-ssh-key-policy>`
   * - Auth method (token / SSH key / password)
     - **OB**
     - Through :doc:`/security-scenarios/index`
   * - Non-SSO automation logins (ansible, backup, CI)
     - **OB**
     - See :doc:`/service-accounts`
   * - Auto-created home / shell / UID/GID range
     - **OB**
     - Provisioning keys in :doc:`/references/configuration`
   * - Which Unix groups are synced from LLNG
     - **Both**
     - Through :ref:`LLNG pamAccessManagedGroups
       <llng-configuration-group-synchronization>` and :ref:`local
       whitelist <local-whitelist-defense-in-depth>`
   * - Process containment (kill on logout, at/cron)
     - **OB**
     - See :doc:`/hardening`
   * - Bastion-to-backend connection trust
     - **Both**
     - LLNG signs the hop cert; backend ``allowed_bastions``, see
       :doc:`architecture </references/bastion-architecture>`
   * - Revoke admin access
     - **SSO**
     - Remove from the group / close the account (see below)
   * - Onboard an admin
     - **SSO**
     - Add to the right group; they self-serve their SSH certificate

SSO side
--------

Configured once in the portal, applied to the whole fleet. See
:doc:`LemonLDAP::NG Configuration </deployment/llng-configuration>`
for the setup.

- Server groups — tag each enrolled server with a group; access
  rules are written per group, not per host. See :ref:`Server groups
  <llng-configuration-server-groups>`.

- Access rules (``pam-access``) — for a given server group, decide
  which LLNG user groups may open an SSH session and which may
  ``sudo``. This is the primary "who can do what, where" control.

- SSH CA (``ssh-ca``) — LLNG signs users' SSH certificates,
  deciding their validity window and principals. Users self-serve a
  certificate from the portal's ``/ssh`` page; closing their account or
  letting the certificate expire removes access. See the SSH CA section
  of :doc:`llng-configuration </deployment/llng-configuration>`.

- Group synchronization — LLNG advertises a user's
  ``managed_groups``; the PAM module maps them to Unix supplementary
  groups on login (creating groups when needed). Pair with the local
  whitelist below.

- Lifecycle

  - Onboarding: add the user to a group → rights apply on next login.

  - Role change: change their groups → old rights drop and new ones
    apply within minutes (bounded by the :doc:`offline cache
    </offline-mode/index>` TTL).

  - Offboarding: remove from the group or close the SSO account.

Open Bastion side (per server)
------------------------------

Set up by :doc:`ob-bastion-setup(8) </references/man/ob-bastion-setup>`,
run as ``ob-backend-setup`` on a backend and ``ob-standalone-setup`` on a
standalone host.

- Security scenario — the strictness of authentication and whether
  ``sudo`` is token-gated. The default, :doc:`maximum security
  </security-scenarios/max-security-scenario>`, accepts only
  SSO-signed certificates, requires a fresh LLNG token for ``sudo``,
  and enforces a KRL; the :doc:`other scenarios
  </security-scenarios/other-security-scenarios>` trade that for
  compatibility.

- sudo policy — token-gated via ``pam_openbastion`` in maximum
  security, and/or a local rule: the setups create the
  ``open-bastion-sudo`` group and ``/etc/sudoers.d/open-bastion``. A
  host can also keep its own classic ``sudoers`` in parallel.

- Service accounts — key-only local accounts that bypass OIDC,
  with a local sudo grant. Powerful and local: see the trade-offs
  (sudo without token, reachability requirements) in :doc:`Service
  Accounts </service-accounts>`.

- User provisioning — shell, home, UID/GID ranges, skeleton
  directory, plus the ``approved_shells`` / ``approved_home_prefixes``
  allow-lists that bound what a provisioned (or service) account may
  use. See :doc:`Configuration </references/configuration>`.

- Account existence — a bastion or standalone host creates no account:
  ``libnss_openbastion`` resolves SSO users from LLNG on the fly (a
  virtual passwd entry) and ``pam_mkhomedir`` creates only the home
  directory. A backend writes the account instead: ``create_user`` is on
  by default there (``--no-create-user`` disables it), and the module
  appends the account to ``/etc/passwd`` and ``/etc/shadow`` on first
  login and creates its home.

- Group-sync whitelist — ``allowed_managed_groups`` limits which
  LLNG-managed groups may be created/modified locally
  (defense-in-depth); groups outside it are never touched.

- Offline resilience — ``auth_cache_enabled`` turns the
  authorization cache on or off, and ``auth_cache_force_online``
  forces every check online; how long a cached authorization survives
  an SSO outage is decided by the server. See :doc:`Offline mode
  </offline-mode/index>`.

- Containment hardening — opt-in ``--enable-hardening`` adds
  logind ``KillUserProcesses``, an ``nproc`` cap and ``at``/``cron``
  allow-lists. See :doc:`Hardening </hardening>`.

Tuning the generated ``sshd`` / PAM configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The setups own three things you may want to extend:

- ``sshd`` drop-ins under ``/etc/ssh/sshd_config.d/``
  (e.g. ``00-open-bastion-*.conf``, and ``60-max-security.conf`` under
  maximum security). You can layer additional drop-ins for site
  policy — for example an ``AuthorizedKeysCommand`` to serve
  :doc:`service-account keys </service-accounts>` when certificates
  are the only accepted key, or ``AllowTcpForwarding no`` to close the
  port-forward channel. Mind ``sshd``'s "first value wins" rule for
  single-valued keywords (the ``00-`` prefix makes the Open Bastion
  settings win over distro drop-ins).

- ``/etc/pam.d/sshd`` (and ``/etc/pam.d/sudo``, ``/etc/pam.d/sudo-i``)
  — the PAM stacks that invoke ``pam_openbastion``. You can add stock
  PAM modules around them. ``pam_systemd`` and ``pam_mkhomedir`` are not
  optional extras you may add: the setups already write them, and both
  are required (:ref:`full stack
  <pam-modes-pam-configuration-for-sshd>`).

- ``/etc/pam.d/systemd-user`` — unlike the files above,
  ``ob-bastion-setup`` does not regenerate this one (its distro
  ``session`` stack varies too much); it only inserts a small
  ``account`` bridge ahead of the distro stack so NSS-only SSO users
  can start ``user@.service`` (:doc:`Security scenarios
  </security-scenarios/index>`). Where the distro ships only
  ``/usr/lib/pam.d/systemd-user`` (Debian trixie onwards), the setup
  creates the ``/etc`` file with the bridge and an ``include`` of the
  vendor one.

.. note::

   Re-running a setup regenerates these files. Keep site additions in
   separate, higher-numbered ``sshd_config.d`` drop-ins where
   possible, and re-apply PAM changes after an upgrade (re-running
   ``ob-*-setup`` is the supported path — see the upgrade notes in the
   `CHANGELOG
   <https://github.com/linagora/open-bastion/blob/main/CHANGELOG.md>`__).

.. _permissions-dual-management:

Dual management
---------------

The two layers are complementary, not exclusive:

- SSO-only (recommended) — no local sudoers, no service accounts;
  every decision comes from LLNG groups. Simplest to reason about and
  audit.

- SSO + local — keep specific local exceptions alongside the SSO:
  a break-glass :doc:`service account </service-accounts>`, a
  host-local ``sudoers`` rule, or a stricter security scenario on a
  sensitive host. Local grants are not visible to the SSO, so
  inventory and review them deliberately.
