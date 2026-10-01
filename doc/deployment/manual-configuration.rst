Manual configuration
====================

Both automated paths — :doc:`Ansible deployment
</deployment/ansible-deployment>` and the :doc:`self-extracting installer
</deployment/self-extracting-installer>` — end in the same commands:
``ob-enroll``, then the setup command for the host's role. This page
describes what those commands do, for an administrator who configures a host
without the generated artefacts, or who wants to know what they will change
before running them.

   **The step-by-step route**, with the file contents and the command to type
   at each step, is the :ref:`maximum security deployment
   <admin-guide-maximum-security-deployment>` section of the
   :doc:`/admin-guide`.

The command
-----------

``ob-bastion-setup``, ``ob-backend-setup`` and ``ob-standalone-setup`` are
the same command under three names: the name chooses the role the host is
configured for, and ``--node-role`` overrides it. A typical call looks like:

.. code:: bash

   sudo ob-bastion-setup --portal https://auth.example.com --server-group bastion

Use the ``server_group`` the portal knows the host by
(:ref:`Server groups <llng-configuration-server-groups>`), and run it on
each bastion, backend and standalone host.

A backup of every file the command modifies is left under ``/var/backup/``
in a directory prefixed with ``open-bastion-setup-``, and a failure during
the run rolls the modified files back.

What it does
------------

- **Server enrollment** — enrolls the host with LLNG through OIDC "Device
  Authorization", or with a token file when ``--token-file`` is given. An
  existing token at ``/var/lib/open-bastion/token`` is reused, so re-running
  the command does not enroll twice, and ``ob-heartbeat.timer`` keeps the
  access token fresh afterwards.

- **SSH certificate authority** — downloads the LLNG SSH CA public key to
  ``/etc/ssh/open-bastion_ca.pub``.

- **``sshd``** — writes ``/etc/ssh/sshd_config.d/00-open-bastion-<role>.conf``
  and restarts ``sshd``. The host then accepts SSH certificates signed by
  that CA, refuses passwords, root logins and X11 forwarding, and points
  ``AuthorizedPrincipalsCommand`` at the helper that makes the key
  fingerprint available to the PAM module.

- **Access authorization** — configures the Open Bastion PAM module, so LLNG
  decides who may log in, and home directories are created on the fly.

- **User and group resolution** — configures NSS so users and groups come
  from LLNG.

- **``sudo``** — writes the ``sudoers`` drop-in and, where the role and the
  options call for it, the PAM stack that governs ``sudo``.

What each role adds
-------------------

**Bastion**, the SSH entry point:

- **Session recording** — ``sshd``'s ``ForceCommand`` runs
  :doc:`ob-session-recorder(8) </references/man/ob-session-recorder>`, the
  socket ``ob-record.socket`` collects the recordings and
  ``ob-session-prune.timer`` schedules their retention. Pass
  ``--disable-session-recorder`` where a third-party mechanism records
  sessions instead. See :doc:`/ssh-session-recording`.

**Backend**, a server reached only through a bastion:

- **Account creation** — a PAM session step creates the Unix account on
  first login, which ``--no-create-user`` disables.
- **Accepted bastions** — the certificate hop is only accepted when the
  certificate's key-id carries a ``bastion=`` listed in
  ``/etc/open-bastion/allowed_bastions`` (``--allowed-bastions`` sets it at
  setup time). Left empty, any bastion of the same server group is accepted;
  see :doc:`ob-bastion-setup(8) </references/man/ob-bastion-setup>`.

**Standalone**, a host users log in to directly, with no backend behind it:
the bastion configuration without the hop. The
:doc:`/other-uses-cases` page walks one through.

Optional features
-----------------

.. list-table:: Optional features configured by the setup command
   :header-rows: 1
   :widths: 30 12 12 46

   * - Maximum security scenario
     - Optional
     - No
     - Enable with ``--max-security``: certificates only, key revocation
       list refreshed every 30 minutes, and sudo with an LLNG token only.
       See :doc:`/pam-modes`.

   * - Sudo through LLNG
     - Optional
     - No
     - Only configured under maximum security (``--max-security``).

   * - Fresh LLNG token on every sudo
     - Optional
     - No
     - Enable with ``--enable-sudo-fresh-otp``. Only effective together
       with ``--max-security``.

   * - SSH access for service accounts
     - Optional
     - No
     - Enable with ``--enable-service-keys``. See
       :doc:`/service-accounts`.

   * - Session containment hardening
     - Optional
     - No
     - Enable with ``--enable-hardening``. See :doc:`/hardening`.

   * - Audit trace with ``auditd``
     - Optional
     - No
     - Enable with ``--enable-audit-trace``. Requires the ``auditd``
       package. See :doc:`/audit`.

Every option, and what each one writes, is in
:doc:`ob-bastion-setup(8) </references/man/ob-bastion-setup>`. To undo what
this command configured, before removing the package, use
:doc:`ob-uninstall(8) </references/man/ob-uninstall>`.
