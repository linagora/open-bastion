Bastion configuration
=====================

When Open Bastion is installed, the ``ob-bastion-setup`` command is
added to the administrator's path, typically ``/usr/sbin/``.

The ``ob-bastion-setup`` command
--------------------------------

Use ``ob-bastion-setup`` to automate bastion configuration. A typical
call looks like:

.. code:: bash

   sudo ob-bastion-setup --portal https://auth.example.com --server-group bastion

This script performs multiple actions that are detailed below.

A backup of all existing files that are modified can be found under
``/var/backup/`` in a dedicated directory with ``open-bastion-setup-``
prefix. And in case of failure during the script execution, a rollback
is performed and original files are restored.

Summary of performed actions
----------------------------

Server enrollment
~~~~~~~~~~~~~~~~~

The script enrolls the bastion with LLNG. It uses OIDC "Device
Authorization", or a token file when the ``--token-file`` option is
given.

Note that when an existing token is found in
``/var/lib/open-bastion/token``, it is reused to bypass unnecessary
enrollment in case of multiple execution of the script.

Automatic refresh of server token is enabled through the
``ob-heartbeat.timer``.

Configuration of `sshd`
~~~~~~~~~~~~~~~~~~~~~~~

The script downloads from LLNG the SSH CA key to
``/etc/ssh/open-bastion_ca.pub`` .

The ``sshd`` configuration is changed through the
``/etc/ssh/sshd_config.d/00-open-bastion-bastion.conf`` file to:

  - Enable public key authentication with certificates signed by LLNG
    SSH CA key

  - Disable password authentication, root logins and X11 forwarding

  - Set ``AuthorizedPrincipalsCommand`` to make key fingerprint
    available to the PAM module responsible for access authorization

Access authorization
~~~~~~~~~~~~~~~~~~~~

The script configures the Open Bastion PAM module for SSH access, so
access authorization are centralized by LLNG and home directories are
created on the fly.

User and group resolution
~~~~~~~~~~~~~~~~~~~~~~~~~

NSS is configured for user and group resolution to come from LLNG.

SSH session recoding
~~~~~~~~~~~~~~~~~~~~

The ``sshd`` option ``ForceCommand`` is modified to execute
``ob-session-recorder`` when an SSH session starts.

The socket responsible for the collect of session recordings
``ob-record.socket`` is started. The service responsible for retention
of session recordings is scheduled through ``ob-session-prune.timer``.

The ``--disable-session-recorder`` option can be used when a
third-party mechanism is available to record SSH sessions.

Learn more on this topic in the dedicated section,
:doc:`/ssh-session-recording`.

.. TODO ADD Hop certificates for ``ob-ssh`` through ``ssh-proxy.conf``
   and enables ``ob-cert.socket``.

Optional features
-----------------

.. list-table:: Optional features configured by ``ob-bastion-setup``
   :header-rows: 1
   :widths: 30 12 12 46

   * - Maximum security scenario
     - Optional
     - No
     - Enable with ``--max-security``: certificates only, key revocation
       list refreshed every 30 minutes, and sudo with an LLNG token only.

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
     - Enable with ``--enable-service-keys``.

   * - Session containment hardening
     - Optional
     - No
     - Enable with ``--enable-hardening``.

   * - Audit trace with ``auditd``
     - Optional
     - No
     - Enable with ``--enable-audit-trace``. Requires the ``auditd``
       package.

Complete the configuration by reading on Crowdsec, etc.


