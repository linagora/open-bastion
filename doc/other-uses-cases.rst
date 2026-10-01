Other uses cases
==================

🚧

Standalone server configuration
-------------------------------

A standalone server authenticates users directly with LLNG, without going through a bastion.

.. mermaid::

   flowchart LR
       User -->|SSH| Standalone[Standalone Server]
       Standalone -->|Verify| LLNG[LLNG Portal]

Step 1: install packages
~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: bash

   # Debian/Ubuntu
   apt-get install open-bastion

   # RHEL/Rocky
   dnf install open-bastion

Step 2: create configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: bash

   cat > /etc/open-bastion/openbastion.conf << 'EOF'
   # LLNG Portal URL
   portal_url = https://auth.example.com

   # OIDC client credentials
   client_id = pam-access
   client_secret = your-client-secret

   # Server group (must match LLNG configuration)
   server_group = standalone

   # Token file (runtime state, refreshed automatically by ob-heartbeat)
   # The token lives under /var/lib/open-bastion/ (FHS: runtime state, not config).
   server_token_file = /var/lib/open-bastion/token

   # Security settings
   verify_ssl = true
   timeout = 10

   # Logging
   log_level = warn
   audit_enabled = true
   audit_to_syslog = true

   # Rate limiting
   rate_limit_enabled = true
   rate_limit_max_attempts = 5
   EOF

   chmod 600 /etc/open-bastion/openbastion.conf

Step 3: enroll server
~~~~~~~~~~~~~~~~~~~~~

.. code:: bash

   ob-enroll -g standalone

Follow the instructions to approve the server in LLNG.

Step 4: configure PAM
~~~~~~~~~~~~~~~~~~~~~

.. code:: bash

   cat > /etc/pam.d/sshd << 'EOF'
   # Authentication: LLNG token or Unix password
   auth       sufficient   pam_openbastion.so
   auth       sufficient   pam_unix.so nullok try_first_pass
   auth       required     pam_deny.so

   # Authorization: LLNG checks access
   account    required     pam_openbastion.so
   account    required     pam_unix.so

   # Session
   session    required     pam_unix.so
   EOF

Step 5: configure SSH
~~~~~~~~~~~~~~~~~~~~~

.. code:: bash

   cat >> /etc/ssh/sshd_config << 'EOF'

   # LLNG PAM Authentication
   UsePAM yes
   PasswordAuthentication yes
   KbdInteractiveAuthentication yes
   PubkeyAuthentication yes
   EOF

   systemctl restart sshd

Step 6: test
~~~~~~~~~~~~

.. code:: bash

   # From another terminal (keep current session open!)
   ssh user@server
   # Enter LLNG token as password

Standalone server (no bastion)
------------------------------

If you just want a **single, isolated server** that users SSO-authenticate into directly — no jump host, no bastion→backend hop — generate one installer with the **standalone** role and run it on that host. There is no allowlist and no second machine to coordinate:

.. code:: bash

   ob-builder --output-shell bootstrap-standalone.sh   # answer "standalone" to target role
   scp bootstrap-standalone.sh host-1:/tmp/
   ssh -t host-1 'sudo /tmp/bootstrap-standalone.sh --yes'

A standalone host is simultaneously its own bastion and backend, so it runs the same code as a bastion and the full stack applies. ``ob-standalone-setup`` **does** exist: it is a symlink to ``ob-bastion-setup`` (as ``ob-backend-setup`` is), and invoking it under that name makes the script default ``--node-role`` to ``standalone`` instead of ``bastion`` (an explicit ``--node-role`` always wins, and configures the role it names). Either command works on a standalone host; ``ob-standalone-setup`` just records the right role without extra flags. Users then log in with their SSO certificate exactly as they would on a bastion — they just don't hop anywhere afterwards. The same :ref:`port-22 lockdown note <shell-quickstart-step-2--deploy-the-bastion>` applies: run setup while you still have a working management session.

