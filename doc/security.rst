Security Features
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

See Also
--------

- :doc:`Configuration Reference </configuration>` - All configuration options
- :doc:`CrowdSec Integration </crowdsec>` - IP blocking and alerts
- :doc:`Service Accounts </service-accounts>` - SSH key authentication
- :doc:`Security Architecture </security/00-architecture>` - Detailed security analysis
- :doc:`Admin Guide </admin-guide>` - Complete administration guide
