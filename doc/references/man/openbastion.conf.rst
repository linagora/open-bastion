openbastion.conf
================

Synopsis
--------

::

   /etc/open-bastion/openbastion.conf

Description
-----------

``pam_openbastion.so`` reads its settings from
``/etc/open-bastion/openbastion.conf``, one ``key = value`` per line. The
module reads the file once per session, so a change applies to the next
login, without restarting anything.

A file written by the setup scripts, ``ob-desktop-setup``, an ``ob-builder``
installer or Ansible role, or the package's debconf questions holds the
host's settings first, then every option below, commented out with its
default value, copied from
``/usr/share/open-bastion/openbastion.conf.reference``. A key set twice
takes its last value, so an option already set above the reference is
changed where it is set.

Syntax
------

- A ``#`` or ``;`` at the start of a line comments the whole line out; a
  blank line is ignored.

- A ``#`` preceded by whitespace ends the value: ``verify_ssl = true # not
  that`` sets ``true``. A ``#`` inside a token is kept, so
  ``portal_url = https://sso.example.com/#frag`` is taken literally. Quote
  the value — ``server_group = "prod # 2"`` — to keep a ``#`` that
  whitespace precedes.

- The values of ``client_secret``, ``notify_secret``, ``webhook_secret``,
  ``request_signing_secret``, ``crowdsec_bouncer_key``, ``crowdsec_password``
  and ``cert_pin`` are never stripped.

- Booleans accept exactly ``true``, ``yes``, ``1``, ``on`` and ``false``,
  ``no``, ``0``, ``off`` — lowercase only. Anything else (``TRUE``,
  ``tru``, an empty value) is a fatal error: the module logs the key and
  refuses the transaction rather than run with a guessed security posture.
  The same strict rule applies to boolean PAM module arguments.

- An unknown key is logged to syslog and ignored, so a typo is visible
  without breaking every login.

The file must be a regular file, owned by root, with no access for group or
others (``0600``); a symlink is refused. The module refuses to run on a
file that fails this. A configuration it cannot use — no ``portal_url`` or
client credentials, a non-HTTPS portal URL while ``verify_ssl`` is on, an
unparseable boolean — is fatal too, with the reason in syslog.

Options
-------

Required
~~~~~~~~

.. option:: portal_url

   LemonLDAP::NG portal URL. It must start with ``https://`` as long as
   ``verify_ssl`` is on, which is the default. Alias: ``portal``.

.. option:: client_id

   OIDC client ID of the PAM-access relying party, as declared in LLNG.

.. option:: client_secret

   OIDC client secret. Not required when ``authorize_only`` is on.

Server identity
~~~~~~~~~~~~~~~

.. option:: server_token_file

   File holding the access token ``ob-enroll`` obtained for this host. The
   setup scripts write ``/var/lib/open-bastion/token``. Alias:
   ``token_file``.

.. option:: server_group

   Server group this host belongs to, as declared in LLNG's
   ``pamAccessServerGroups``. Default: ``default``.

.. option:: node_role

   Role reported to the portal in each heartbeat: ``bastion``,
   ``standalone`` or ``backend``. Written by the setup scripts; read by
   ``ob-heartbeat``, not by the PAM module.

.. option:: report_sessions

   Have ``ob-heartbeat`` report the connected users (name, source host,
   tty, login time) in each heartbeat. The portal stores the list per
   machine. Privacy-sensitive: set it to ``false`` to turn the reporting
   off. Default: ``true``.

.. option:: max_reported_sessions

   Most sessions sent in one heartbeat; the extra ones are dropped and a
   warning is logged. Default: ``200``.

HTTP client
~~~~~~~~~~~

.. option:: timeout

   HTTP timeout in seconds, 1 to 300. Default: ``10``.

.. option:: verify_ssl

   Verify the portal's TLS certificate. ``false`` is for test setups only:
   it allows an ``http://`` portal URL and disables verification, in the
   module and in the commands that read this file. Default: ``true``.

.. option:: ca_cert

   PEM file holding the CA that signed the portal's certificate, for a
   private CA.

.. option:: min_tls_version

   Minimum TLS version, as ``12`` (TLS 1.2) or ``13`` (TLS 1.3). Default:
   ``13``; any other value falls back to it.

.. option:: cert_pin

   Public-key pinning, as ``curl``'s ``CURLOPT_PINNEDPUBLICKEY``: a
   semicolon-separated list of ``sha256//<base64>`` pins or paths to PEM
   files. When set, the portal's certificate public key must match one of
   them. The value is taken literally.

Request signing
~~~~~~~~~~~~~~~

.. option:: request_signing_secret

   Shared HMAC-SHA256 secret that turns on the ``X-Signature-256`` /
   ``X-Timestamp`` / ``X-Nonce`` headers on every ``/pam/`` call this host
   makes. It must equal the portal's ``pamAccessRequestSigningSecret``:
   one value for the whole fleet, proving fleet membership rather than
   identifying a caller. Generate one with ``openssl rand -hex 32``. The
   value is taken literally, ``#`` included.

Authorization cache (offline mode)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. option:: auth_cache_enabled

   Cache the portal's authorization decisions, so an already-authorized
   user can log in while the portal is unreachable. The lifetime of a
   cached decision is decided by the portal, not here. Default: ``true``.
   Alias: ``auth_cache``.

.. option:: auth_cache_dir

   Cache directory. Default: ``/var/cache/open-bastion/auth``.

.. option:: auth_cache_force_online

   Force-online file. While it exists, the cache is not consulted: an
   empty file forces every user online, and a file listing usernames —
   one per line, blank lines and ``#`` comments ignored — forces only
   those users. When the cache is not consulted for a user, that user's
   authorization goes to the portal, which is what bounds an offline
   session that outlived its grace period; see
   :doc:`ob-session-monitor(8) <ob-session-monitor>`. Default:
   ``/etc/open-bastion/force_online``. Alias: ``force_online_file``.

Authorization mode
~~~~~~~~~~~~~~~~~~

.. option:: authorize_only

   Skip the password check: ``pam_sm_authenticate`` always succeeds and
   only ``pam_sm_acct_mgmt`` performs the authorization, for setups where
   ``sshd`` authenticates the user with a key or certificate. Default:
   ``false``.

Logging and audit
~~~~~~~~~~~~~~~~~

.. option:: log_level

   ``error``, ``warn``, ``info``, ``debug``, or ``0`` to ``3``. Default:
   ``warn``. Alias: ``debug``.

.. option:: audit_enabled

   Write the structured audit log. Default: ``true``. Alias: ``audit``.

.. option:: audit_log_file

   Audit log path. Default: ``/var/log/open-bastion/audit.json``. Alias:
   ``audit_file``.

.. option:: audit_to_syslog

   Also emit audit events to syslog. Default: ``true``. Alias:
   ``audit_syslog``.

.. option:: audit_level

   ``critical`` (0), ``auth`` (1, authentication events) or ``all`` (2).
   Default: ``auth``.

Rate limiting
~~~~~~~~~~~~~

.. option:: rate_limit_enabled

   Throttle repeated authentication failures, per user and source address.
   Default: ``true``. Alias: ``rate_limit``.

.. option:: rate_limit_state_dir

   State directory of the limiter. Default:
   ``/var/lib/open-bastion/ratelimit``.

.. option:: rate_limit_max_attempts

   Failures allowed before the first lockout, 1 to 100. Default: ``5``.

.. option:: rate_limit_initial_lockout

   First lockout, in seconds, 1 to 3600. Default: ``30``.

.. option:: rate_limit_max_lockout

   Longest lockout, in seconds, 60 to 86400. Default: ``3600``.

.. option:: rate_limit_backoff_mult

   Multiplier applied to the lockout at each repeat, 1.1 to 10.0. Default:
   ``2.0``.

Token binding
~~~~~~~~~~~~~

The four settings below, and the PAM arguments that set the same fields,
are parsed and kept but not read by any component of this release: the
server token is renewed, refresh token included, by ``ob-heartbeat``.

.. option:: token_bind_ip

   Bind a server token to the client address it was issued to. Default:
   ``true``. Alias: ``bind_ip``; the PAM argument ``no_bind_ip`` turns it
   off for one stack.

.. option:: token_bind_fingerprint

   Bind a server token to the client fingerprint. Default: ``false``.
   Alias: ``bind_fingerprint``.

.. option:: token_check_revocation

   Check the token against the portal's revocation state on each use.
   Default: ``false``. Alias: ``check_revocation``.

.. option:: token_rotate_refresh

   Rotate the refresh token at each renewal. Default: ``true``. Alias:
   ``rotate_refresh``.

User creation
~~~~~~~~~~~~~

.. option:: create_user

   Create the Unix account on first login when it does not exist yet: the
   module appends it to ``/etc/passwd`` and ``/etc/shadow``. The primary
   group must already exist locally. Default: ``false``. Alias:
   ``create_user_enabled``; the PAM argument ``create_user`` turns it on
   for one stack.

.. option:: create_user_shell

   Login shell of a created account, when the portal supplies none or an
   unapproved one. It must be in ``approved_shells``. Default:
   ``/bin/bash``.

.. option:: create_user_home_base

   Parent directory of a created account's home. Default: ``/home``.
   Alias: ``home_base``.

.. option:: create_user_skel

   Skeleton directory copied into the new home (``cp -rTP``). It must be
   an absolute path, owned by root, with no symlink in it. Default:
   ``/etc/skel``. Alias: ``skel``.

.. option:: create_user_groups

   Additional groups of a created account, comma-separated. Accepted and
   kept; the module does not apply it in this release.

.. option:: approved_shells

   Colon-separated shells an account may use. Default: ``/bin/bash``,
   ``/bin/sh``, ``/bin/zsh``, ``/bin/dash``, ``/bin/fish`` and their
   ``/usr/bin`` variants.

.. _openbastion-conf-approved_home_prefixes:

.. option:: approved_home_prefixes

   Colon-separated prefixes a home directory may live under. Default:
   ``/home:/var/home``.

Group synchronization
~~~~~~~~~~~~~~~~~~~~~

.. option:: allowed_managed_groups

   Comma-separated whitelist (defence in depth) of LLNG-managed groups the
   module may create or change locally. Unset means no restriction beyond
   the portal's own ``managed_groups``.

Service accounts
~~~~~~~~~~~~~~~~

.. option:: service_accounts_file

   File declaring the key-only local accounts. Default:
   ``/etc/open-bastion/service-accounts.conf``. Alias:
   ``service_accounts``.

Notifications
~~~~~~~~~~~~~

.. option:: notify_enabled

   Send security events to a webhook. Default: ``false``. Alias:
   ``notify``.

.. option:: notify_url

   Webhook URL. Alias: ``webhook_url``.

.. option:: notify_secret

   HMAC secret signing the webhook body. Alias: ``webhook_secret``. The
   value is taken literally.

CrowdSec
~~~~~~~~

.. option:: crowdsec_enabled

   Consult CrowdSec: a bouncer check before authentication, and alerts
   after it. Default: ``false``. Alias: ``crowdsec``.

.. option:: crowdsec_url

   CrowdSec LAPI URL. Default: ``http://127.0.0.1:8080``.

.. option:: crowdsec_timeout

   HTTP timeout for CrowdSec requests, in seconds, 1 to 60. Default:
   ``5``.

.. option:: crowdsec_fail_open

   ``true`` lets a login proceed when CrowdSec cannot be reached,
   ``false`` refuses it. Default: ``true``.

.. option:: crowdsec_bouncer_key

   Bouncer API key, from ``cscli bouncers add``. Required for the
   pre-authentication IP check.

.. option:: crowdsec_action

   What to do with a banned address: ``reject`` or ``warn``. Any other
   value is ignored, keeping the default ``reject``.

.. option:: crowdsec_whitelist

   Comma-separated addresses and CIDR ranges that bypass the CrowdSec
   check, IPv4 and IPv6.

.. option:: crowdsec_machine_id

   Machine ID, from ``cscli machines add``, for sending alerts.

.. option:: crowdsec_password

   Machine password. The value is taken literally.

.. option:: crowdsec_scenario

   Scenario name carried by the alerts. Default:
   ``open-bastion/ssh-auth-failure``.

.. option:: crowdsec_send_all_alerts

   ``true`` sends every authentication failure as an alert, ``false`` only
   when the auto-ban threshold is reached. Default: ``true``.

.. option:: crowdsec_max_failures

   Failures from one address before it is banned, 0 to 100; ``0`` disables
   auto-banning and keeps reporting. Default: ``5``.

.. option:: crowdsec_block_delay

   Window, in seconds, over which those failures are counted, 10 to 86400.
   Default: ``180``.

.. option:: crowdsec_ban_duration

   Ban duration, as ``4h``, ``1d``, ``1w``. Default: ``4h``.

SSH key policy
~~~~~~~~~~~~~~

.. option:: ssh_key_policy_enabled

   Refuse a connection whose key type or size is not allowed below.
   Enforcement is fail-closed: a login whose key cannot be identified is
   denied. It needs an ``sshd`` configured by a recent setup script
   (``AuthorizedPrincipalsCommand ... %t %k``), which is how the module
   learns which key was presented. Default: ``false``. Alias:
   ``ssh_key_policy``.

.. option:: ssh_key_allowed_types

   Comma-separated key types: ``ed25519``, ``ecdsa``, ``rsa``, ``dsa``,
   ``sk`` (FIDO2) or ``all``. ``all`` does not include DSA. Default: all
   types. Alias: ``ssh_allowed_types``.

.. option:: ssh_key_min_rsa_bits

   Minimum RSA key size, 1024 to 16384. Default: ``2048``. Alias:
   ``ssh_min_rsa_bits``.

.. option:: ssh_key_min_ecdsa_bits

   Minimum ECDSA key size, in bits, 256 to 521 (P-256, P-384, P-521).
   Default: ``256``. Alias: ``ssh_min_ecdsa_bits``.

.. option:: fingerprint_required

   Refuse an SSH login whose key fingerprint cannot be recovered, instead
   of authorizing it without the binding. Only for hosts that run the
   principals helper (the certificate scenarios): where there is never a
   fingerprint, every login would be denied. Default: ``false``. Alias:
   ``ssh_fingerprint_required``.

Cache brute-force protection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. option:: cache_rate_limit_enabled

   Count every cache lookup, hits included, per user, and lock out after
   ``cache_rate_limit_max_attempts``. Only an authorized cache hit resets
   the counter. Default: ``false``. Alias: ``cache_rate_limit``.

.. option:: cache_rate_limit_max_attempts

   Cache lookups allowed before lockout, 1 to 100. Default: ``3``.

.. option:: cache_rate_limit_lockout_sec

   First lockout, in seconds, 1 to 86400, doubling on each repeat. Default:
   ``60``. Alias: ``cache_rate_limit_lockout``.

.. option:: cache_rate_limit_max_lockout_sec

   Longest lockout, in seconds, 60 to 86400. Default: ``3600``. Alias:
   ``cache_rate_limit_max_lockout``.

Desktop SSO
~~~~~~~~~~~

These settings are compiled into the desktop build of the module only, for
the LightDM greeter and offline sessions.

.. option:: oauth2_token_auth

   Accept OAuth2 access tokens instead of one-time PAM tokens, validated
   through ``/oauth2/introspect``. Default: ``false``.

.. option:: oauth2_token_cache

   Cache successful OAuth2 authentications for offline fallback. Default:
   ``true``.

.. option:: oauth2_token_min_ttl

   Refuse a token whose remaining lifetime is below this many seconds, 0
   to 3600. Default: ``60``.

.. option:: offline_cache_enabled

   Cache credentials, with Argon2id and AES-256-GCM, for offline
   authentication. Default: ``false``.

.. option:: offline_cache_dir

   Credential cache directory, root-owned mode 0700. Default:
   ``/var/cache/open-bastion/credentials``.

.. option:: offline_cache_ttl

   How long a cached credential stays valid, 3600 to 2592000 seconds.
   Default: ``604800`` (7 days).

.. option:: offline_cache_max_failures

   Failed offline attempts before the entry is locked, 1 to 20; unlocking
   needs an online authentication. Default: ``5``.

.. option:: offline_cache_lockout

   Lockout duration in seconds, 60 to 86400. Default: ``300``.

.. option:: offline_cache_key_file

   File holding the 32-byte encryption key, root-owned mode 0600. Default:
   ``/etc/open-bastion/cache.key``.

.. option:: offline_revalidation_enabled

   Have the session monitor revalidate offline sessions once the network
   is back. Default: ``true``.

.. option:: offline_revalidation_grace

   Age, in seconds, past which an offline cache forces an online
   re-authentication at the next unlock, 600 to 86400. Default:
   ``14400``.

.. option:: offline_max_sso_unreachable

   Longest time the portal may be unreachable while the network is up
   before offline sessions are terminated, 600 to 86400. Default:
   ``3600``.

Accepted but not read from this file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``cache_enabled``, ``cache_dir``, ``cache_ttl``, ``create_home`` and
``default_shell`` are written into ``openbastion.conf`` by the setup
scripts and by ``ob-builder``, and are recognised so they are not reported
as typos. The module that reads them is the NSS module, from its own file,
``/etc/open-bastion/nss_openbastion.conf``.

PAM module arguments
--------------------

The same settings can be given on a ``pam_openbastion.so`` line, where
they override the file for that stack only. ``conf=/path/to/file`` selects
another file, ``key=value`` sets any option above (``portal_url=…``,
``server_group=…``, ``verify_ssl=false``, …), and the flags are: ``debug``,
``authorize_only``, ``no_auth_cache``, ``insecure`` (or
``no_verify_ssl``), ``no_audit``, ``no_syslog``, ``no_rate_limit``,
``no_bind_ip``, ``bind_fingerprint``, ``check_revocation``,
``no_rotate_refresh``, ``create_user``, ``no_create_user``.

Files
-----

``/etc/open-bastion/openbastion.conf``
   This file's usual path; ``conf=`` names another one.

``/usr/share/open-bastion/openbastion.conf.reference``
   Every option, commented out, with its default: the reference appended
   to a generated ``openbastion.conf``. Not a configuration file: an
   upgrade replaces it.

``/etc/open-bastion/nss_openbastion.conf``
   Configuration of the NSS module, and of the keys listed under "Accepted
   but not read from this file".

``/etc/open-bastion/service-accounts.conf``
   Key-only local accounts, declared by ``service_accounts_file``.

``/var/lib/open-bastion/token``
   Server access token, written by ``ob-enroll``.

See also
--------

:doc:`ob-enroll(8) <ob-enroll>`,
:doc:`ob-heartbeat(8) <ob-heartbeat>`,
:doc:`ob-bastion-setup(8) <ob-bastion-setup>`,
:doc:`ob-uninstall(8) <ob-uninstall>`

The exhaustive security catalogue is in the HTML documentation shipped in
``/usr/share/doc/open-bastion/html``.
