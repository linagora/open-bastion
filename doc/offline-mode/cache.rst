Cache administration
====================

The credential cache lets a desktop user authenticate while the LLNG portal
is unreachable: the PAM module stores what it needs at the last successful
online login, encrypted, and verifies it locally during the outage.
:doc:`Offline mode </offline-mode/index>` covers what else survives an
outage; this page covers the cache itself and the ``ob-cache-admin`` tool
that administers it.

What an entry holds, and how it is protected
--------------------------------------------

Each entry is written after a successful online login:

- the password, hashed with Argon2id at OWASP-recommended parameters —
  64 MB of memory, 3 iterations, 4 lanes, a 32-byte hash and a 16-byte
  random salt per user;

- the account attributes needed offline (``gecos``, shell, home), and the
  lockout state — no separate lockout file exists, so it cannot be cleared
  by editing the disk;

- the whole entry encrypted with AES-256-GCM, with a fresh random nonce on
  every write. The key is derived with PBKDF2-SHA256 from a root-only key
  file, ``/etc/open-bastion/cache.key``, or from ``/etc/machine-id`` when
  there is none, which is weaker.

Both the key file and the machine-id are machine-specific, which is what
makes a stolen cache file useless — and what invalidates every entry when
they change:

.. list-table::
   :header-rows: 1
   :widths: 26 30 44

   * - Change
     - Effect
     - What to do
   * - The virtual machine is cloned
     - Every entry becomes unreadable
     - Regenerate the machine-id after cloning.
   * - The system is reinstalled
     - Every entry becomes unreadable
     - Users re-authenticate online.
   * - ``cache.key`` is rotated
     - Every entry becomes unreadable
     - Users re-authenticate online.

Directory and key file
----------------------

.. code:: bash

   mkdir -p /var/cache/open-bastion/credentials
   chmod 700 /var/cache/open-bastion/credentials
   chown root:root /var/cache/open-bastion/credentials

   dd if=/dev/urandom of=/etc/open-bastion/cache.key bs=32 count=1 status=none
   chmod 600 /etc/open-bastion/cache.key

Entry files are created mode 0600, owner read/write only.
``ob-desktop-setup --offline`` generates the key file itself.

The cache directory, TTL, failure threshold and lockout duration are the
``offline_cache_*`` options of
:doc:`openbastion.conf(5) </references/man/openbastion.conf>`, or the
``offline_cache`` / ``no_offline_cache`` PAM arguments for one stack. The
failure threshold and lockout duration default to the compile-time
constants ``OFFLINE_CACHE_MAX_FAILED_ATTEMPTS`` (5) and
``OFFLINE_CACHE_LOCKOUT_DURATION`` (300 s).

File format
-----------

An entry is a ``.cred`` file named after a SHA256 hash of the username —
``SHA256("cred:<username>")`` truncated to 32 hex characters — which keeps
the directory from listing users:

::

   /var/cache/open-bastion/credentials/
   ├── a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6.cred
   ├── d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1.cred
   └── .cred_salt

Each file is an 8-byte ``OBCRED01`` magic header followed by the
AES-256-GCM encrypted JSON payload — version, user, creation and expiry
timestamps, last success, failed attempts, lockout deadline, the Argon2id
hash and salt, and the account attributes. The format is internal: use
``ob-cache-admin`` rather than the files.

Administration
--------------

``ob-cache-admin`` (``/usr/sbin``, from the ``open-bastion`` package)
administers the cache. All commands need root:

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Command
     - What it does
   * - ``ob-cache-admin list``
     - List the entries: one line per file with its modification time and
       size, and the total.
   * - ``ob-cache-admin stats``
     - Summarise the directory: number of entries, valid formats, disk
       usage, oldest and newest entry.
   * - ``ob-cache-admin show <user>``
     - Report what the cache holds for one user.
   * - ``ob-cache-admin invalidate <user>``
     - Delete one user's entry, with ``shred``; they authenticate online
       next time.
   * - ``ob-cache-admin invalidate-all``
     - Delete every entry and the salt file, after a typed confirmation;
       this forces a new key derivation.
   * - ``ob-cache-admin unlock <user>``
     - Clear a lockout. Entries are encrypted, so the tool cannot edit one
       in place: it offers to wait for the lockout to expire, to invalidate
       and re-cache, or to force an online authentication.
   * - ``ob-cache-admin cleanup``
     - Remove files with an invalid header, empty files and orphaned
       ``.tmp`` files. Expiry is checked at login time, not here.

Options: ``-c, --config <file>``, ``-d, --cache-dir <dir>``, ``-q,
--quiet``, ``-h, --help``. Environment: ``OB_CACHE_DIR``,
``OB_CONFIG_FILE``.

Monitoring
----------

Offline authentication events go to syslog with the ``auth`` facility:
successes and failures per user, entries refused because they are locked,
and the switch to offline mode when LLNG is unreachable. Worth watching:

- offline authentications per day — a spike means the portal was down;

- lockout events — several in an hour suggest a brute-force attempt;

- cache size and entry count — growth means users are not refreshing and
  cleanup is not running.

Troubleshooting
---------------

A user cannot log in offline. The entry is written only by a successful
online login, and it stops working once its TTL has expired or after
``ob-cache-admin invalidate``:

.. code:: bash

   grep offline_cache_ /etc/open-bastion/openbastion.conf
   sudo ob-cache-admin show <user>
   sudo ob-cache-admin stats

If the account is locked, wait for the lockout or run ``ob-cache-admin
unlock <user>``.

Nothing is cached at all. Credentials are cached only after an online
login, and only when ``offline_cache_enabled`` is true: check that the
option is set, that the cache directory is writable by root, and that the
key file exists.

The cache does not work. Check the directory permissions, that the service
that authenticates really loads ``pam_openbastion``
(``grep pam_openbastion /etc/pam.d/lightdm``), and syslog
(``journalctl | grep pam_openbastion``). After a machine-id or key-file
change, every user gets decryption errors: they re-authenticate online, and
``sudo ob-cache-admin invalidate-all`` clears what is left.

Security notes
--------------

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Risk
     - Mitigation
   * - A stolen device
     - Short TTL, lockout, full-disk encryption.
   * - Brute force
     - Argon2id with 64 MB of memory, lockout after 5 failures.
   * - Tampering with the cache
     - Owner-only permissions and the integrity check of AES-256-GCM.
   * - Extracting the key
     - A dedicated key file, mode 0600, readable only by root.

Recommendations: disable the cache on hosts that do not need it, which
reduces the attack surface; keep ``offline_cache_ttl`` as short as the
deployment tolerates; encrypt the disk; alert on repeated lockouts; run
``ob-cache-admin cleanup`` periodically; and review the auth log for
offline authentications. For compliance: credentials are hashed, never
stored in clear; the key stays in a root-only file; nothing leaves the
machine; and the whole cache can be cleared instantly with
``ob-cache-admin invalidate-all``.

See also
--------

- :doc:`Offline mode </offline-mode/index>` — the outage matrix, the two
  server-side caches, and :ref:`network revalidation
  <offline-mode-network-revalidation>`.
- :doc:`/desktop-sso` — the LightDM greeter that uses this cache.
