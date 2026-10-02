ob-cache-admin
==============

Synopsis
--------

::

   ob-cache-admin <command> [options]

Description
-----------

``ob-cache-admin`` administers the offline credential cache of
``pam_openbastion``: the encrypted entries a password is verified against
while the LLNG portal is unreachable. It works on
``/var/cache/open-bastion/credentials``, or on the directory named by
``offline_cache_dir`` in ``openbastion.conf``, and every command requires
root.

The entries are encrypted and named after a hash of the username, so the
tool never prints a user list from the filenames: use ``show`` to ask about
one account. See :doc:`openbastion.conf(5) <openbastion.conf>` for the
cache options, and :doc:`ob-desktop-setup(8) <ob-desktop-setup>` for the
workstation side.

Commands
--------

.. option:: stats

   Summarise the cache: number of entries, how many are well formed, disk
   usage, and the oldest and newest entry.

.. option:: list

   List the entries, one line each, with their date and size. Filenames are
   hashes: they do not give the usernames.

.. option:: show <username>

   Report whether the cache holds an entry for that user, and what it can
   read from it.

.. option:: invalidate <username>

   Delete the user's entry, with ``shred``. They authenticate online next
   time, which recreates it.

.. option:: invalidate-all

   Delete every entry and the salt file, after a typed confirmation. The
   next login derives a new key.

.. option:: unlock <username>

   Clear a lockout. The entry is encrypted, so the tool cannot edit it in
   place: it explains the three ways out — wait for the lockout to expire,
   invalidate the entry and let the user re-authenticate online, or force
   the next authentication online — and offers to invalidate.

.. option:: cleanup

   Remove what cannot be used: files whose magic header is wrong, empty
   files and leftover ``.tmp`` files. Expiry is not checked here — the PAM
   module rejects an expired entry at login time.

Options
-------

.. option:: -c, --config FILE

   Read the cache directory from another configuration file.

.. option:: -d, --cache-dir DIR

   Work on another cache directory.

.. option:: -q, --quiet

   Print the essentials only.

.. option:: -h, --help

   Show the command list.

Environment
-----------

``OB_CACHE_DIR``
   Default cache directory, overridden by ``-d``.

``OB_CONFIG_FILE``
   Default configuration file, overridden by ``-c``.

Files
-----

``/var/cache/open-bastion/credentials``
   Cache directory, mode 0700, root-owned.

``<hash>.cred``
   One encrypted entry per user; an 8-byte ``OBCRED01`` header followed by
   the encrypted payload. Mode 0600.

``.cred_salt``
   Salt file of the cache key.

``/etc/open-bastion/cache.key``
   The 32-byte key the entries are encrypted with, when it exists.

Exit status
-----------

``0``
   The command ran.

``1``
   Failure, including being run without root.

See also
--------

:doc:`openbastion.conf(5) <openbastion.conf>`,
:doc:`ob-desktop-setup(8) <ob-desktop-setup>`,
:doc:`ob-bastion-setup(8) <ob-bastion-setup>`

Author
------

Xavier Guimard xguimard@linagora.com
