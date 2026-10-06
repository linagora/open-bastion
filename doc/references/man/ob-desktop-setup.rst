ob-desktop-setup
================

Synopsis
--------

::

   ob-desktop-setup -p URL [--offline] [--force] [--dry-run]

Description
-----------

``ob-desktop-setup`` configures a workstation to log in through
LemonLDAP::NG: it installs the LightDM display manager and its WebKit2
greeter with the Open Bastion theme, writes the greeter's configuration,
the PAM stack of the ``lightdm`` service and
``/etc/open-bastion/openbastion.conf``, and makes LightDM the display
manager of the machine.

With ``--offline`` it also turns on the credential cache, so a user can log
in with their password while the portal is unreachable, and generates the
key that cache is encrypted with. The cache itself is administered with
:doc:`ob-cache-admin(8) <ob-cache-admin>`, and its settings are the
``offline_cache_*`` options of
:doc:`openbastion.conf(5) <openbastion.conf>`.

Options
-------

.. option:: -p, --portal URL

   LemonLDAP::NG portal URL. Required.

.. option:: -o, --offline

   Enable the credential cache for offline logins, create the cache
   directory and generate ``/etc/open-bastion/cache.key`` when it is
   missing.

.. option:: -f, --force

   Overwrite the existing configuration. Without it, an existing
   ``openbastion.conf`` or PAM stack is left alone and reported.

.. option:: -n, --dry-run

   Print what would be done without changing anything.

.. option:: -h, --help

   Show the options.

What it writes
--------------

``/etc/lightdm/lightdm-webkit2-greeter.conf``
   An ``[open-bastion]`` section: ``portal_url``, ``desktop_login_path``
   (``/desktop/login``), ``check_online_interval`` and
   ``offline_mode_enabled``.

``/etc/pam.d/lightdm``
   ``auth sufficient pam_openbastion.so oauth2_token_auth``, with the
   distribution's stack kept as the fallback. An existing file is backed up
   to ``.bak`` before being replaced.

``/etc/open-bastion/openbastion.conf``
   The portal URL, ``oauth2_token_auth = true``, ``oauth2_token_min_ttl``,
   the logging settings, and — with ``--offline`` —
   ``offline_cache_enabled = true`` with its directory. Mode 0600.

``/etc/open-bastion/cache.key``
   Thirty-two random bytes, mode 0600, only with ``--offline`` and only
   when the file does not exist yet.

``/usr/share/lightdm-webkit/themes/open-bastion``
   The greeter theme.

``/var/cache/open-bastion/credentials``
   Cache directory, mode 0700, only with ``--offline``.

Examples
--------

.. code:: bash

   sudo ob-desktop-setup -p https://auth.example.com
   sudo ob-desktop-setup -p https://auth.example.com --offline
   sudo ob-desktop-setup -p https://auth.example.com --dry-run

Exit status
-----------

``0``
   Configuration completed.

``1``
   Failure, including a missing ``--portal``; also what ``--help`` exits
   with.

See also
--------

:doc:`openbastion.conf(5) <openbastion.conf>`,
:doc:`ob-cache-admin(8) <ob-cache-admin>`,
:doc:`ob-bastion-setup(8) <ob-bastion-setup>`

LemonLDAP::NG documentation: https://lemonldap-ng.org/
