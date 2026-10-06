Offline desktop logins
======================

.. warning::

   Desktop SSO is **experimental (alpha)** and not production-ready: its
   authentication path has not been security-reviewed. It ships in the
   ``open-bastion-desktop`` package.

A workstation keeps letting its users log in while the LLNG portal is
unreachable, from a credential cache written at their last online login.
What a portal outage changes on a server — SSH, ``sudo``, the NSS and
authorization caches — is on :doc:`/offline-mode/index`.

Greeter fallback
----------------

The greeter detects an unreachable portal, shows an offline banner and
falls back to the password prompt; there the PAM module verifies what it
has cached for the user, and the greeter switches back to SSO when the
portal answers again. ``ob-desktop-setup --offline`` sets it up, and
``offline_mode_enabled`` in the greeter's configuration turns the fallback
on or off. See :doc:`/desktop-sso/index` for the greeter itself, and
:doc:`credentials-cache` for the credential cache: the cryptography, the
file format, the ``offline_cache_*`` options, lockout handling and
``ob-cache-admin``.

.. _desktop-sso-network-revalidation:

Network revalidation
--------------------

An offline session is revalidated once the portal answers again, by three
complementary mechanisms:

- the PAM module, when the user unlocks their screen with a password: it
  re-authenticates online, refreshes the cache and clears the offline
  session marker, and refuses the unlock if the account has been revoked —
  terminating the session itself is ``ob-session-monitor``'s business;

- the greeter, which refreshes the OAuth2 access token through
  ``/desktop/refresh`` before falling back to the SSO page or to the
  offline path;

- :doc:`ob-session-monitor(8) </references/man/ob-session-monitor>`, a
  systemd service that polls the portal: when connectivity returns, it
  checks every offline session against ``/pam/userinfo`` and terminates the
  sessions whose account is gone.

.. list-table::
   :header-rows: 1
   :widths: 16 16 20 48

   * - Network
     - SSO portal
     - Duration
     - Action
   * - Down
     - Down
     - any
     - Normal offline mode.
   * - Up
     - Up
     - —
     - Revalidate the sessions.
   * - Up
     - Down
     - under the timeout
     - A warning is logged.
   * - Up
     - Down
     - past the timeout
     - Every offline session is terminated.

The last two rows are the anti-firewall-bypass protection: a local rule
that blocks the portal while the rest of the network works ends with every
offline session terminated once ``offline_max_sso_unreachable`` (1 hour by
default) has passed.

.. code:: ini

   # defaults
   offline_revalidation_enabled = true
   offline_revalidation_grace = 14400    # force online re-auth after 4 h
   offline_max_sso_unreachable = 3600    # firewall-bypass timeout, 1 h

.. code:: bash

   sudo systemctl enable --now ob-session-monitor
   journalctl -u ob-session-monitor

Limitations
-----------

- The first login must be online: with no cached entry, there is no
  offline login.

- A password changed in the portal keeps its old cached value working
  until the next online login refreshes the entry.

- Group changes need an online login to propagate.

- MFA is bypassed offline: the password is all there is.

- Only the attributes that were cached are available.
