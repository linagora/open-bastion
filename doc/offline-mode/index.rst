Offline mode
============

The LLNG portal is not always reachable. This page says what keeps working
while it is down, and how the caches behind that answer are sized. The
credential cache a password is verified against during an outage has its
own page: :doc:`Cache administration </offline-mode/cache>`.

What works offline, and what needs the portal
---------------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 34 20 46

   * - Operation
     - Portal down
     - Why
   * - Resolve a user (``getent passwd``)
     - ✅ while the NSS cache holds
     - ``libnss_openbastion`` caches lookups; ``cache_ttl`` in
       ``nss_openbastion.conf``.
   * - SSH login with a valid certificate
     - ✅ while the authorization cache holds
     - ``sshd`` validates the certificate locally against
       ``TrustedUserCAKeys``; the PAM ``account`` phase answers from the
       authorization cache.
   * - SSH login with a plain key, or a plain ``ssh`` from the bastion to
       a backend
     - ✅ in the key modes only
     - Maximum security sets ``AuthorizedKeysFile none``, so ``sshd``
       refuses a plain key.
   * - ``sudo`` for an SSO user, once sudo's own timestamp has lapsed
     - ❌
     - The ``auth`` phase wants a fresh token from ``/pam/verify``: the
       cache holds authorizations, not authentications.
   * - ``sudo`` for an SSO user, while sudo's timestamp is still valid
     - ⚠️ if the authorization is cached too
     - ``sudo`` runs no ``auth`` while its credential is fresh; the
       ``account`` phase then answers from the cache.
   * - ``sudo`` for a service account
     - ✅
     - Its rights come from ``service-accounts.conf``, read locally.
   * - Hopping to a backend with :doc:`ob-ssh(1) </references/man/ob-ssh>`,
       :doc:`ob-scp(1) </references/man/ob-scp>` or
       :doc:`ob-sftp(1) </references/man/ob-sftp>`
     - ❌
     - Each mints a certificate through ``/pam/bastion-cert``; nothing
       there is cacheable.
   * - Enrolling a new server
     - ❌
     - The device flow needs the portal and an approval.
   * - Refreshing the KRL
     - ❌, the last list stays in force
     - ``RevokedKeys`` is a local file that simply stops being updated.
   * - Revoking a user
     - ❌ — the point that matters
     - Revocation happens in the portal; a cached authorization keeps
       working until its TTL expires.

The two ``sudo`` rows deserve their nuance: ``sudo`` keeps its own
credential (``timestamp_timeout``, 15 minutes by default, idle-based and
rearmed on each use), and while it is valid it does not run the PAM
``auth`` phase at all — no token is asked for, and the ``account`` phase
answers from the authorization cache. During an outage, an SSO user who
elevated recently therefore keeps elevating, and the failure lands on the
first ``sudo`` after the timestamp lapses.
``--enable-sudo-fresh-otp`` sets ``timestamp_timeout=0`` for the SSO group,
deliberately trading that availability for a fresh proof on every
elevation: the ⚠️ row becomes a ❌, and the designed answer is a break-glass
service account.

Two caches are involved, and they must be sized together:

- the NSS cache, ``cache_ttl`` in ``nss_openbastion.conf``: without it the
  user does not resolve at all, and nothing else matters;

- the PAM authorization cache, ``auth_cache_enabled`` in
  :doc:`openbastion.conf(5) </references/man/openbastion.conf>`: its TTL
  is not a local setting — the portal sends it in the ``/pam/authorize``
  response, from LLNG's ``pamAccessOfflineTtl``, with a 24-hour fallback.

A personal key on the bastion, as a fallback?
---------------------------------------------

The question comes up on every deployment. Under maximum security, the
answer is no, by design: backends accept only certificates signed by the
LLNG CA, whose key-id carries the bastion, so a plain user key is refused
by ``sshd`` before PAM is consulted, and ``ob-ssh`` cannot mint its
ephemeral certificate without the portal. That is the property that makes
the bastion the only way in.

In the key modes — a certificate setup without ``--max-security``, or SSH
keys with LLNG authorization — it works, under four conditions: the backend
is not under maximum security; the user is already in its authorization
cache, which only a recent online login put there; NSS still resolves them;
and their public key already sits in ``~/.ssh/authorized_keys`` on the
backend, placed out of band.

It is a deliberate trade, not free resilience: a long-lived private key now
lives on the bastion, its compromise is not bounded by a certificate TTL,
and it cannot be revoked through the portal; the hop is no longer vouched,
so ``allowed_bastions`` and the source-address pinning stop applying to it.
The audit trail, on the other hand, survives — a plain ``ssh`` run inside a
bastion session is recorded like any other command. What is not recorded is
a ``ssh -J`` ProxyJump from a workstation, which uses a channel the forced
command never sees, the gap R-S25 describes in
:doc:`the risk study </security/99-risk-reduce>`.

Prefer the two mechanisms designed for the outage: a break-glass service
account, whose rights are read locally with no portal call, and out-of-band
console access. Both are what R-S17 prescribes for a total lockout.

Desktop logins (LightDM)
------------------------

The greeter detects an unreachable portal, shows an offline banner and
falls back to the password prompt; there the PAM module verifies what it
has cached for the user, and the greeter switches back to SSO when the
portal answers again. ``ob-desktop-setup --offline`` sets it up, and
``offline_mode_enabled`` in the greeter's configuration turns the fallback
on or off. See :doc:`/desktop-sso` for the greeter itself, and
:doc:`cache` for the credential cache: the cryptography, the file format,
the ``offline_cache_*`` options, lockout handling and ``ob-cache-admin``.

.. _offline-mode-network-revalidation:

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

- ``ob-session-monitor``, a systemd service that polls the portal: when
  connectivity returns, it checks every offline session against
  ``/pam/userinfo`` and terminates the sessions whose account is gone.

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

One caveat on the matrix above and the maximum security answer: they are
derived from the code and the generated ``sshd`` configurations, but the
key-mode path has not been validated end to end in a lab — portal up, then
down, the cached authorization still admitting the key. Until it has, treat
those rows as analysis rather than as a tested procedure (#165).

.. toctree::
   :maxdepth: 1

   cache
