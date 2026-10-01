Maximum security
================

What the :doc:`default scenario </pam-modes>` relies on underneath: the
security model, the ``sshd`` drop-in it writes, the revocation list, the
fingerprint binding, and what ``sudo``'s timestamp cache means in practice.

The security model
------------------

::

   ┌──────────────────────────┐       ┌──────────────────────────┐
   │       SSH Access         │       │    sudo Escalation       │
   │                          │       │                          │
   │  SSO Certificate (1 yr)  │       │  LLNG Token (5-60 min)  │
   │  + /pam/authorize        │       │  + /pam/authorize        │
   │                          │       │  (sudo_allowed=true)     │
   │  "I have the right       │       │  "I want to perform a    │
   │   to be here"            │       │   privileged action      │
   │                          │       │   now"                   │
   └──────────────────────────┘       └──────────────────────────┘
            │                                    │
            ▼                                    ▼
      Revocation:                         Revocation:
      - KRL (immediate)                   - Disable LLNG account
      - Disable LLNG account              - Remove sudo_allowed
      - Remove from groups                  (immediate effect)

The ``sshd`` drop-in
--------------------

``ob-bastion-setup --max-security`` writes
``/etc/ssh/sshd_config.d/60-max-security.conf``:

.. code:: text

   UsePAM yes
   PasswordAuthentication no                         # No SSH passwords
   KbdInteractiveAuthentication no
   PubkeyAuthentication yes                          # SSH certificates only
   TrustedUserCAKeys /etc/ssh/open-bastion_ca.pub
   AuthorizedKeysFile none                           # No unsigned keys
   RevokedKeys /etc/ssh/revoked_keys                 # KRL mandatory
   ExposeAuthInfo yes                                # For certificate audit
   # Bastion: two tokens (%u %f). Backend: three (%u %f %i) — %i carries the
   # bastion= key-id checked against /etc/open-bastion/allowed_bastions.
   AuthorizedPrincipalsCommand /usr/local/sbin/ob-ssh-principals %u %f
   AuthorizedPrincipalsCommandUser nobody
   PermitRootLogin no
   PermitEmptyPasswords no

**Do not replace ``ob-ssh-principals`` with ``/bin/echo %u``.** Earlier
revisions of this documentation showed that shortcut; it silently disables
two controls:

- ``%f`` is what feeds the :ref:`SSH fingerprint binding
  <pam-modes-ssh-fingerprint-binding-on-pamauthorize-and-pamverify>`: the
  helper drops it in ``/run/open-bastion/ssh-fp/<pid>.fp`` for
  ``pam_openbastion`` to read. With ``/bin/echo`` no fingerprint is ever
  captured, so the binding degrades to "not sent".
- On **backends** the helper is invoked with a third token,
  ``AuthorizedPrincipalsCommand /usr/local/sbin/ob-ssh-principals %u %f
  %i``, and ``%i`` (the certificate key-id) is what carries
  ``bastion=<id>``, checked against
  ``/etc/open-bastion/allowed_bastions`` **before PAM runs**. With
  ``/bin/echo`` any CA-signed certificate whose principal matches the
  login name is accepted, including a direct user SSO certificate that
  never went through a bastion.

The helper is written to ``/usr/local/sbin/ob-ssh-principals`` at setup
time by ``ob-bastion-setup`` / ``ob-backend-setup``; it is not shipped as a
packaged file.

.. _pam-modes-how-often-you-are-actually-prompted-sudos-timestamp-cache:

How often you are actually prompted: sudo's timestamp cache
-----------------------------------------------------------

The :doc:`scenario </pam-modes>` promises a fresh SSO re-authentication
for each ``sudo``. That claim holds **at the SSO layer**, and it is worth
being precise about what an operator sees, because the two are not the
same thing.

What the SSO guarantees:

- The LLNG temporary token is **one-time**. ``/pam/verify`` consumes it
  server-side on first use, so a token that has been used cannot be
  replayed — not by the user, not by anyone who captured it.
- Its lifetime is short (``llng pam_token`` mints a token with a TTL
  measured in minutes).
- Authorization is re-evaluated **live at every escalation**:
  ``pam_openbastion`` calls the portal each time, so revoking
  ``sudo_allowed`` or disabling the account takes effect on the next
  ``sudo``, with no cached verdict.

What an operator observes:

- ``sudo`` keeps its own **timestamp cache**, independent of PAM. While
  that timestamp is valid, ``sudo`` skips the PAM ``auth`` phase entirely
  and never prompts. On Debian the default is ``timestamp_timeout=15``
  (minutes), and it is **re-armed on each use**, so a continuously working
  admin can go a long time between token prompts. The ``account`` phase —
  and therefore the live authorization check — still runs on every
  ``sudo``.

So the residual gap is one of prompt frequency, not of authorization: a
stolen *token* is useless (single use, short TTL), and a revoked *right*
is enforced immediately. What survives inside the window is the operator's
own already authenticated terminal.

If your policy requires a token prompt for **every** ``sudo``, pass
``--enable-sudo-fresh-otp`` to ``ob-bastion-setup`` or
``ob-backend-setup``. It scopes ``timestamp_timeout=0`` to the SSO group in
``/etc/sudoers.d/open-bastion``, so SSO users go through the PAM ``auth``
phase — and therefore the LLNG token — on every elevation, while local
break-glass admins keep normal ``sudo`` behaviour:

.. code:: bash

   ob-bastion-setup --portal https://auth.example.com --max-security \
                    --enable-sudo-fresh-otp

::

   # /etc/sudoers.d/open-bastion
   Defaults:%open-bastion-sudo timestamp_timeout=0
   %open-bastion-sudo ALL=(ALL) ALL

Both setups validate the drop-in with ``visudo -cf`` before installing it,
and on a host that already has the file they only **add** the ``Defaults:``
line rather than rewriting what is there. Run the setup again without the
flag and the line stays: removing it is a deliberate edit, not a side
effect.

This is deliberately **not** the default: with ``timestamp_timeout=0``
every ``sudo`` in a shell loop or a long maintenance session needs a new
token, which in practice pushes operators towards ``sudo -i``. Choose per
site.

Mandatory KRL
-------------

With long-lived certificates (1 year), the KRL is **mandatory**.
``ob-bastion-setup --max-security`` downloads it once, then enables
``ob-krl-refresh.timer``, which runs ``ob-krl-refresh(8)`` every 30
minutes. The program reads the portal URL from ``openbastion.conf``,
refuses anything that is not a KRL that parses (``sshd`` would read a
broken list as revoking every key), and replaces
``/etc/ssh/revoked_keys`` by an atomic rename:

.. code:: bash

   # Refresh now, and see when it last ran and runs next
   sudo ob-krl-refresh
   systemctl list-timers ob-krl-refresh.timer
   journalctl -u ob-krl-refresh.service

   # Another interval: at setup time...
   sudo ob-bastion-setup ... --max-security --krl-refresh-interval 10
   # ...or by hand
   sudo systemctl edit ob-krl-refresh.timer     # [Timer] OnCalendar= / OnCalendar=*:0/10

Up to 0.6 the refresh was a cron job (``/etc/cron.d/open-bastion-krl``)
running a generated ``/usr/local/bin/open-bastion-refresh-krl``.
``ob-post-upgrade`` replaces it with the timer and keeps its interval; see
``UPGRADE-NOTES.md``.

.. _pam-modes-ssh-fingerprint-binding-on-pamauthorize-and-pamverify:

SSH fingerprint binding on ``/pam/authorize`` and ``/pam/verify``
-----------------------------------------------------------------

From plugin PamAccess 0.1.16 onwards, ``pam_openbastion`` forwards the
SHA256 fingerprint of the SSH key used to open the session in **both** the
``/pam/authorize`` request issued at every SSH connection (PAM ``account``
phase) and the ``/pam/verify`` request issued on every LLNG-token
operation (sudo, re-authentication).

How the fingerprint is captured
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Modern OpenSSH (≥ 9.x) does **not** propagate the authentication info to
the PAM environment during ``pam_acct_mgmt`` — ``ExposeAuthInfo yes`` is
not sufficient on its own. The bastion therefore uses an explicit
out-of-band channel:

1. sshd invokes
   ``AuthorizedPrincipalsCommand /usr/local/sbin/ob-ssh-principals %u %f %t %k``
   (deployed by ``ob-bastion-setup`` / ``ob-backend-setup``; the backend
   variant also gets ``%i``, the certificate key-id). The ``%f`` token is
   the SHA256 fingerprint of the client key or certificate (not ``%F``,
   which is the CA key's fingerprint), ``%t`` is the key or certificate
   type and ``%k`` its base64 blob. All of these have been supported on
   ``AuthorizedPrincipalsCommand`` since OpenSSH 7.4.

2. The helper runs as the unprivileged
   ``AuthorizedPrincipalsCommandUser``, so it owns no spool: it hands the
   key to ``ob-fp-daemon`` through ``/run/open-bastion/ssh-fp.sock``
   (``ob-fp-submit`` is what it uses). The root daemon derives the session
   anchor from the helper's ``/proc`` ancestry — never from the request —
   and writes two drop files (atomic ``mktemp`` + ``mv``) keyed on the
   ``sshd-session`` PID:

   - ``/run/open-bastion/ssh-fp/<sshd-session-pid>.fp`` — the fingerprint,
     as a bare ``SHA256:<base64>`` line;
   - ``/run/open-bastion/ssh-fp/<sshd-session-pid>.key`` — v1 key
     metadata, ``v=1`` / ``fp=`` / ``alg=`` / ``key=`` lines, used by the
     SSH key policy.

   They are separate files on purpose: an older ``pam_openbastion`` that
   only knows ``.fp`` keeps working byte-for-byte against a newer helper.
   The spool directory is ``root:root``, mode ``0700``, so no
   unprivileged user can pre-create or substitute a drop file.

3. ``pam_openbastion`` walks ``/proc/<pid>/status`` from its own PID up to
   the ``sshd-session`` ancestor, reads the corresponding spool files and
   validates each one (regular file owned by the spool-dir owner, mode
   ``0600``, ``nlink == 1``, size-capped; ``.fp`` must additionally match
   the strict ``SHA256:<base64>`` format). The fingerprint is forwarded to
   LLNG; the key metadata feeds the SSH key policy. If the two drops
   disagree on the fingerprint, the metadata is discarded as stale.

As a fallback, if a custom sshd variant does populate ``SSH_USER_AUTH``
with the content (``publickey <algo> SHA256:<fp>``), the module will parse
it from there instead.

The same channel is what makes ``ssh_key_policy_*`` enforceable: the key
blob is decoded by the module itself, so ``ssh_key_min_rsa_bits`` really is
applied, and a login whose key cannot be identified is denied. The policy
itself, and the check that the installed helper is recent enough for it,
are in :ref:`security-ssh-key-policy`.

Security properties
~~~~~~~~~~~~~~~~~~~

LLNG rejects the call unless it finds a matching, non-revoked and
non-expired SSH CA record in the user's persistent session (``_sshCerts``).
This provides a second line of defense on top of the local ``sshd`` KRL
check:

- **Session opening**: even if the bastion's ``/etc/ssh/revoked_keys`` is
  stale or ``RevokedKeys`` is missing from ``sshd_config``, a newly
  revoked certificate is rejected at ``/pam/authorize`` (``account``
  phase), and the SSH session is refused before the shell is spawned.
- **Privilege escalation**: the same check runs on ``/pam/verify``, so a
  compromised or revoked certificate cannot be used to obtain privileges
  via sudo from an already-established session either.
- **Token binding**: a stolen LLNG token cannot be replayed from a machine
  holding a different SSH key — the fingerprint presented in the request
  would not match any ``_sshCerts`` entry of the token's ``sub`` user.

Operational requirements
~~~~~~~~~~~~~~~~~~~~~~~~

- ``ob-bastion-setup`` / ``ob-backend-setup`` install
  ``/usr/local/sbin/ob-ssh-principals``, wire it as
  ``AuthorizedPrincipalsCommand``, and prepare the spool directory +
  ``/etc/tmpfiles.d/open-bastion-ssh-fp.conf`` drop-in so that ``/run``
  gets the directory recreated at boot.
- ``ExposeAuthInfo yes`` is **not** required for the fingerprint binding
  itself (the helper + spool are self-sufficient); it remains useful for
  session auditing.
- The ``fingerprint`` field is optional on the LLNG side, so bastions
  running on older portals that lack PamAccess 0.1.16 remain fully
  compatible — the portal simply ignores it.
