Service accounts
================

A service account is a local Unix account that logs in with an SSH key
alone, without the SSO. You create the account; Open Bastion serves its
key to ``sshd``, exempts it from the SSO in PAM and, on a host that records
sessions, records it like any other session.

Why service accounts?
---------------------

Some accounts do not correspond to people and cannot go through a browser
login: automation tools, backup systems, CI/CD pipelines, monitoring
agents, and anything else that needs an SSH key and a fixed account, but
no interactive login.

What Open Bastion does, and what it leaves to you
-------------------------------------------------

The SSO knows nothing of these accounts, and Open Bastion's part ends
where the SSO is not involved.

Open Bastion provides:

- the key: ``sshd``'s ``AuthorizedKeysCommand`` serves the root-owned
  ``/etc/open-bastion/service-accounts.d/<name>.pub``
  (``--enable-service-keys``, or the key in an ``ob-builder`` build);
- the SSO exemption: ``pam_openbastion`` authorizes an account listed in
  ``/etc/open-bastion/service-accounts.conf`` locally, with no portal call;
- session recording: on a bastion or standalone host that records, the
  session goes through the recorder's ``ForceCommand`` like any other.

You provide, with your configuration management:

- the Unix account itself (``useradd``), its home and its shell, which
  must be ``/usr/sbin/ob-login-shell`` on a host that records (see
  :ref:`service-accounts-recording-shell`);
- its groups, if it needs any;
- its ``sudo``, if it needs any: a ``sudoers`` rule (see
  :ref:`service-accounts-sudo`);
- its removal (``userdel``) when it is retired.

Open Bastion never creates the account, never adds it to a group and
does not touch its ``sudo``.

How a login works
-----------------

1. ``sshd`` looks the account up. It must be in ``/etc/passwd``:
   ``sshd`` refuses an unknown user before it looks at any key.
2. ``sshd`` runs ``ob-service-account-keys``, which prints
   ``service-accounts.d/<name>.pub`` when the file exists and is owned
   by root.
3. ``sshd`` accepts the connection if the client holds the matching
   private key.
4. In the PAM ``account`` phase, ``pam_openbastion`` finds the name in
   ``service-accounts.conf`` and authorizes it without calling the
   portal. A name that is not listed goes to the portal, which does not
   know it and refuses it.
5. On a host that records, the session runs through the recorder.

The account therefore needs all three: the local account, the key, and
the entry in ``service-accounts.conf``.

Creating the account
--------------------

.. code:: bash

   # A host that records sessions (bastion, standalone)
   useradd --system --create-home --shell /usr/sbin/ob-login-shell obbackup

   # A backend, or a host set up with --disable-session-recorder
   useradd --system --create-home --shell /bin/bash obbackup

The account needs no password: it logs in with its key, and
``sudo``, if you grant it, must be ``NOPASSWD``. Give it the same uid on
every host if files it writes travel between them.

.. _service-accounts-recording-shell:

The shell on a host that records
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``sshd`` does not run the recorder's ``ForceCommand`` itself: it runs
``<login shell> -c /usr/sbin/ob-session-recorder``. With ``/bin/bash`` as
the login shell, bash sources ``~/.bashrc`` first, because sshd started
it. That file belongs to the account, so whoever holds the key can make
it run anything, ``exec`` included, before the recorder starts and
outside the recording.

``/usr/sbin/ob-login-shell`` reads no file of the account and executes
the recorder directly; the recorder then starts the real shell
(``default_shell`` in ``nss_openbastion.conf``) inside the recording. See
:doc:`ob-login-shell(8) </references/man/ob-login-shell>`.

SSO users get that shell from ``libnss_openbastion``. A service account
is resolved from ``/etc/passwd``, so its shell is the one you gave it,
and nothing checks it: neither the setup nor PAM refuses a service
account whose shell is ``/bin/bash``. To fix an existing account:

.. code:: bash

   usermod -s /usr/sbin/ob-login-shell obbackup

Configuration
-------------

Service accounts are listed in ``/etc/open-bastion/service-accounts.conf``,
an INI-style file with one ``[name]`` section per account, ``name`` being
the Unix account name. The file must be owned by root and have 0600
permissions.

The file is local to each server, so an account is exempted from the SSO
only where it is listed; deploy the right file per server with your
configuration management tool.

Example:

.. code:: ini

   # Ansible automation account
   [ansible]
   key_fingerprint = SHA256:abc123def456...

   # Backup service account
   [obbackup]
   key_fingerprint = SHA256:xyz789...

Get ``key_fingerprint`` from the public key:

.. code:: bash

   ssh-keygen -lf /path/to/key.pub
   # 256 SHA256:abc123def456 user@host (ED25519)
   # -> key_fingerprint = SHA256:abc123def456

.. _service-accounts-options:

Options
~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 22 10 68

   * - Option
     - Requirement
     - Description
   * - ``key_fingerprint``
     - Yes
     - Fingerprint of the account's key, ``SHA256:...`` or ``MD5:...``.
       Aliases: ``fingerprint``, ``ssh_key``. An entry without a valid one
       is dropped at load, with a syslog warning, and its logins go to the
       portal. See :ref:`service-accounts-fingerprint` for what it is
       checked against.

Keys that earlier releases read — ``uid``, ``gid``, ``shell``, ``home``
(``home_dir``), ``gecos`` (``description``), ``sudo_allowed`` (``sudo``)
and ``sudo_nopasswd`` (``nopasswd``) — are ignored with a warning in the
logs. The account they described is yours now: set its shell and home
with ``useradd``/``usermod``, and its ``sudo`` in ``sudoers``. Remove the
lines once that is done.

.. _service-accounts-fingerprint:

What ``key_fingerprint`` does, and does not do
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``pam_openbastion`` compares ``key_fingerprint`` with the fingerprint of
the key that opened the session only when it learns that fingerprint. It
has two sources: ``SSH_USER_AUTH`` in the PAM environment, which OpenSSH
does not set during the ``account`` phase, and the spool under
``/run/open-bastion/ssh-fp``, which the ``AuthorizedPrincipalsCommand``
helper writes, and which ``sshd`` runs only for a certificate. A service
account logs in with a plain key, so in practice there is nothing to
compare, and the check is skipped.

What controls access is the key ``sshd`` accepts: the root-owned
``service-accounts.d/<name>.pub`` served by ``AuthorizedKeysCommand``, or
an ``authorized_keys`` file. Treat that file as the credential, and keep
``key_fingerprint`` equal to it.

The same absence has two consequences:

- ``fingerprint_required = true`` in ``openbastion.conf`` refuses a login
  whose fingerprint cannot be determined. On a host that sets it, service
  accounts cannot log in with a plain key.
- ``ssh_key_policy_enabled = true`` refuses a key it cannot identify, for
  the same reason (see :ref:`the SSH key policy
  <security-ssh-key-policy>`).

Generating with ob-builder
--------------------------

Instead of writing the file on each server, declare the accounts once
and have them baked into the artefacts generated by
:doc:`ob-builder(1) </references/man/ob-builder>`. Such service accounts
will apply to every role deployed using the artefacts: bastion, backend
and standalone.

Refer to that man page for the documentation of the ``service_accounts``
list in a YAML file passed with ``--config``.

.. code:: yaml

   service_accounts:
     - name: ci-ansible
       public_key_file: keys/ci-ansible.pub # the fingerprint comes from it
     - name: obbackup
       public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… backup@ops"

Service accounts can also be defined when using ``ob-builder``
interactive mode.

The artefacts write ``service-accounts.conf`` and the keys; they do not
create the Unix accounts. Create them on every target, with the shell
their role needs (``/usr/sbin/ob-login-shell`` on a bastion or standalone
host that records), before the accounts are used. The keys ``uid``,
``gid``, ``shell``, ``home``, ``gecos``, ``sudo_allowed`` and
``sudo_nopasswd`` of earlier releases are ignored with a warning.

Authorizing the public key at the SSH layer
-------------------------------------------

``sshd`` has to be told the key is acceptable, by one of:

- ``AuthorizedKeysCommand`` — required under maximum security, and
  works in other security scenarios. Maximum security sets
  ``AuthorizedKeysFile none``, so ``authorized_keys`` is ignored. The
  ``ob-service-account-keys`` helper serves the key from
  ``/etc/open-bastion/service-accounts.d/<name>.pub``, and only from a
  file owned by root, so the account cannot add a key of its own:

  ::

     # /etc/ssh/sshd_config.d/09-open-bastion-service-keys.conf
     AuthorizedKeysCommand /usr/sbin/ob-service-account-keys %u
     AuthorizedKeysCommandUser nobody
     ExposeAuthInfo yes

  Install each key in ``/etc/open-bastion/service-accounts.d/``
  (``install -m 0644 -o root -g root key.pub
  /etc/open-bastion/service-accounts.d/<name>.pub``); ``sshd`` runs the
  helper at every login, so no restart is needed for a new key.
  ``ExposeAuthInfo yes`` exposes the authentication details to the
  session (``SSH_USER_AUTH``); it does not bring the fingerprint to the
  PAM ``account`` phase (see :ref:`service-accounts-fingerprint`).

- ``authorized_keys`` — works with every security scenario but maximum
  security. Put the key in ``~<name>/.ssh/authorized_keys`` (``0600``,
  owned by the account). The account owns that file and can add keys to
  it, and since ``key_fingerprint`` is not compared on a plain-key login,
  such a key works too: prefer ``AuthorizedKeysCommand``.

The command :doc:`ob-bastion-setup(8) </references/man/ob-bastion-setup>`
``--enable-service-keys`` (and the same flag on
:doc:`ob-backend-setup(8) </references/man/ob-bastion-setup>`) writes the
whole drop-in and creates the directory.

Letting ob-builder deploy the key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A ``service_accounts:`` entry carrying the key itself
(``public_key`` / ``public_key_file``) makes the generated bundle write
``/etc/open-bastion/service-accounts.d/<name>.pub``. ``key_fingerprint`` is
then derived from the key; supply it as well only to have it checked, and a
value that does not describe the key stops the build.

When any account carries a key, the shell installer also passes
``--enable-service-keys`` to the setup it runs, which writes the
``AuthorizedKeysCommand`` drop-in; ``service_keys: false`` in the
configuration opts out, ``true`` forces it. When the setup is skipped, the
installer says so if it finds sshd not serving the keys.

``key_fingerprint`` alone is not an alternative to the key: it gives
``sshd`` nothing to accept. The account can log in only if its key reaches
``sshd`` some other way, an ``authorized_keys`` file you deploy yourself.
Under maximum security (``AuthorizedKeysFile none``) there is no other way,
so give the key.

Reaching servers through a bastion
----------------------------------

Service accounts authenticate by SSH key, independently of the certificate
vouching human users rely on:

- They cannot use :doc:`ob-ssh(1) </references/man/ob-ssh>`: that path
  needs a bastion voucher, which a key-only account never obtains. The
  recorded bastion-to-backend hop is therefore not available to them.
- Point them directly at the servers they automate.
- A native ``ssh -J bastion backup@backend`` can work if the account exists
  on both hosts and the bastion permits TCP forwarding, but the bastion's
  session recorder does not cover the forwarded channel: such a hop is not
  recorded. Treat it as a deliberate audit bypass.

.. _service-accounts-sudo:

sudo
----

Open Bastion does not manage a service account's ``sudo``, under any
security scenario, maximum security included. In the ``sudo`` and
``sudo-i`` services, ``pam_openbastion`` neither grants nor refuses it
(``PAM_IGNORE``): the rest of the PAM stack and ``sudoers`` decide. It
does not add the account to ``open-bastion-sudo`` or remove it from that
group either.

To give an account ``sudo``, write a ``sudoers`` rule for it. The rule
must be ``NOPASSWD``: the account has no password and no SSO token to
present, and ``NOPASSWD`` makes ``sudo`` skip the ``auth`` phase.

.. code:: bash

   # visudo -f /etc/sudoers.d/service-accounts
   obbackup ALL=(root) NOPASSWD: /usr/local/sbin/run-backup
   ansible  ALL=(ALL)  NOPASSWD: ALL

Do not use ``open-bastion-sudo`` for it: that group's rule asks for
authentication, and the module maintains the group for SSO users. Take
out of it an account that an earlier release put there
(``gpasswd -d ansible open-bastion-sudo``): ``sudoers`` applies the last
rule that matches, so that group's rule in ``/etc/sudoers.d/open-bastion``
overrides yours whenever your file sorts before it.

Whether the rule is enough depends on the ``sudo`` PAM stack:

- **Every scenario but maximum security**: it is. A bastion or
  standalone host keeps the distribution's stack, and the backend stack
  passes an account of ``/etc/passwd`` with
  ``account sufficient pam_localuser.so``; ``sudoers`` alone decides.
- **Maximum security**: it is not. That stack is ``pam_openbastion``
  alone and refuses every local account, service accounts included (see
  :ref:`max-security-scenario-sudo`). Giving one ``sudo`` there means
  editing ``/etc/pam.d/sudo`` and ``/etc/pam.d/sudo-i`` by hand, for
  instance:

  .. code:: text

     account    sufficient   pam_succeed_if.so quiet user in ansible:obbackup
     account    required     pam_openbastion.so

  That is your decision to take, not a supported configuration of the
  scenario. Those accounts then elevate with no SSO involvement, which is
  exactly what maximum security promises does not happen: there, every
  elevation goes through the SSO. A key with such a rule is a standing
  root credential; keep the rule as narrow as the job allows, and rotate
  the key like any other long-lived secret. A setup re-run rewrites both
  files and drops the line.

A service account's ``sudo`` is never seen by the portal: audit it on the
host (``sudo`` logs to syslog, and :doc:`/audit` can trace it).
