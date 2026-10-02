Other security scenarios
========================

The four scenarios other than :doc:`the default </security-scenarios/max-security-scenario>`.
None of them is covered by the :doc:`security study </security/index>`, and
:doc:`/security-scenarios/index` compares all five and tells how one is selected.

.. _pam-modes-mode-a-llng-token-only-strictest:

Token only
----------

Scenario ``token-only``. Users authenticate with their LLNG token, typed
at the SSH prompt in place of a password; Unix passwords are refused. Use
it when every user has an LLNG account.

.. code:: text

   # /etc/pam.d/sshd
   auth       sufficient   pam_openbastion.so
   auth       required     pam_deny.so

   account    required     pam_openbastion.so
   account    required     pam_unix.so

   session    required     pam_unix.so

And in ``/etc/ssh/sshd_config``:

.. code:: text

   UsePAM yes
   PasswordAuthentication yes
   KbdInteractiveAuthentication yes
   PubkeyAuthentication yes          # optional: also accept SSH keys
   PermitEmptyPasswords no

The scenario names the password channel only: with
``PubkeyAuthentication yes``, SSH keys are still accepted, and the
``account`` phase submits them to LLNG like any other login.

Token + Unix password
---------------------

Scenario ``token+unix``. The LLNG token and the Unix password are both
accepted, the token first. Use it during a migration, while some users
have no LLNG account yet.

.. code:: text

   # /etc/pam.d/sshd
   auth       sufficient   pam_openbastion.so
   auth       sufficient   pam_unix.so nullok try_first_pass
   auth       required     pam_deny.so

   account    required     pam_openbastion.so
   account    required     pam_unix.so

   session    required     pam_unix.so

The ``sshd`` settings are those of :ref:`token only
<pam-modes-mode-a-llng-token-only-strictest>`.

SSH keys + LLNG authorization
-----------------------------

Scenario ``keys+llng``. Users authenticate with their SSH key; PAM does
not handle that authentication, but LLNG authorizes every connection. Use
it on hosts that must keep accepting keys without moving to certificates.

.. code:: text

   # /etc/pam.d/sshd
   auth       required     pam_deny.so

   account    required     pam_openbastion.so
   account    required     pam_unix.so

   session    required     pam_unix.so

.. code:: text

   UsePAM yes
   PasswordAuthentication no
   KbdInteractiveAuthentication no
   PubkeyAuthentication yes
   PermitEmptyPasswords no

The ``auth`` stack denies for the same reason as in :ref:`the default
scenario <pam-modes-pam-configuration-for-sshd>`.

Unlike maximum security, this scenario leaves ``AuthorizedKeysFile``
alone, so ``~/.ssh/authorized_keys`` still authenticates its owner — an
opt-in fallback while the portal is unreachable, with the trade-offs
described in :doc:`/offline-mode`.

``sudo`` asks for no password here: the SSH key is the only control, and
the stack the package writes permits elevation.

Mixed
-----

Scenario ``mixed``. All three methods are accepted, and LLNG authorizes
every connection. Use it for a transition, or where no method can be
dropped yet.

.. code:: text

   # /etc/pam.d/sshd
   auth       sufficient   pam_openbastion.so
   auth       sufficient   pam_unix.so nullok try_first_pass
   auth       required     pam_deny.so

   account    required     pam_openbastion.so
   account    required     pam_unix.so

   session    required     pam_unix.so

.. code:: text

   UsePAM yes
   PasswordAuthentication yes
   KbdInteractiveAuthentication yes
   PubkeyAuthentication yes
   PermitEmptyPasswords no

What they do not give you
-------------------------

* No SSH certificates, so no revocation list is enforced at login, and
  nothing identifies the machine a connection comes from.
* No bastion-to-backend vouching: a hop certificate is what lets a
  backend accept only its bastion's connections.
* A password or a key can be guessed, phished or reused elsewhere; the
  default scenario removes both from the SSH path.
* ``sudo`` is gated differently in each — see the
  :doc:`comparison table </security-scenarios/index>`.
