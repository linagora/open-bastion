Other security scenarios
========================

Open Bastion's default is :doc:`maximum security </pam-modes>`, where SSH
accepts only SSO certificates and ``sudo`` asks for an LLNG token. The
four scenarios below trade strictness for compatibility: choose one for a
transition period, or for a host that must keep Unix passwords or bare SSH
keys. None of them is covered by the :doc:`security study
</security/index>`.

.. list-table:: The five scenarios
   :header-rows: 1
   :widths: 24 13 26 28 8

   * - Scenario
     - ``ob-builder`` slug
     - SSH accepts
     - ``sudo`` asks for
     - Letter
   * - Token only
     - ``token-only``
     - LLNG token
     - LLNG token
     - A
   * - Token + Unix password
     - ``token+unix``
     - LLNG token, Unix password
     - LLNG token or Unix password
     - B
   * - SSH keys + LLNG authorization
     - ``keys+llng``
     - SSH keys, authorized by LLNG
     - nothing, LLNG still authorizes
     - C
   * - Mixed
     - ``mixed``
     - LLNG token, Unix password, SSH keys
     - LLNG token or Unix password
     - D
   * - :doc:`Maximum security </pam-modes>`
     - ``max-security``
     - certificates signed by the LLNG CA
     - LLNG token
     - E

The letters are the old vocabulary. This documentation no longer names
scenarios that way, but generated files (``ob_pam_mode``) and the French
security study still carry them, and the table above is how you place
them.

How a scenario is selected
--------------------------

* In ``ob-builder``, the "Security scenario" question — maximum security
  is the default answer — records the choice in the generated
  ``openbastion.conf`` and Ansible role.
* In a ``build.yml``, the ``scenario`` key takes the same values
  (:doc:`/deployment/ansible-deployment`).
* On a host installed from the package, the ``open-bastion/pam-mode``
  question writes the PAM stacks of the four scenarios below. Maximum
  security is not offered there; it comes from ``ob-bastion-setup
  --max-security``.

.. note::

   The setup scripts write the certificate-mode ``sshd`` stack whatever
   the scenario (:ref:`the full stack
   <pam-modes-pam-configuration-for-sshd>`). The stacks below are what the
   package's question writes, or what you write yourself.

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

The ``auth`` stack denies for the same reason as in :ref:`maximum
security <pam-modes-pam-configuration-for-sshd>`.

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
  maximum security scenario removes both from the SSH path.
* ``sudo`` is gated differently in each — see the table above.
