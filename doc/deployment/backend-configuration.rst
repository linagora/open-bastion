Backend configuration
=====================

When Open Bastion is installed, the ``ob-backend-setup`` command is
added to the administrator's path, typically ``/usr/sbin/``.

The ``ob-backend-setup`` command
--------------------------------

Use ``ob-backend-setup`` to automate backend server configuration: A
typical call looks like:

.. code:: bash

   sudo ob-backend-setup --portal https://auth.example.com --server-group production

This script performs the following actions:

- Download from LLNG the public key of the SSH certificate authority

- Configures the SSH service ``sshd`` to only accept signed user
  certificates to authenticate users (aka ``TrustedUserCAKeys``)

- Configures PAM with automatic user creation (can be disabled with
  ``--no-create-user`` command-line parameter)

- Configures ``sudo`` to use LLNG authorization (can be disabled with
  the ``--no-sudo`` command-line parameter)

- Configures NSS for user/group resolution by LLNG

- Enrolls the server with LLNG


