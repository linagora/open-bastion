ob-sftp
=======

Synopsis
--------

::

   ob-sftp [OPTIONS] [sftp-options] [user@]backend[:path]

Description
-----------

``ob-sftp`` is the :manpage:`sftp(1)` counterpart of
:doc:`ob-ssh(1) <ob-ssh>` and :doc:`ob-scp(1) <ob-scp>`. Run on a bastion by a
user already authenticated to it, it mints a short-lived, LemonLDAP::NG-signed
certificate for this user and runs ``sftp`` with it, so an interactive or
batch SFTP session can be opened to a backend:

* interactive: ``ob-sftp user@backend``

* with a path: ``ob-sftp user@backend:/remote/dir``

* batch mode: ``ob-sftp -b script.sftp user@backend``

The destination is a single ``[user@]backend[:path]`` endpoint. Unlike
:doc:`ob-scp(1) <ob-scp>` there is no backend-to-backend case: SFTP connects
to one remote endpoint, and a single vouched certificate authenticates as
exactly one principal.

No SSH key of the user's own on the bastion and no agent forwarding are
needed: the ephemeral private key lives in tmpfs and is wiped when ``ob-sftp``
exits.

Options
-------

Options consumed by ob-sftp itself must come first. Any further options are
passed straight to :manpage:`sftp(1)` — including ``sftp``'s own
``-c CIPHER``, which is why ob-sftp's config option is long-only (a short
``-c`` would shadow it).

.. option:: --config FILE

   Use alternate configuration file (default:
   ``/etc/open-bastion/ssh-proxy.conf``)

.. option:: -d, --debug

   Enable debug output to stderr

.. option:: -h, --help

   Show help message and exit

.. option:: -V, --version

   Show version and exit

Any further options are passed straight through to :manpage:`sftp(1)` (for
example ``-r``, ``-P PORT``, ``-b FILE``, ``-C``).

Configuration
-------------

Shares ``/etc/open-bastion/ssh-proxy.conf`` with :doc:`ob-ssh(1) <ob-ssh>`;
see that page for the keys.

Files
-----

``/etc/open-bastion/ssh-proxy.conf``
   Configuration file (world-readable; contains no secret)

``/usr/lib/open-bastion/ob-cert-lib.sh``
   Shared cert-vouching library sourced by ob-ssh, ob-scp and ob-sftp

Exit status
-----------

``0``
   Success

``1``
   Error (configuration, no valid voucher, or no destination endpoint)

Otherwise the exit status of the underlying :manpage:`sftp(1)`.

Examples
--------

::

   $ ob-sftp dwho@backend1
   $ ob-sftp dwho@backend1:/var/log
   $ ob-sftp -b commands.sftp dwho@backend1

See also
--------

:doc:`ob-ssh(1) <ob-ssh>`,
:doc:`ob-scp(1) <ob-scp>`,
:doc:`ob-cert-request(1) <ob-cert-request>`,
:doc:`ob-cert-daemon(8) <ob-cert-daemon>`,
:doc:`ob-bastion-setup(8) <ob-bastion-setup>`,
:manpage:`sftp(1)`,
:manpage:`ssh(1)`
