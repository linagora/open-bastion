ob-scp
======

Synopsis
--------

::

   ob-scp [OPTIONS] [scp-options] SOURCE ... DEST

Description
-----------

``ob-scp`` is the :manpage:`scp(1)` counterpart of :doc:`ob-ssh(1) <ob-ssh>`.
Run on a bastion by a user already authenticated to it, it mints a
short-lived, LemonLDAP::NG-signed certificate for this user and runs ``scp``
with it, so files can be copied:

* bastion to backend: ``ob-scp file user@backend:/path``

* backend to bastion: ``ob-scp user@backend:/path file``

* backend to backend: ``ob-scp user@b1:/path user@b2:/path``

``SOURCE``/``DEST`` are local paths or ``[user@]backend:/path`` specs. All
remote endpoints must use the SAME remote user, because a single vouched
certificate authenticates as exactly one principal.

All transfers are forced through the bastion (``scp -3``). This is not just
convenience: the vouched certificate is pinned to the bastion's source
address, so a direct backend-to-backend transfer would be rejected. Routing
every connection through the bastion keeps the source address matching the
certificate.

Options
-------

Options consumed by ob-scp itself must come first. Any further options are
passed straight to :manpage:`scp(1)` — including ``scp``'s own
``-c CIPHER``, which is why ob-scp's config option is long-only (a short
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

Any further options are passed straight through to :manpage:`scp(1)` (for
example ``-r``, ``-P PORT``, ``-p``, ``-C``, ``-l``).

Configuration
-------------

Shares ``/etc/open-bastion/ssh-proxy.conf`` with :doc:`ob-ssh(1) <ob-ssh>`;
see that page for the keys.

Files
-----

``/etc/open-bastion/ssh-proxy.conf``
   Configuration file (world-readable; contains no secret)

``/usr/lib/open-bastion/ob-cert-lib.sh``
   Shared cert-vouching library sourced by ob-ssh and ob-scp

Exit status
-----------

``0``
   Success

``1``
   Error (configuration, no valid voucher, mismatched remote users, or no
   remote endpoint)

Otherwise the exit status of the underlying :manpage:`scp(1)`.

Examples
--------

::

   $ ob-scp ./data.tar dwho@backend1:/tmp/
   $ ob-scp dwho@backend1:/var/log/app.log ./
   $ ob-scp -r dwho@backend1:/etc/app dwho@backend2:/etc/app

See also
--------

:doc:`ob-ssh(1) <ob-ssh>`,
:doc:`ob-sftp(1) <ob-sftp>`,
:doc:`ob-cert-request(1) <ob-cert-request>`,
:doc:`ob-cert-daemon(8) <ob-cert-daemon>`,
:doc:`ob-bastion-setup(8) <ob-bastion-setup>`,
:manpage:`scp(1)`,
:manpage:`sftp(1)`,
:manpage:`ssh(1)`

Author
------

Xavier Guimard <xguimard@linagora.com>
