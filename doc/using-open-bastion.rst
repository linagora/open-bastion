Using Open Bastion
==================

Once an administrator has deployed Open Bastion, nothing changes in
the way you work: you still connect with ``ssh``, ``scp`` and
``sftp``. What changes is that the LLNG portal signs your key, and
that the servers behind the bastion are reached through it. There
``sudo`` requires user to enter LLNG tokens as passwords.

This page is everything a user needs. Each command is documented in
full — options, exit statuses, configuration — under :doc:`End user
commands </references/man/end-user-commands>`.

.. _using-open-bastion-getting-your-certificate:

Getting your certificate
------------------------

You get your certificate from the portal, in a browser, from any
workstation: open ``https://sso.example.com/ssh`` — your administrator
will give you the portal's real address — paste your SSH public key,
choose how long you need it, and save what the page hands back beside
your private key: the file ``id_ed25519-cert.pub`` next to
``id_ed25519``. If you do not have a key yet:

.. code:: bash

   ssh-keygen -t ed25519
   cat ~/.ssh/id_ed25519.pub     # paste this line into the portal page

``ssh`` finds a certificate that sits beside its key, so that is the
whole of the configuration it needs. Ask for a validity that covers
the work ahead; the portal caps it.

Connecting to the bastion
-------------------------

With the certificate beside your key, an ordinary login is all it takes:

.. code:: bash

   ssh alice@bastion.example.com

If your administrator has set the host up to record sessions, your session is
recorded while you work — you do not have to do anything, and your commands
behave as usual.

A certificate that has expired is the usual reason a connection that
worked this morning is refused this afternoon: get a new one.

Token authentication
~~~~~~~~~~~~~~~~~~~~

Depending on the administrators choice, the bastion may not accept SSH
access through certificates but prompt for an LLNG token.

An LLNG token is a one-time password, valid for a short while, that
the portal issues for you: retrieve one from the portal's ``/pam``
page — ``https://sso.example.com/pam`` — and paste it at the
prompt.

Reaching a backend
------------------

On the bastion, ``ob-ssh`` opens a session on a backend without your
needing a key there, and without agent forwarding:

.. code:: bash

   # A shell on the backend
   ob-ssh backend-web01

   # One command, output returned as it is (it pipes and captures cleanly)
   ob-ssh backend-web01 uptime

   # Another remote user, or another port
   ob-ssh admin@backend-web01 2222

``ob-scp`` and ``ob-sftp`` do the same for file transfers, and are run
on the bastion too:

.. code:: bash

   ob-scp report.csv backend-web01:/tmp/
   ob-sftp backend-web01

To skip the bastion step from your workstation, add a host entry to
your ``~/.ssh/config`` whose ``RemoteCommand`` is ``ob-ssh`` — see
below.

.. warning::

   A plain ``ProxyJump`` or ``ProxyCommand`` is **not** a supported
   way to reach a backend. It would bypass the controls the bastion
   applies to the hop, and the backend refuses it.

Running commands with ``sudo``
------------------------------

On a bastion or on a backend, ``sudo`` asks for an LLNG token rather
than a Unix password: retrieve one from the portal's ``/pam`` page, as
you would to log in to a token-authenticated host, and paste it at the
``Password:`` prompt. Whether you may use ``sudo`` at all is decided
in the portal, by your administrator — a valid token does not help if
the answer there is no.

``sudo`` remembers that you authenticated, for a quarter of an hour by
default, so a series of commands asks for the token once; your
administrator may have set it to ask at every command. An elevation
you made recently also keeps working while the portal is unreachable,
until that memory lapses.

On a host where ``sudo`` is not tied to the portal, it behaves as you
are used to: no prompt at all, or your Unix password.

Configuring your SSH client
---------------------------

Two entries cover the usual day: one to log in to the bastion, one to
land directly on a backend.

.. code:: text

   # ~/.ssh/config
   Host bastion
       HostName bastion.example.com
       User alice
       IdentityFile ~/.ssh/id_ed25519   # the key your certificate was issued for
       IdentitiesOnly yes

   Host backend-web01
       HostName bastion.example.com     # you connect to the bastion...
       User alice
       IdentityFile ~/.ssh/id_ed25519
       IdentitiesOnly yes
       RequestTTY yes
       RemoteCommand ob-ssh backend-web01   # ...which hops to the backend

With that in place, ``ssh bastion`` logs you in to the bastion and
``ssh backend-web01`` lands on the backend in one command; ``scp`` and
``sftp`` keep working against the bastion entry.

OpenSSH finds a certificate stored beside the key (``id_ed25519`` and
``id_ed25519-cert.pub``); when the certificate lives in your agent
instead, drop the ``IdentityFile`` and ``IdentitiesOnly`` lines. If
you connect with several keys and the bastion complains about too many
authentication failures, see :doc:`/troubleshooting`.

When a connection is refused
----------------------------

- **``Permission denied`` right after a login that used to work** —
  your certificate has expired. See :ref:`Getting your certificate
  <using-open-bastion-getting-your-certificate>`.

- **``Permission denied`` for a backend, while the bastion accepts
  you** — you are not authorized for that server, or a certificate has
  been revoked.  Ask your administrator; on the bastion,
  :doc:`ob-ssh(1) </references/man/ob-ssh>` reports what it tried.

- **The bastion refuses you while your certificate is still valid** — the
  portal may be unreachable, which also stops a hop to a backend. Waiting for
  the portal to come back is enough; see :doc:`/offline-mode` for what keeps
  working meanwhile.

- **``sudo`` refuses you** — either the portal does not grant you
  ``sudo`` on this host, which is your administrator's call, or the
  token you pasted has expired. For the second, retrieve a fresh one
  from the portal ``/pam`` page.

- **The portal refuses to sign your key** — your account may not be allowed to
  log in to the servers you asked for. Your administrator grants that.
