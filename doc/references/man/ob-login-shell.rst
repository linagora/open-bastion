ob-login-shell
==============

Synopsis
--------

::

   ob-login-shell [-l|--login|-i] [-c COMMAND]

Description
-----------

``ob-login-shell`` is the login shell that ``libnss_openbastion`` hands out to
every user it resolves on a bastion or standalone host that records sessions
(the ``force_shell`` key of ``nss_openbastion.conf``, written by
:doc:`ob-bastion-setup(8) <ob-bastion-setup>` and
:doc:`ob-post-upgrade(8) <ob-post-upgrade>`). It is not meant to be run by
hand.

sshd never executes a ``ForceCommand`` itself: it runs it through the user's
login shell, as ``shell -c '/usr/sbin/ob-session-recorder'``. A shell reads
startup files before it runs that command, and some belong to the user:
Debian's :manpage:`bash(1)` sources ``~/.bashrc`` for ``bash -c`` whenever
``SSH_CLIENT`` is set, and :manpage:`zsh(1)` reads ``~/.zshenv`` for every
invocation. With such a login shell, whatever those files hold runs before the
session recorder, and is not recorded.

``ob-login-shell`` reads no file the user controls and starts no shell. It has
one way out: it executes :doc:`ob-session-recorder(8) <ob-session-recorder>`,
in the same process, with an environment it builds itself. The recorder then
starts the user's real shell inside :manpage:`script(1)`, where reading
``~/.bashrc`` is harmless: it is recorded.

Invocations
-----------

``-c /usr/sbin/ob-session-recorder [OPTIONS]``
   sshd running the ``ForceCommand``. The recorder is executed with those
   options, and ``SSH_ORIGINAL_COMMAND`` (the command the client asked for) is
   passed on. The options must be plain words (letters, digits and
   ``_ . / = : , + -``); a ``ForceCommand`` with quoting or shell syntax is
   not recognised, and is handled as the next case.

``-c COMMAND``
   Anything else asking the login shell to run a command:
   ``su -c COMMAND``, ``sudo -i -u USER COMMAND``, an sshd with no
   ``ForceCommand`` for this user. ``COMMAND`` is **not** run. It becomes
   ``SSH_ORIGINAL_COMMAND`` and the recorder runs it, recorded.

no argument, ``-l``, ``--login``, ``-i``
   An interactive login: the console, ``su -``, ``sudo -i``. The recorder
   starts the real shell, recorded. An ``SSH_ORIGINAL_COMMAND`` inherited from
   the caller is not passed on.

Any other invocation (another option, arguments after ``-c COMMAND``) is
refused and nothing runs. Every accepted path ends in the recorder: there is
no way through this program that is not recorded.

Environment
-----------

The recorder does not inherit the caller's environment. It gets:

``USER``, ``LOGNAME``, ``HOME``
   from the passwd entry of the real uid, not from the variables of the same
   names;

``SHELL``
   the shell the recorder starts for the session (see **Files**);

``PATH``
   ``/usr/local/bin:/usr/bin:/bin:/usr/games``;

``TERM``, ``SSH_CLIENT``, ``SSH_CONNECTION``, ``SSH_TTY``, ``SSH_AUTH_SOCK``
   when present and well-formed;

``LANG``, ``LANGUAGE``, ``LC_*``
   when they name a locale; a locale named by a path, which glibc would load
   from that path, is dropped;

``XDG_RUNTIME_DIR``, ``XDG_SESSION_ID``, ``XDG_SESSION_TYPE``, ``XDG_SESSION_CLASS``
   when well-formed (the runtime directory only as ``/run/user/UID``);

``LLNG_BASTION_VOUCHER``
   when well-formed: the voucher **pam_openbastion** sets on a bastion, which
   **ob-ssh**\(1) needs to obtain the certificate of the next hop;

``SSH_ORIGINAL_COMMAND``
   as described under **Invocations**.

Everything else is dropped: ``BASH_ENV``, ``ENV``, ``SHELLOPTS``, exported
functions, ``LD_*``, ``OB_*``, ``LOCPATH``, ``GCONV_PATH``, ``TMPDIR``,
``TZ``, and the rest.

Files
-----

``/etc/open-bastion/nss_openbastion.conf``
   ``default_shell`` is the shell the recorder starts for the session (last
   occurrence wins, surrounding quotes removed). The file is ignored unless it
   is a regular file owned by root and writable by nobody else. Without it, or
   without the key, ``/bin/bash`` is used. A value that is not a plain
   absolute path to an executable file, or that is ``ob-login-shell`` itself
   or the recorder (the recorder would start itself inside its own recording,
   forever), is refused with a syslog warning and ``/bin/bash`` is used
   instead.

``/usr/sbin/ob-session-recorder``
   The only program this one executes.

``/etc/shells``
   Lists ``/usr/sbin/ob-login-shell`` (the package and the setup add it), so
   that :manpage:`pam_shells(8)` and other checks of "a valid login shell"
   accept it.

Exit status
-----------

On success it does not return: it becomes the recorder.

``1``
   The account could not be resolved, no usable shell exists for the session,
   or the recorder could not be executed. The session is refused.

``2``
   Unsupported invocation. Nothing was run.

Notes
-----

A backend has no ``ForceCommand`` and records nothing, and
``ob-bastion-setup --disable-session-recorder`` installs no recorder: on those
hosts ``force_shell`` is not set and SSO users keep an ordinary shell.

Local accounts in ``/etc/passwd`` are not resolved by ``libnss_openbastion``,
and keep the shell the administrator gave them. On a recording host, an
account that logs in over SSH goes through the same ``ForceCommand`` and has
the same exposure; give it this shell with
``chsh -s /usr/sbin/ob-login-shell`` *USER*.

See also
--------

:doc:`ob-session-recorder(8) <ob-session-recorder>`,
:doc:`ob-bastion-setup(8) <ob-bastion-setup>`,
:doc:`ob-post-upgrade(8) <ob-post-upgrade>`,
:manpage:`sshd_config(5)`,
:manpage:`nsswitch.conf(5)`,
:manpage:`shells(5)`
