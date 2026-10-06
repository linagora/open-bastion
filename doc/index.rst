Open Bastion documentation
==========================

Open Bastion enforces centralized SSH and ``sudo`` access control with
SSO integration, eliminating credential sprawl and simplifying audit
compliance.

Where to start
--------------

End user
~~~~~~~~

If you are an end user — you connect to servers through a bastion that
someone else runs — two pages are enough:

* :doc:`overview`, to understand what Open Bastion is.

* :doc:`using-open-bastion`, which covers obtaining your certificate,
  connecting, reaching a backend and using ``sudo``.

The :doc:`end user commands </references/man/end-user-commands>`
reference has every option of the commands you may run.

Administrator
~~~~~~~~~~~~~

If you administer Open Bastion or plan to, read these in order:

* :doc:`/deployment/index`, which covers the
  installation, and supported configuration methods (Ansible based,
  self-extracting installers or manual).

* :doc:`/security-scenarios/index` for the five security scenarios — what
  a host accepts, what ``sudo`` asks for — and how one is chosen.

* :doc:`Permissions </permissions>` and :doc:`/service-accounts` for
  who may do what.

* :doc:`/offline-mode/index` for what survives a portal outage.

* :doc:`/ssh-session-recording` and :doc:`/audit` for what is traced.

* :doc:`/hardening` for what the hosts themselves enforce.

* :doc:`/troubleshooting` when something does not
  work.

The :doc:`administrator man pages </references/man/administrator-commands>`
document each command and ``openbastion.conf``.

Security review
~~~~~~~~~~~~~~~

If you review the security of a deployment: :doc:`security` lists the
controls and what they do not cover, the :doc:`security reference
</references/security-reference>` is the exhaustive catalogue, and the
:doc:`EBIOS Risk Manager study </security/index>` (in French) is the
formal analysis of the maximum security target.

.. _start-here:

.. toctree::
   :caption: Getting started
   :hidden:
   :maxdepth: 2

   overview
   using-open-bastion


.. toctree::
   :caption: Administrator guide
   :hidden:
   :maxdepth: 2

   deployment/index
   Security scenarios <security-scenarios/index>
   permissions
   service-accounts
   offline-mode/index
   hardening
   security
   ssh-session-recording
   Primary audit trace <audit>
   CrowdSec integration <crowdsec>
   other-uses-cases
   troubleshooting
   competitors


.. toctree::
   :caption: References
   :hidden:
   :maxdepth: 2

   references/configuration
   references/llng-plugins-parameters
   references/security-reference
   references/maximum-security
   references/reference-paths
   references/bastion-architecture
   references/bastion-cert-vouching
   references/tamper-evident-session-recording
   

.. toctree::
   :caption: Man pages
   :hidden:
   :maxdepth: 2

   references/man/end-user-commands
   references/man/administrator-commands
   references/man/internal-commands


.. toctree::
   :caption: Desktop SSO (experimental)
   :hidden:
   :maxdepth: 2

   desktop-sso/index
   references/man/desktop-commands


.. toctree::
   :caption: Security Analysis (EBIOS RM)
   :hidden:
   :maxdepth: 2
   :glob:

   Introduction <security/index>
   security/[0-9]*
