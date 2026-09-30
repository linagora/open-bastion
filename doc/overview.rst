Overview
========

Uses cases
----------

The typical use case is a single publicly accessible server through
which all SSH access to protected backend servers flows. Both SSH and
``sudo`` access are managed centrally in LLNG.

In this scenario there are two human participants:

* The **end user** who connects to a backend using SSH and executes
  commands as another user with ``sudo``.

  .. figure:: user-context.png
     :figwidth: 100%
     :align: center
     :alt: Open Bastion user context

* The **administrator** who is responsible of Open Bastion deployment,
  the bastion and backends enrollment and access rules configuration.

  .. figure:: administrator-context.png
     :figwidth: 100%
     :align: center
     :alt: Open Bastion administrator context


.. note::

   Depending on the organization size, the access rules management can
   be delegated to IAG operators. To keep this documentation simple we
   consider that all those responsabilities rest with the
   administrator.

   This same desire for simplicity led us to focus on the most rep
   resentative—yet also the simplest—scenario; however, this should
   not obscure Open Bastion's ability, in the case of a complex
   platform, to protect various isolated zones—for instance, by
   deploying multiple instances.

In the platform one can identify:

* A protected zone gathering **backend servers**.

* The **bastion** through which all SSH access flows.

* An instance of **LLNG** responsible for:

  - User authentication (OIDC, SAML, LDAP)

  - Generation of PAM token (for SSH access or ``sudo`` authentication,
    depending on configuration)

  - Gathering authorization rules (per-user, per-group,
    per-server-group)

  - Bastion and backend enrollment (through "device enrollment" as
    specified by `RFC8628 <https://www.rfc-editor.org/info/rfc8628/>`__)

  - Centralized access logs

Features
--------

Beyond its primary functionality —centralizing SSH and ``sudo`` access
via OIDC— Open Bastion is feature rich. It provides:

* :doc:`offline-mode`: Encrypted authorization cache keeps SSH key
  authentication working when LLNG is unavailable

* User accounts and group resolution from LLNG via OIDC

* Server groups for granular access control

* :doc:`service-accounts`: SSH key authentication without OIDC, with
  per-server configuration and fine-grained ``sudo`` permissions

* Bastion-to-backend authentication: Certificate-based proof of
  connection origin, so backends only accept SSH from authorized
  bastions — no agent forwarding or user key required on the bastion

* :doc:`ssh-session-recording`: Full terminal I/O capture for audit
  compliance, with unique session identifiers

* :doc:`audit`: Audit trace with ``auditd``

* :doc:`hardening`: Host level configuration to keep authenticated
  user from escaping SSH session recording

* :doc:`crowdsec`:
  Pre-authentication IP blocking and post-authentication failure
  reporting, with auto-ban and `Crowdsieve
  <https://github.com/linagora/crowdsieve>`__ support for centralized
  alerts

* Monitoring: Server heartbeat and statistics reporting to LLNG portal
