.. raw:: html

   <!-- column_layout: [1, 2, 1] -->

.. raw:: html

   <!-- column: 1 -->

|image1|

.. raw:: html

   <!-- reset_layout -->

Open Bastion
============

.. _presentation-centralized-ssh--sudo-for-your-linux-fleet--decided-by-your-sso:

Centralized SSH & sudo for your Linux fleet — decided by your SSO
-----------------------------------------------------------------

Manage your Linux administrators as easily as your SSO users, with **LemonLDAP::NG**:

- the SSO decides **SSH access** — no per-server keys
- the SSO decides **sudo** — no per-server sudoers
- **session recording** on the bastion that cannot be bypassed

.. raw:: html

   <!-- end_slide -->

Two Components
==============

.. _presentation-1-server-side-llng:

1. Server-side (LLNG)
---------------------

Portal plugins and endpoints

.. _presentation-2-client-side-linux:

2. Client-side (Linux)
----------------------

C PAM module (``pam_openbastion.so``)

.. raw:: html

   <!-- end_slide -->

Key Security Feature
====================

One-Time Tokens (PAMTOKEN)
--------------------------

.. raw:: html

   <!-- pause -->

- User tokens are **single-use**

.. raw:: html

   <!-- pause -->

- Destroyed after first use

.. raw:: html

   <!-- pause -->

- **Prevents replay attacks**

.. raw:: html

   <!-- pause -->

- Even if intercepted, tokens cannot be reused

::

   Token generated → Used once → Destroyed
                                 ↓
                       Replay attempt → DENIED

.. raw:: html

   <!-- end_slide -->

Architecture Overview
=====================

::

   ┌─────────────────────────────────────────────────────────┐
   │                        User                             │
   │  1. Login to LLNG portal                                │
   │  2. Generate temporary token ("PAM Access" tab)         │
   │  3. Use token as SSH password                           │
   └─────────────────────────────────────────────────────────┘
                              │
                              ▼
   ┌─────────────────────────────────────────────────────────┐
   │               LemonLDAP::NG Portal                      │
   │  Endpoints: /pam/verify, /pam/authorize, /pam/userinfo  │
   │  Plugins: PamAccess.pm, OIDCDeviceFlow.pm               │
   └─────────────────────────────────────────────────────────┘
                              │
                              ▼
   ┌─────────────────────────────────────────────────────────┐
   │               Linux Server (PAM Client)                 │
   │  /lib/security/pam_openbastion.so  - PAM module                │
   │  /lib/*/libnss_openbastion.so.2    - NSS module                │
   │  /etc/open-bastion/             - Configuration         │
   └─────────────────────────────────────────────────────────┘

.. raw:: html

   <!-- end_slide -->

LLNG Portal Endpoints
=====================

======================= =================================
Endpoint                Purpose
======================= =================================
``GET/POST /pam``       User interface (token generation)
``POST /pam/verify``    One-time token validation
``POST /pam/authorize`` Authorization check
``POST /pam/userinfo``  User info for NSS
``POST /pam/heartbeat`` Server heartbeat
``POST /oauth2/device`` Device Authorization Grant
``POST /oauth2/token``  Token exchange
======================= =================================

.. raw:: html

   <!-- end_slide -->

Server Enrollment (RFC 8628)
============================

Device Authorization Grant
--------------------------

One-time setup per Linux server:

.. code:: bash

   sudo ob-enroll

.. raw:: html

   <!-- pause -->

Enrollment Flow
---------------

1. Script contacts ``/oauth2/device``
2. Displays user code (e.g., ``ABCD-EFGH``)
3. Admin approves on LLNG portal
4. Script receives ``access_token`` + ``refresh_token``
5. Tokens saved to ``/var/lib/open-bastion/token``

.. raw:: html

   <!-- end_slide -->

Authentication Flow
===================

Token-Based SSH Login
---------------------

::

   User                    Linux Server                LLNG
    │                           │                        │
    │  1. ssh user@server       │                        │
    │──────────────────────────>│                        │
    │                           │                        │
    │  2. Password: <token>     │                        │
    │──────────────────────────>│                        │
    │                           │  3. POST /pam/verify   │
    │                           │──────────────────────> │
    │                           │                        │
    │                           │  4. {valid, user, grp} │
    │                           │     TOKEN DESTROYED    │
    │                           │<───────────────────────│
    │                           │                        │
    │  5. Connection OK         │                        │
    │<──────────────────────────│                        │

.. raw:: html

   <!-- end_slide -->

SSH Key Authentication
======================

Authorization-Only Mode
-----------------------

When using SSH keys, PAM only checks authorization:

::

   User                    Linux Server                LLNG
    │                           │                        │
    │  1. ssh -i key user@srv   │                        │
    │──────────────────────────>│                        │
    │                           │                        │
    │  2. SSH key validated     │                        │
    │                           │                        │
    │                           │ 3. POST /pam/authorize │
    │                           │──────────────────────> │
    │                           │                        │
    │                           │ 4. {authorized: bool}  │
    │                           │<───────────────────────│
    │                           │                        │
    │  5. Access granted/denied │                        │
    │<──────────────────────────│                        │

.. raw:: html

   <!-- end_slide -->

NSS Module: libnss_openbastion
==============================

The Problem
-----------

SSH checks if user exists in ``/etc/passwd`` **BEFORE** calling PAM

.. raw:: html

   <!-- pause -->

The Solution
------------

``libnss_openbastion`` queries LLNG for unknown users

.. code:: bash

   # /etc/nsswitch.conf
   passwd:         files openbastion

.. raw:: html

   <!-- pause -->

Flow
----

1. SSH calls ``getpwnam("dwho")``
2. NSS checks ``/etc/passwd`` → not found
3. NSS calls ``libnss_openbastion`` → queries ``/pam/userinfo``
4. LLNG returns user attributes
5. SSH continues with PAM authentication

.. raw:: html

   <!-- end_slide -->

Automatic User Creation
=======================

First Login Provisioning
------------------------

PAM can automatically create Unix accounts on first connection

.. raw:: html

   <!-- pause -->

Configuration
-------------

.. code:: ini

   # /etc/open-bastion/openbastion.conf
   create_user = true
   create_user_shell = /bin/bash
   create_user_groups = users,docker
   create_user_home_base = /home
   create_user_skel = /etc/skel

.. raw:: html

   <!-- pause -->

LLNG Exported Attributes
------------------------

::

   pamAccessExportedVars:
     gecos => cn
     shell => loginShell
     home  => homeDirectory

.. raw:: html

   <!-- end_slide -->

Heartbeat Monitoring
====================

.. _presentation-server-registration--health-checks:

Server Registration & Health Checks
-----------------------------------

.. code:: bash

   sudo systemctl enable --now ob-heartbeat.timer

.. raw:: html

   <!-- pause -->

Benefits
--------

- Detect "ghost" servers (uninstalled PAM modules)
- Maintain active server registry
- Collect usage statistics
- Detect stolen tokens (rotation)

.. raw:: html

   <!-- pause -->

Heartbeat Payload
-----------------

.. code:: json

   {
     "hostname": "server.example.com",
     "server_group": "production",
     "version": "0.1.0",
     "stats": { "auth_success": 42 }
   }

.. raw:: html

   <!-- end_slide -->

.. _presentation-server-groups--authorization:

Server Groups & Authorization
=============================

LLNG Manager Configuration
--------------------------

.. code:: perl

   # Server Groups → Access Rules
   production => $hGroup->{ops}
   staging    => $hGroup->{ops} or $hGroup->{dev}
   dev        => $hGroup->{dev}
   default    => 1

.. raw:: html

   <!-- pause -->

Per-Server Configuration
------------------------

.. code:: ini

   # /etc/open-bastion/openbastion.conf
   server_group = production

.. raw:: html

   <!-- pause -->

Only members of ``ops`` group can access production servers!

.. raw:: html

   <!-- end_slide -->

Security Features
=================

PAM Module Security
-------------------

- **AES-256-GCM** encryption for secrets
- **Rate limiting** with exponential backoff
- **JSON audit logging**
- **Token binding** (IP, fingerprint)
- **Webhook notifications** for security events

.. raw:: html

   <!-- pause -->

Communications
--------------

- HTTPS mandatory
- SSL verification enabled by default
- Short-lived access tokens (1h)
- Long-lived refresh tokens with rotation

.. raw:: html

   <!-- end_slide -->

Token Rotation
==============

Detecting Token Theft
---------------------

Refresh token rotation is enabled via:

::

   oidcRPMetaDataOptionsRefreshTokenRotation = 1

.. raw:: html

   <!-- pause -->

How It Works
------------

1. New refresh token generated on each renewal
2. Old refresh token invalidated
3. All ``_pam*`` metadata automatically copied

.. raw:: html

   <!-- pause -->

Theft Detection
---------------

If attacker uses stolen token:

→ Legitimate server's token becomes invalid

→ Attack detected!

.. raw:: html

   <!-- end_slide -->

PAM Configuration Modes
=======================

Mode A: LLNG Token Only
-----------------------

::

   auth       sufficient   pam_openbastion.so
   auth       required     pam_deny.so
   account    required     pam_openbastion.so

.. raw:: html

   <!-- pause -->

Mode B: LLNG Token OR Unix Password
-----------------------------------

::

   auth       sufficient   pam_openbastion.so
   auth       sufficient   pam_unix.so nullok try_first_pass
   auth       required     pam_deny.so

.. raw:: html

   <!-- pause -->

.. _presentation-mode-c-ssh-key--llng-authorization:

Mode C: SSH Key + LLNG Authorization
------------------------------------

::

   auth       required     pam_deny.so
   account    required     pam_openbastion.so

.. raw:: html

   <!-- pause -->

The ``auth`` stack denies on purpose: sshd never calls ``pam_authenticate()`` for key/certificate logins, so anything reaching it is a password attempt.

.. raw:: html

   <!-- end_slide -->

Installation
============

Debian/Ubuntu
-------------

.. code:: bash

   sudo apt install open-bastion

From Source
-----------

.. code:: bash

   cd open-bastion
   mkdir build && cd build
   cmake ..
   make
   sudo make install

.. raw:: html

   <!-- end_slide -->

Quick Setup
===========

.. _presentation-1-configure:

1. Configure
------------

.. code:: bash

   vim /etc/open-bastion/openbastion.conf

.. raw:: html

   <!-- pause -->

.. _presentation-2-enroll:

2. Enroll
---------

.. code:: bash

   sudo ob-enroll

.. raw:: html

   <!-- pause -->

.. _presentation-3-configure-pam:

3. Configure PAM
----------------

.. code:: bash

   vim /etc/pam.d/sshd

.. raw:: html

   <!-- pause -->

.. _presentation-4-enable-heartbeat:

4. Enable heartbeat
-------------------

.. code:: bash

   sudo systemctl enable --now ob-heartbeat.timer

.. raw:: html

   <!-- end_slide -->

Troubleshooting
===============

Logs
----

.. code:: bash

   # System logs
   sudo tail -f /var/log/auth.log

   # PAM audit logs
   sudo tail -f /var/log/open-bastion/audit.json

   # Journalctl
   sudo journalctl -u sshd -f

.. raw:: html

   <!-- pause -->

Debug Mode
----------

.. code:: ini

   # /etc/open-bastion/openbastion.conf
   log_level = debug

.. raw:: html

   <!-- pause -->

Re-enrollment
-------------

.. code:: bash

   sudo rm /var/lib/open-bastion/token
   sudo ob-enroll

.. raw:: html

   <!-- end_slide -->

Summary
=======

Key Benefits
------------

- **Single Sign-On** for Linux servers
- **One-time tokens** prevent replay attacks
- **Centralized authorization** via LLNG
- **Automatic provisioning** of Unix accounts
- **Token rotation** detects theft
- **Heartbeat monitoring** tracks server fleet

.. raw:: html

   <!-- pause -->

Components
----------

========================= ==================================
Component                 Function
========================= ==================================
``pam_openbastion.so``    PAM authentication & authorization
``libnss_openbastion.so`` User resolution before PAM
``ob-enroll``             Server enrollment
``ob-heartbeat``          Server monitoring
========================= ==================================

.. raw:: html

   <!-- end_slide -->

.. raw:: html

   <!-- jump_to_middle -->

Thank You!
==========

.. raw:: html

   <!-- column_layout: [1, 2, 1] -->

.. raw:: html

   <!-- column: 1 -->

|image2|

.. raw:: html

   <!-- reset_layout -->

References
----------

- RFC 8628 - Device Authorization Grant
- https://lemonldap-ng.org
- https://github.com/linagora

.. |image1| image:: ../linagora.png
.. |image2| image:: ../linagora.png
