CrowdSec integration
====================

Open Bastion can integrate with `CrowdSec
<https://www.crowdsec.net/>`__ for enhanced security.

There's two possible non exclusive integrations:

- As a bouncer, to block banned IPs before authentication

- As a watcher, to report authentication failures to CrowdSec for
  threat detection

Prerequisites
-------------

* The CrowdSec Local API (LAPI) URL of a Crowdsec instance.

* Depending on the planned integration:

  - To block banned IPs, a bouncer API key as obtained via 
    ``cscli bouncers add open-bastion`` is required

  - To report authentication failures, a machine ID and password must
    be generated with ``cscli machines add open-bastion --password
    <password>``

Configuration
-------------

Extend the file ``/etc/open-bastion/openbastion.conf`` with:

.. code:: ini

   # Enable CrowdSec integration
   crowdsec_enabled = true
   crowdsec_url = http://127.0.0.1:8080

where ``crowdsec_url`` must be updated to match the Crowdsec Local
API.

Then complete with the blocks required by the planned integration
(don't forget to update the API key and/or machine password):

.. code:: ini

   # Bouncer: Block banned IPs
   crowdsec_bouncer_key = your-bouncer-api-key
   crowdsec_action = reject       # reject or warn
   crowdsec_fail_open = true      # allow if CrowdSec unavailable

and/or:

.. code:: ini

   # Watcher: Report authentication failures
   crowdsec_machine_id = open-bastion
   crowdsec_password = your-machine-password
   crowdsec_scenario = open-bastion/ssh-auth-failure
   crowdsec_send_all_alerts = true   # send all alerts, not just bans
   crowdsec_max_failures = 5         # auto-ban after N failures
   crowdsec_block_delay = 180        # time window in seconds
   crowdsec_ban_duration = 4h        # ban duration

Configuration options
---------------------

+------------------------------+-----------------------------------+----------------------------------------+
| Option                       | Default                           | Description                            |
+==============================+===================================+========================================+
| ``crowdsec_enabled``         | ``false``                         | Enable CrowdSec integration            |
+------------------------------+-----------------------------------+----------------------------------------+
| ``crowdsec_url``             | ``http://127.0.0.1:8080``         | CrowdSec LAPI URL                      |
+------------------------------+-----------------------------------+----------------------------------------+
| ``crowdsec_timeout``         | ``5``                             | HTTP timeout in seconds                |
+------------------------------+-----------------------------------+----------------------------------------+
| ``crowdsec_fail_open``       | ``true``                          | Allow auth if CrowdSec unavailable     |
+------------------------------+-----------------------------------+----------------------------------------+
| ``crowdsec_bouncer_key``     | n/a                               | Bouncer API key for IP checking        |
+------------------------------+-----------------------------------+----------------------------------------+
| ``crowdsec_action``          | ``reject``                        | Action on ban: ``reject`` or ``warn``  |
+------------------------------+-----------------------------------+----------------------------------------+
| ``crowdsec_whitelist``       | n/a                               | See :ref:`crowdsec-ip-whitelist`       |
+------------------------------+-----------------------------------+----------------------------------------+
| ``crowdsec_machine_id``      | n/a                               | Machine ID for alert reporting         |
+------------------------------+-----------------------------------+----------------------------------------+
| ``crowdsec_password``        | n/a                               | Machine password                       |
+------------------------------+-----------------------------------+----------------------------------------+
| ``crowdsec_scenario``        | ``open-bastion/ssh-auth-failure`` | Scenario name for alerts               |
+------------------------------+-----------------------------------+----------------------------------------+
| ``crowdsec_send_all_alerts`` | ``true``                          | Send all alerts or only bans           |
+------------------------------+-----------------------------------+----------------------------------------+
| ``crowdsec_max_failures``    | ``5``                             | Auto-ban after N failures (0=disabled) |
+------------------------------+-----------------------------------+----------------------------------------+
| ``crowdsec_block_delay``     | ``180``                           | Time window for counting failures      |
+------------------------------+-----------------------------------+----------------------------------------+
| ``crowdsec_ban_duration``    | ``4h``                            | Ban duration (e.g., ``4h``, ``1d``)    |
+------------------------------+-----------------------------------+----------------------------------------+

.. _crowdsec-ip-whitelist:

IP whitelist
------------

The ``crowdsec_whitelist`` option allows you to specify IPs and
networks that should bypass CrowdSec checks entirely. This is useful
for:

- VPN exit nodes: Multiple users sharing the same public IP could trigger false positives
- Corporate networks: Trusted internal networks that should never be blocked
- Bastion hosts: If traffic is forwarded through a bastion with a known IP

Format
~~~~~~

The value must be a comma-separated list of IPs/CIDRs:

- Single IPv4 addresses: ``192.168.1.1``
- IPv4 CIDR networks: ``10.0.0.0/8``
- Single IPv6 addresses: ``::1``
- IPv6 CIDR networks: ``2001:db8::/32``

Example:

.. code:: ini

   crowdsec_whitelist = 10.0.0.0/8, 192.168.1.0/24, 172.16.0.0/12, ::1, 2001:db8::/32

Security considerations
~~~~~~~~~~~~~~~~~~~~~~~

.. warning::

   Whitelisted IPs bypass all CrowdSec checks, including:

   - banned IPs blocking (the bouncer integration)
   - Authentication failure reporting (the watcher integration)

Use this feature carefully:

- Only whitelist IPs you fully trust
- Prefer specific IPs over large CIDR ranges
- Consider using ``crowdsec_action = warn`` for monitoring whitelisted traffic

See :ref:`security-dos-prevention-via-crowdsec-whitelist` for the DoS
prevention use case.

