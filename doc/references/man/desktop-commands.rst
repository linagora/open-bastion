Desktop SSO man pages
=====================

.. warning::

   Desktop SSO is **experimental (alpha)** and not production-ready: its
   authentication path has not been security-reviewed.

The commands of a workstation that logs in through LLNG with the LightDM
greeter. They ship, with their man pages, in the ``open-bastion-desktop``
package; see :doc:`/desktop-sso/index`.

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Page
     - What it documents
   * - :doc:`ob-desktop-setup(8) <ob-desktop-setup>`
     - Configure a workstation to log in through LLNG with the LightDM
       greeter, offline login included.
   * - :doc:`ob-cache-admin(8) <ob-cache-admin>`
     - Inspect, invalidate and unlock the offline credential cache.
   * - :doc:`ob-session-monitor(8) <ob-session-monitor>`
     - Revalidates sessions opened offline: ends the ones the portal reports
       gone, and forces the others back online after the grace period.
       Runs as ``ob-session-monitor.service``.

.. toctree::
   :hidden:

   ob-desktop-setup
   ob-cache-admin
   ob-session-monitor
