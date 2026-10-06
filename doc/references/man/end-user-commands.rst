End user commands
=================

The commands a user runs from their workstation, or from a bastion session
to reach a backend. Each has a man page of the same name, installed by the
``open-bastion`` package. For the whole of it in one page, see
:doc:`Using Open Bastion </using-open-bastion>`.

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Command
     - What it does
   * - :doc:`ob-ssh(1) <ob-ssh>`
     - Open a session on a backend through the bastion, with a short-lived
       certificate minted for the hop. No key or agent forwarding leaves the
       workstation.
   * - :doc:`ob-scp(1) <ob-scp>`
     - Copy files to, from or between backends, over the same vouched hop.
   * - :doc:`ob-sftp(1) <ob-sftp>`
     - The same for interactive SFTP transfers.

.. toctree::
   :hidden:

   ob-ssh
   ob-scp
   ob-sftp
