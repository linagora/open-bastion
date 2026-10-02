Install
=======

This section addresses the installation of Open Bastion on the bastion
and the backend server, and the installation of the mandatory LLNG
plugins.

.. warning::

   Don't forget to install the :ref:`mandatory LLNG plugins
   <mandatory-lemonldap-ng-plugins>`. Open Bastion requires those
   plugins.

.. _open_bastion_installation:

Open Bastion installation
-------------------------

Debian based distributions
~~~~~~~~~~~~~~~~~~~~~~~~~~

Download and install the GPG key, configure a new package source, then
install the package:

.. code:: bash
   
   curl -fsSL https://linagora.github.io/open-bastion/KEY.gpg | \
         sudo gpg --dearmor -o /etc/apt/keyrings/open-bastion.gpg
   
   DISTRO=trixie
   echo "deb [signed-by=/etc/apt/keyrings/open-bastion.gpg]" \
     "https://linagora.github.io/open-bastion ${DISTRO} main" | \
     sudo tee /etc/apt/sources.list.d/open-bastion.list
   
   sudo apt update
   sudo apt install open-bastion

Make sure to adapt to your distribution: packages are provided for
Debian trixie, bookworm and Ubuntu noble.

Rocky Linux / RHEL (DNF)
~~~~~~~~~~~~~~~~~~~~~~~~

Supported distributions:

* Rocky Linux 9 / RHEL 9 / AlmaLinux 9

* Rocky Linux 10 / RHEL 10 / AlmaLinux 10

Import the GPG key, add the repository and install:

.. code:: bash

   sudo rpm --import https://linagora.github.io/open-bastion/KEY.gpg
   
   sudo tee /etc/yum.repos.d/open-bastion.repo << 'EOF'
   [open-bastion]
   name=Open Bastion
   baseurl=https://linagora.github.io/open-bastion/rpm/el$releasever/x86_64/
   enabled=1
   gpgcheck=1
   gpgkey=https://linagora.github.io/open-bastion/KEY.gpg
   EOF
   
   sudo dnf install open-bastion

Install from sources
~~~~~~~~~~~~~~~~~~~~

.. code:: bash

   sudo apt-get install libcurl4-openssl-dev \
                        libjson-c-dev \
                        libpam0g-dev \
                        libssl-dev \
                        libkeyutils-dev \
                        cmake \
                        curl \
                        jq
   
   cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/usr
   cmake --build build
   cmake --build build -- install

Note the use of ``CMAKE_INSTALL_PREFIX=/usr`` rather than taking CMake's
``/usr/local`` default: paths written into the generated ``sshd`` and
PAM configuration are absolute and hard-coded.

.. _mandatory-lemonldap-ng-plugins:

Mandatory LLNG plugins
----------------------

The portal side of Open Bastion is provided by four LLNG plugins
available from `Linagora's plugins store
<https://github.com/linagora/lemonldap-ng-plugins>`__.

Install via Linagora's plugins store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::

   This is the recommended installation method.

First, register Linagora's plugins store, then install the plugins:

.. code:: bash

   sudo lemonldap-ng-store add-store \
      https://linagora.github.io/lemonldap-ng-plugins/

   sudo lemonldap-ng-store install oidc-device-authorization \
        oidc-device-organization \
        pam-access \
        ssh-ca

With LLNG ≥ 2.24.0, the ``Autoloader`` plugin is enabled by default and
each plugin loads as soon as its activation key
(e.g. ``pamAccessActivation=1``, ``sshCaActivation=1``) is truthy in the
config.

With older LLNG, add ``--activate`` to the ``install`` command or make sure
``::Plugins::Autoloader`` is in ``customPlugins``.

Install via Linagora's DEB package repository
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Download and install the store GPG key, then install the packages with
the LLNG plugins:

.. code:: bash

   curl -fsSL https://linagora.github.io/lemonldap-ng-plugins/store-key.asc \
     | sudo gpg --dearmor -o /usr/share/keyrings/linagora-llng-plugins.gpg
   
   echo "deb [signed-by=/usr/share/keyrings/linagora-llng-plugins.gpg] \
   https://linagora.github.io/lemonldap-ng-plugins/debian stable main" \
     | sudo tee /etc/apt/sources.list.d/linagora-llng-plugins.list
   
   sudo apt update
   sudo apt install \
       linagora-lemonldap-ng-plugin-oidc-device-authorization \
       linagora-lemonldap-ng-plugin-oidc-device-organization \
       linagora-lemonldap-ng-plugin-pam-access \
       linagora-lemonldap-ng-plugin-ssh-ca

.. Third option: Use yadd/lemonldap-ng-{portal,manager,full} Docker
   images which are pre-populated with the plugins.  Is it worth
   describing?
