# AGENTS.md

Read this first. Follow it exactly. Skipping steps will break CI,
block merges, corrupt the codebase or make the maintainers unhappy.

## Presentation

* The goal of Open Bastion is to provide centralized SSH and ``sudo``
  access control to Linux servers with SSO integration.

* The code base is composite implementing a PAM module, an NSS module,
  systemd units, a configuration script `ob-bastion-setup`, and
  deployment helpers targeting shell users and Ansible.

* The toolchain is based on CMake.

* A test suite is integrated to the toolchain.

* Packaging is provided in DEB and RPM format.

## Contribution rules

Read [CONTRIBUTING.md](CONTRIBUTING.md) and follow it: comments,
documentation, CHANGELOG and UPGRADE-NOTES, commit messages, and the
checklist before submitting.
