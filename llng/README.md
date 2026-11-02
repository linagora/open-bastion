# LLNG plugins

The four LemonLDAP::NG plugins Open Bastion provides — `pam-access`,
`ssh-ca`, `oidc-device-authorization` and `oidc-device-organization` — are
maintained here.
[lemonldap-ng-plugins](https://github.com/linagora/lemonldap-ng-plugins)
packages them for the LLNG store.

Note they are GPL-2+, not AGPL-3.0 as the rest of Open Bastion: see
[COPYING](./COPYING) in this directory.

## Installation with Debian packages

The plugins are installed on the portal from Linagora's LLNG store, or from
its Debian packages: see [the installation
page](../doc/deployment/install.rst) of the documentation, section
"Mandatory LLNG plugins". The HTML documentation renders the README of each
plugin as its reference page.

## Pinning the submodule

`lemonldap-ng-plugins` embeds this repository as the `open-bastion` submodule
and builds the four plugins from it. Its pin must be a **tag**, never a branch
or a bare sha: this repository's history is rewritten by rebases, and a commit
that no tag carries becomes unreachable as soon as its branch is rebased away —
the submodule then fails to fetch in every fresh clone.

The tags are named `plugins-vX.Y.Z`, where `X.Y.Z` is the highest of the four
`plugin.json` versions at the tagged commit, and the `plugins-v*` pattern is
protected so that a tag cannot be moved or deleted.

We do not apply the lockstep rule of the packaging repository, where
every plugin touched by a release is bumped to that release's
version. Here only the plugin that changed is bumped. A release that
touches none of the four needs no new tag.

## Working on them

The plugins are grafted into a LemonLDAP::NG tree to be built and tested, and
that environment lives in `lemonldap-ng-plugins`: follow its `CONTRIBUTING.md`
for the development environment and for running the `t/` suites.

Nothing in this repository exercises them: no CI job runs the 34 `t/` files,
ShellCheck scans `./scripts` only, and the packaging ignores this directory. An
edit that breaks a plugin still merges green here — run the suites in the
`lemonldap-ng-plugins` checkout before merging.
