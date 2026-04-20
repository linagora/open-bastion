# Open Bastion — Quick Start

A 2-container setup to try Open Bastion in under 2 minutes:

- a LemonLDAP::NG portal (image `yadd/lemonldap-ng-portal`, with all
  Open Bastion plugins pre-installed — no `customPlugins` config needed,
  everything is loaded by the plugin autoloader)
- a single SSH server that enrolls itself against the portal on startup,
  then accepts LLNG access tokens as SSH passwords.

For richer scenarios (bastion → backend with JWT proof-of-origin, SSH
certificate authentication, hardened security settings), see
`docker-demo-token/`, `docker-demo-cert/` and `docker-demo-maxsec/`.

## Start

```bash
cd quick-start/
docker compose up -d
docker compose ps   # wait until both services are healthy
```

First startup takes a minute or two because the server image builds the
PAM and NSS modules from source.

## Get a token

Open http://localhost and login with one of:

| User   | Password | SSH | Sudo |
| ------ | -------- | --- | ---- |
| dwho   | dwho     | yes | no   |
| rtyler | rtyler   | yes | yes  |
| msmith | msmith   | yes | no   |

Then open http://localhost/pam and copy the displayed access token.

Alternatively, with the `llng` CLI:

```bash
llng --llng-url http://localhost --login dwho --password dwho access_token
```

## SSH in

```bash
ssh -p 2222 dwho@localhost
# Password: paste the access token
```

The server has no pre-existing Unix account for `dwho`: the NSS module
resolves the user from LLNG on the fly, and the PAM session creates the
home directory on first login.

## Try sudo

Login as `rtyler` and run `sudo -i`. You'll be asked for an access
token again — paste a fresh `rtyler` token. `dwho` and `msmith` are
rejected by the sudo rule in `lmConf-1.json`.

## Stop

```bash
docker compose down -v
```

## What this demo does not show

- Bastion → backend split with JWT proof-of-origin (see `docker-demo-token/`)
- SSH certificate authentication (see `docker-demo-cert/`)
- Session recording, CrowdSec, offline cache hardening (see `docker-demo-maxsec/`)
- `ob-enroll` manual enrollment — the server here enrolls itself in its
  entrypoint via the Device Authorization Grant, using the built-in
  `dwho` admin account.

## Adding Open Bastion plugins to an existing LemonLDAP::NG

Open Bastion does not ship with LemonLDAP::NG itself. The portal side is
provided by four plugins from the
[`lemonldap-ng-plugins`](https://github.com/linagora/lemonldap-ng-plugins)
store. All of them are required, even if you only plan to use SSH
certificate authentication — the PAM module on each server still calls
`/pam/authorize` (exposed by `pam-access`) to check server-group access,
and server self-enrollment uses the `oidc-device-authorization` /
`oidc-device-organization` plugins.

| Plugin                      | Role                                                    |
| --------------------------- | ------------------------------------------------------- |
| `pam-access`                | `/pam/authorize`, `/pam/userinfo`, `/pam/bastion-token` |
| `ssh-ca`                    | SSH certificate signing (`/ssh/sign`, `/ssh/ca`)        |
| `oidc-device-authorization` | RFC 8628 Device Authorization Grant (enrollment)        |
| `oidc-device-organization`  | Admin approval flow for device codes                    |

### Option A — via `lemonldap-ng-store` (LLNG ≥ 2.23.0, recommended)

```bash
# Register the Linagora plugins store
sudo lemonldap-ng-store add-store https://linagora.github.io/lemonldap-ng-plugins/

# Install the four plugins
sudo lemonldap-ng-store install pam-access ssh-ca \
    oidc-device-authorization oidc-device-organization
```

On LLNG ≥ 2.24.0, the `Autoloader` plugin is enabled by default and each
plugin loads as soon as its activation key (e.g. `pamAccessActivation=1`,
`sshCaActivation=1`) is truthy in the config — no `customPlugins` edit
needed. On older LLNG, add `--activate` to the `install` command (or
make sure `::Plugins::Autoloader` is in `customPlugins`).

### Option B — via Debian packages

```bash
curl -fsSL https://linagora.github.io/lemonldap-ng-plugins/store-key.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/linagora-llng-plugins.gpg

echo "deb [signed-by=/usr/share/keyrings/linagora-llng-plugins.gpg] \
https://linagora.github.io/lemonldap-ng-plugins/debian stable main" \
  | sudo tee /etc/apt/sources.list.d/linagora-llng-plugins.list

sudo apt update
sudo apt install \
    linagora-lemonldap-ng-plugin-pam-access \
    linagora-lemonldap-ng-plugin-ssh-ca \
    linagora-lemonldap-ng-plugin-oidc-device-authorization \
    linagora-lemonldap-ng-plugin-oidc-device-organization
```

The `linagora-lemonldap-ng-store` package is pulled in automatically on
LLNG < 2.24.0 so that autoload works the same way.

See the
[plugins store README](https://github.com/linagora/lemonldap-ng-plugins#readme)
for details on activation conditions and troubleshooting.

### Portal configuration

Once the plugins are installed, configure them through the LLNG Manager:

1. **PAM Access** tab — enable it, pick an OIDC RP (typically a new
   `pam-access` client with `pam` and `pam:server` scopes), and declare
   your `pamAccessSshRules` / `pamAccessSudoRules` per server group.
2. **SSH CA** tab (only if you want certificate authentication) —
   enable it and generate or import a signing key.
3. **OpenID Connect service** → enable the Device Authorization Grant on
   the `pam-access` RP (checkbox _Allow Device Authorization_) and
   require PKCE.

The `lmConf-1.json` shipped with this quick-start is a minimal working
example you can use as a reference.
