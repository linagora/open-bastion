# LemonLDAP::NG Configuration

Before deploying the PAM module on your servers, you need to configure LemonLDAP::NG.

## Step 1: Install the Plugins

Copy the plugins from the [`llng-plugin`](../llng-plugin) directory to your LemonLDAP::NG installation:

```bash
sudo cp -r llng-plugin/usr/share/* /usr/share/
```

This installs the 3 Open Bastion plugins for LemonLDAP::NG:

- **PamAccess** - Main plugin: token generation interface and authorization endpoints (`/pam/authorize`, `/pam/bastion-token`)
- **OIDCDeviceAuthorization** - Server enrollment via OAuth 2.0 Device Authorization Grant (RFC 8628)
- **SSHCA** _(optional)_ - SSH Certificate Authority for certificate-based authentication

## Step 2: Create the OIDC Relying Party

In the LLNG Manager, create a new OIDC Relying Party:

1. Go to **OpenID Connect Relying Parties** → **Add**
2. Configure:
   - **Client ID**: `pam-access`
   - **Client secret**: Generate a strong secret
   - **Allowed grant types**: Enable `device_code` (for server enrollment)
   - **Allowed scopes**: `openid`, `pam:server`

## Step 3: Enable the Plugins

Use `customPlugins` inside `lemonldap-ng.ini`, section `[portal]`:

- without SSHCA:

```ini
[portal]
customPlugins = ::Plugin::OIDCDeviceAuthorization, ::Plugins::PamAccess
```

- with SSHCA

```ini
[portal]
customPlugins = ::Plugin::OIDCDeviceAuthorization, ::Plugins::PamAccess, ::Plugins::SSHCA
```

## Step 4: Plugin Parameters

Additional and optional parameters that can be inserted into `lemonldap-ng.ini`, section `[portal]`:

### General Parameters

| Parameter                                       | Default      | Description                             |
| ----------------------------------------------- | ------------ | --------------------------------------- |
| `oidcServiceDeviceAuthorizationExpiration`      | `600` (10mn) | Device authorization expiration time    |
| `oidcServiceDeviceAuthorizationPollingInterval` | `5`          | Polling interval in seconds             |
| `oidcServiceDeviceAuthorizationUserCodeLength`  | `8`          | Length of user code                     |
| `portalDisplayPamAccess`                        | `0`          | Set to 1 (or a rule) to display PAM tab |
| `pamAccessRp`                                   | `pam-access` | OIDC Relying Party name                 |
| `pamAccessTokenDuration`                        | `600` (10mn) | Token duration                          |
| `pamAccessMaxDuration`                          | `3600` (1h)  | Maximum token duration                  |
| `pamAccessExportedVars`                         | `{}`         | Exported variables                      |
| `pamAccessOfflineTtl`                           | `86400` (1d) | Offline cache TTL                       |
| `pamAccessSshRules`                             | `{}`         | SSH access rules                        |
| `pamAccessServerGroups`                         | `{}`         | Server groups configuration             |
| `pamAccessSudoRules`                            | `{}`         | Sudo rules                              |
| `pamAccessOfflineEnabled`                       | `0`          | Enable offline mode                     |
| `pamAccessHeartbeatInterval`                    | `300` (5mn)  | Heartbeat interval                      |

### SSH CA Parameters (optional)

| Parameter               | Default    | Description                               |
| ----------------------- | ---------- | ----------------------------------------- |
| `portalDisplaySshCa`    | `0`        | Set to 1 (or a rule) to display SSHCA tab |
| `sshCaCertMaxValidity`  | `365` (1y) | Maximum certificate validity              |
| `sshCaSerialPath`       | `""`       | Path for certificate serial storage       |
| `sshCaPrincipalSources` | `$uid`     | Principal sources                         |
| `sshCaKrlPath`          | `""`       | Path for Key Revocation List              |

## Step 4.1: Generate and Import the SSH CA Key (optional)

If you're using the SSH CA plugin for key-based authentication, you need to generate a CA key pair and import it into LemonLDAP::NG.

### Generate the SSH CA Key Pair

```bash
# Generate Ed25519 CA key pair (recommended)
openssl genpkey -algorithm ed25519 -out ssh-ca.key
openssl pkey -in ssh-ca.key -pubout -out ssh-ca.pub

# Display keys for import into LLNG Manager
echo "=== Private Key (copy this) ==="
cat ssh-ca.key
echo "=== Public Key (copy this) ==="
cat ssh-ca.pub
```

Alternatively, for compatibility with older systems, use RSA:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out ssh-ca.key
openssl pkey -in ssh-ca.key -pubout -out ssh-ca.pub
```

### Import the Key into LLNG

#### Via Manager (LemonLDAP::NG >= 2.22)

1. Go to **General Parameters** → **Keys** → **Add a key**
2. Set a key name (e.g., `ssh-ca`)
3. Paste the private key content into **Private key**
4. Paste the public key content into **Public key**
5. Save the configuration

Then configure the SSH CA plugin to use this key inside `lemonldap-ng.ini`, section `[portal]`:

```ini
[portal]
sshCaKeyRef = ssh-ca
```

#### Via lemonldap-ng.ini

Insert this into `lemonldap-ng.ini`, section `[portal]`:

```ini
[portal]
keys = { ssh-ca => { keyPublic => "<public key value>", keyPrivate => "<private key value>" } }
sshCaKeyRef = ssh-ca
```

### Create directories for SSH CA state files

```bash
sudo mkdir -p /var/lib/lemonldap-ng/ssh
sudo chown www-data:www-data /var/lib/lemonldap-ng/ssh
```

These directories store the certificate serial number counter and the Key Revocation List (KRL).

## Step 5: Restart LemonLDAP::NG

```bash
sudo systemctl restart lemonldap-ng-fastcgi-server
# or
sudo systemctl restart apache2  # if using mod_perl
```

## Server Groups

Server groups allow different authorization rules for different server categories.

### Configure in LLNG Manager

```
General Parameters > Plugins > PAM Access > Server Groups

production => $hGroup->{ops}
staging    => $hGroup->{ops} or $hGroup->{dev}
dev        => $hGroup->{dev}
default    => 1
```

### Configure on Each Server

In `/etc/open-bastion/openbastion.conf`:

```ini
server_group = production
```

Or during enrollment:

```bash
sudo ob-enroll -g production
```
