# Open Bastion Demo — Token + Service Accounts

Same as `docker-demo-token/` (LLNG tokens used as SSH passwords for human
users) but also wires up **local service accounts** (`ansible`, `backup`,
...) that authenticate via a plain SSH key declared in
`/etc/open-bastion/service-accounts.conf` — **no SSH CA, no SSO
signature, no LLNG involvement on the auth path**.

## Two authentication flows in one bastion

| User kind       | SSH auth         | How                                                                                                                         |
| --------------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Human           | Password (token) | Paste LLNG access token as the SSH password                                                                                 |
| Service account | Public key       | sshd accepts the key via `AuthorizedKeysCommand` → pam_openbastion verifies the fingerprint against `service-accounts.conf` |

A service account is a plain local account: you create it with `useradd`,
Open Bastion does not. It exempts the account from the SSO and serves its
key, nothing more.

Regular users can still `sudo` by re-entering their token (stock
behaviour). Open Bastion grants service accounts no `sudo` right: a
`NOPASSWD:` rule of yours in `/etc/sudoers` is what does.

## Quick start

```bash
cd docker-demo-token-svc
docker compose up -d --build
```

### Human-user login (unchanged from docker-demo-token)

```bash
# Get an access token
TOKEN=$(llng --llng-url http://localhost:80 \
             --login dwho --password dwho \
             --client-id pam-access --client-secret pamsecret \
             access_token)

ssh -p 2222 dwho@localhost
# Password prompt: paste $TOKEN
```

### Register a service account

```bash
# Generate an SSH key locally
ssh-keygen -t ed25519 -f ~/.ssh/ansible-ci -N ""

# Create the Unix account. This demo does not record sessions; on a host
# that does, use --shell /usr/sbin/ob-login-shell.
docker exec ob-token-svc-bastion \
    useradd --system --create-home --shell /bin/bash ansible-ci

# Register its key fingerprint with Open Bastion
docker exec -i ob-token-svc-bastion sh -c \
    'cat > /etc/open-bastion/service-accounts.conf' <<EOF
[ansible-ci]
key_fingerprint = $(ssh-keygen -l -E sha256 -f ~/.ssh/ansible-ci.pub | awk '{print $2}')
EOF
docker exec ob-token-svc-bastion chmod 600 /etc/open-bastion/service-accounts.conf

# Install the authorized public key
docker cp ~/.ssh/ansible-ci.pub \
    ob-token-svc-bastion:/etc/open-bastion/service-accounts.d/ansible-ci.pub
docker exec ob-token-svc-bastion \
    chmod 644 /etc/open-bastion/service-accounts.d/ansible-ci.pub

# If it needs sudo: your rule, not Open Bastion's
docker exec ob-token-svc-bastion sh -c \
    'echo "ansible-ci ALL=(ALL:ALL) NOPASSWD: ALL" >> /etc/sudoers'
```

### Log in as the service account

```bash
ssh -i ~/.ssh/ansible-ci -p 2222 ansible-ci@localhost
sudo id
# uid=0(root) ...
```

## Integration test

```bash
./tests/test_integration_token_svc.sh --verbose
```

Covers: human-user LLNG auth, service-account registration (NSS does not
serve it, a login before `useradd` is refused and creates nothing), SSH
login with plain key once created, groups left alone by the session, no
`sudo` from Open Bastion and `sudo -n` through an operator `NOPASSWD:`
rule, rejection of non-registered keys.

## See also

- `docker-demo-token/` — token auth for humans only (no service accounts)
- `docker-demo-maxsec/` — Mode E (SSH certificates) + service accounts
- `../doc/service-accounts.rst` — canonical documentation
