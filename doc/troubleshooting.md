# Troubleshooting

Common checks and fixes when SSH/sudo access or enrollment misbehaves. See also
the [Configuration Reference](configuration.md), [PAM modes](pam-modes.md) and
[Access & Permissions](permissions.md).

## Check logs

```bash
# System auth log
sudo tail -f /var/log/auth.log

# Or journald
sudo journalctl -u sshd -f
```

`pam_openbastion` logs to the `authpriv` facility, so its detailed messages are
only visible to root / the `adm` group.

## Enable debug mode

In `/etc/open-bastion/openbastion.conf`:

```ini
log_level = debug
```

## Test token introspection

```bash
curl -X POST https://auth.example.com/oauth2/introspect \
  -u "pam-access:secret" \
  -d "token=<user_token>"
```

## Test the authorization endpoint

```bash
curl -X POST https://auth.example.com/pam/authorize \
  -H "Authorization: Bearer $(sudo cat /var/lib/open-bastion/token)" \
  -H "Content-Type: application/json" \
  -d '{"user": "testuser", "host": "'$(hostname)'", "server_group": "default"}'
```

## Common issues

| Issue                              | Cause                           | Solution                                           |
| ---------------------------------- | ------------------------------- | -------------------------------------------------- |
| `PAM unable to load module`        | Module not in path              | Check `/lib/security/` or `/lib64/security/`       |
| `Token introspection failed`       | Wrong credentials               | Verify client_id and client_secret                 |
| `Server not enrolled`              | Missing/invalid token           | Run `ob-enroll`                                    |
| `User not authorized`              | Server group rules              | Check LLNG Manager configuration                   |
| `Connection refused`               | Portal unreachable              | Check network and portal_url                       |
| `Too many authentication failures` | Client offers too many SSH keys | `ssh -o IdentitiesOnly=yes -i <key> …` (see below) |

## "Too many authentication failures"

```
Received disconnect from <host>: Too many authentication failures
```

This is a **client-side** problem, not an Open Bastion rejection. When you have
many SSH keys (in `~/.ssh` or loaded in an `ssh-agent`), the SSH client offers
them all, one by one, before the one that actually works. `sshd` counts every
offered key as a failed attempt and drops the connection once it exceeds
`MaxAuthTries` (default 6) — so the right key is never reached.

Tell the client to offer **only** the key you specify:

```bash
ssh -o IdentitiesOnly=yes -i ~/.ssh/id_for_this_host user@host
```

To make it permanent, pin it per host in `~/.ssh/config`:

```sshconfig
Host bastion.example.com
    IdentityFile ~/.ssh/id_for_this_host
    IdentitiesOnly yes
    # If an agent holds many keys and still interferes, also:
    # IdentityAgent none
```

`IdentitiesOnly yes` makes the client present only the listed `IdentityFile`(s)
instead of every key the agent advertises. This also matters when using an
SSO-signed certificate: pin the cert's key with `-i` + `IdentitiesOnly=yes` (the
`ob-ssh` / `ob-scp` / `ob-sftp` connectors already do this internally).

## Re-enrollment

If the server token expires or is compromised:

```bash
sudo rm /var/lib/open-bastion/token
sudo ob-enroll
```
