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

| Issue                        | Cause                 | Solution                                     |
| ---------------------------- | --------------------- | -------------------------------------------- |
| `PAM unable to load module`  | Module not in path    | Check `/lib/security/` or `/lib64/security/` |
| `Token introspection failed` | Wrong credentials     | Verify client_id and client_secret           |
| `Server not enrolled`        | Missing/invalid token | Run `ob-enroll`                              |
| `User not authorized`        | Server group rules    | Check LLNG Manager configuration             |
| `Connection refused`         | Portal unreachable    | Check network and portal_url                 |

## Re-enrollment

If the server token expires or is compromised:

```bash
sudo rm /var/lib/open-bastion/token
sudo ob-enroll
```
