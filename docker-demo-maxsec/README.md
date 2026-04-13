# Open Bastion Maximum Security Demo (Mode E)

This Docker Compose demo demonstrates the **maximum security configuration** (Mode E) with LemonLDAP::NG:

- **SSH**: only SSO-signed certificates accepted (`AuthorizedKeysFile none`)
- **sudo**: only LLNG temporary tokens accepted (PAM-access re-authentication)
- **KRL**: mandatory Key Revocation List, refreshed every 30 minutes
- **Bastion JWT**: backend requires cryptographic proof of bastion origin

## Architecture

```mermaid
flowchart LR
    subgraph Docker["Docker Network"]
        SSO["SSO<br/>(LLNG)<br/>:80"]
        Bastion["Bastion<br/>(SSH)<br/>:2222"]
        Backend["Backend<br/>(SSH)<br/>:22"]
    end

    User["User"] -->|:80| SSO
    User -->|:2222| Bastion
    Bastion -->|SSH + JWT| Backend

    style Backend fill:#f9f,stroke:#333
```

> Only bastion port 2222 is exposed externally. Backend has no external port.

## Security Model

```
┌──────────────────────────┐       ┌──────────────────────────┐
│       SSH Access          │       │    sudo Escalation        │
│                          │       │                          │
│  SSO Certificate (1yr)   │       │  LLNG Token (5-60 min)   │
│  + /pam/authorize        │       │  + /pam/authorize        │
│                          │       │  (sudo_allowed=true)     │
│  "I have the right       │       │  "I want to perform a    │
│   to be here"            │       │   privileged action now"  │
└──────────────────────────┘       └──────────────────────────┘
```

### What's different from docker-demo-cert?

| Feature              | docker-demo-cert | docker-demo-maxsec (Mode E) |
| -------------------- | ---------------- | --------------------------- |
| SSH auth             | CA certificates  | CA certificates ONLY        |
| `AuthorizedKeysFile` | Default          | `none` (no unsigned keys)   |
| `RevokedKeys` (KRL)  | Not configured   | Mandatory + auto-refresh    |
| sudo                 | `NOPASSWD`       | LLNG token required         |
| KRL refresh          | Manual           | Cron every 30 min           |

## Quick Start

### 1. Start the environment

```bash
cd docker-demo-maxsec/
docker compose up -d
```

Wait for all services to be healthy:

```bash
docker compose ps
```

### 2. Get an SSH certificate

Create an SSH key pair (if needed) and get it signed by the SSO:

```bash
# Create an Ed25519 key
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N "" 2>/dev/null || true

# Login to LLNG
llng --llng-url http://localhost:80 --login dwho --password dwho llng_cookie

# Sign your public key
curl -s -X POST http://localhost:80/ssh/sign \
  -b ~/.cache/llng-cookies \
  -H "Content-Type: application/json" \
  -d "{\"public_key\":\"$(cat ~/.ssh/id_ed25519.pub)\",\"server_group\":\"bastion\"}" \
  | jq -r '.certificate' > ~/.ssh/id_ed25519-cert.pub

# Verify
ssh-keygen -L -f ~/.ssh/id_ed25519-cert.pub
```

### 3. Connect to the bastion

```bash
ssh -p 2222 dwho@localhost
```

### 4. Test that unsigned keys are rejected

```bash
# Generate a new unsigned key
ssh-keygen -t ed25519 -f /tmp/unsigned_key -N "" -q

# Try to connect - should be REJECTED
ssh -p 2222 -i /tmp/unsigned_key dwho@localhost
# Expected: Permission denied (publickey)
```

### 5. Test sudo (requires LLNG token)

From the bastion, connect to backend and try sudo:

```bash
# On bastion - connect to backend
ob-ssh-proxy backend

# On backend - try sudo
sudo whoami
# You will be prompted for a password
# Enter a fresh LLNG temporary token from the portal
```

To get a temporary token:

1. Go to http://localhost:80 and log in as `rtyler` / `rtyler`
2. Navigate to the PAM-access section
3. Generate a temporary token
4. Use this token as the sudo "password"

> **Note**: Only `rtyler` has sudo permissions in this demo.

## Demo Users

| User   | Password | SSH Access       | Sudo on Backend  |
| ------ | -------- | ---------------- | ---------------- |
| dwho   | dwho     | bastion, backend | No               |
| rtyler | rtyler   | bastion, backend | Yes (with token) |
| msmith | msmith   | bastion, backend | No               |

## KRL (Key Revocation List)

The KRL is automatically refreshed every 30 minutes via cron. To manually check:

```bash
# Check KRL on bastion
docker exec ob-maxsec-bastion ls -la /etc/ssh/revoked_keys

# Check cron job
docker exec ob-maxsec-bastion cat /etc/cron.d/open-bastion-krl
```

## Troubleshooting

### Check container logs

```bash
docker logs ob-maxsec-sso
docker logs ob-maxsec-bastion
docker logs ob-maxsec-backend
```

### Verify Mode E configuration

```bash
# Check AuthorizedKeysFile is none
docker exec ob-maxsec-bastion grep AuthorizedKeysFile /etc/ssh/sshd_config.d/llng-bastion.conf

# Check KRL is configured
docker exec ob-maxsec-bastion grep RevokedKeys /etc/ssh/sshd_config.d/llng-bastion.conf

# Check sudo PAM uses pam_openbastion (not NOPASSWD)
docker exec ob-maxsec-backend cat /etc/pam.d/sudo
```

### Reset everything

```bash
docker compose down
docker compose up -d
```

## Security Notes

- In production, use HTTPS for the portal
- Each server should have a unique enrollment token
- KRL refresh interval should match your revocation SLA
- Consider shorter certificate validity in high-security environments
- Enable audit logging for compliance
- **Bastion JWT**: Backends require a valid JWT from the bastion
- **sudo tokens**: Each sudo operation requires a fresh LLNG authentication
