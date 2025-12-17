# LemonLDAP::NG Token-based SSH Authentication Demo

This Docker Compose demo demonstrates SSH authentication using LLNG tokens as passwords, including:

- **SSO Portal**: LemonLDAP::NG with PamAccess and Device Authorization plugins
- **SSH Bastion**: Jump host with token-based authentication and PAM authorization
- **SSH Backend**: Internal server accessible only through the bastion

> **Note**: For SSH certificate-based authentication (more secure), see the `docker-demo-cert/` folder.

## Architecture

```
                    ┌─────────────────────────────────────────────────────┐
                    │                   Docker Network                     │
                    │                                                      │
┌──────────┐        │  ┌───────────┐      ┌───────────┐      ┌──────────┐ │
│  User    │        │  │    SSO    │      │  Bastion  │      │ Backend  │ │
│          │───────────│  (LLNG)   │      │   (SSH)   │─────▶│  (SSH)   │ │
│          │  :80   │  │  :80      │      │  :2222    │      │  :22     │ │
└──────────┘        │  └───────────┘      └───────────┘      └──────────┘ │
     │              │        │                  │                  │      │
     │              │        └──────────────────┴──────────────────┘      │
     │              │                    llng-token-net                    │
     └──────────────┴─────────────────────────────────────────────────────┘
           :2222 (bastion only - backend has no external port)
```

## Quick Start

### 1. Start the environment

```bash
cd docker-demo-token/
docker compose up -d
```

Wait for all services to be healthy:
```bash
docker compose ps
```

### 2. Get an access token

Using the `llng` CLI tool:
```bash
llng --llng-url http://localhost:80 --login dwho --password dwho access_token
```

Copy the access token - you'll use it as your SSH password.

Or via browser at http://localhost:80 with credentials:
- Username: `dwho`, `rtyler`, or `msmith`
- Password: same as username

Then go to the "PAM Access" tab to see your access token.

### 3. Connect to the bastion

```bash
ssh -p 2222 dwho@localhost
# Password: paste your LLNG access token
```

### 4. From bastion, connect to backend

```bash
# On bastion - get a new token first (or use the same one)
ssh dwho@backend
# Password: paste your LLNG access token
```

## Demo Users

| User    | Password | SSH Access        | Sudo on Backend |
|---------|----------|-------------------|-----------------|
| dwho    | dwho     | bastion, backend  | No              |
| rtyler  | rtyler   | bastion, backend  | Yes             |
| msmith  | msmith   | bastion, backend  | No              |

## How Token Authentication Works

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│    User     │         │  LLNG SSO   │         │ SSH Server  │
│             │         │             │         │  (PAM)      │
│ Has: token  │         │ Validates   │         │ Checks      │
│             │         │   tokens    │         │   with SSO  │
└──────┬──────┘         └──────┬──────┘         └──────┬──────┘
       │                       │                       │
       │  1. SSH with token    │                       │
       │       as password     │                       │
       │──────────────────────────────────────────────▶│
       │                       │                       │
       │                       │  2. Validate token    │
       │                       │◀──────────────────────│
       │                       │                       │
       │                       │  3. Return user info  │
       │                       │──────────────────────▶│
       │                       │                       │
       │  4. Access granted    │                       │
       │◀──────────────────────────────────────────────│
```

### Token Authentication Flow

1. **User obtains token**: Log in to the LLNG portal and get an access token
2. **SSH connection**: User connects to SSH server, using the token as password
3. **PAM validation**: The `pam_llng.so` module validates the token with the portal
4. **Authorization check**: Portal checks if user can access the server group
5. **User creation**: If user doesn't exist locally, it's created dynamically via NSS

## Comparison with Certificate Authentication

| Feature | Token Auth | Certificate Auth |
|---------|------------|------------------|
| **Security** | Good | Better (no password in transit) |
| **User experience** | Must paste token | Transparent with SSH agent |
| **Key management** | Token expires automatically | Certificate expires automatically |
| **Server setup** | Only PAM module needed | PAM module + CA trust |
| **Offline support** | Limited (cached auth) | Full (cert is self-contained) |

For production environments, we recommend **certificate authentication** (`docker-demo-cert/`).

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/pam/authorize` | POST | Check user authorization |
| `/oauth2/device` | POST | Start device authorization |
| `/device` | GET/POST | User device verification page |
| `/oauth2/token` | POST | Exchange device code for token |

## Troubleshooting

### Check container logs
```bash
docker logs llng-token-sso
docker logs llng-token-bastion
docker logs llng-token-backend
```

### Test PAM authorization manually
```bash
docker exec llng-token-bastion curl -s http://sso/pam/authorize \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"user":"dwho","server_group":"bastion"}'
```

### Token not working?

1. Make sure the token hasn't expired (default: 1 hour)
2. Get a fresh token from the portal
3. Check that the user has access to the server group

## Configuration Files

- `docker-compose.yml` - Service definitions
- `lmConf-1.json` - LemonLDAP::NG configuration
- `bastion/Dockerfile` - Bastion image build
- `bastion/entrypoint.sh` - Bastion startup script
- `backend/Dockerfile` - Backend image build
- `backend/entrypoint.sh` - Backend startup script

## Security Notes

- In production, use HTTPS for the portal
- Each server should have a unique token
- Tokens should be rotated regularly
- Enable `verify_ssl = true` in production
- Consider certificate authentication for better security
