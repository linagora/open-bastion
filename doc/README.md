# Open Bastion Documentation

Grouped by theme, roughly in reading order: **try it → deploy it → understand
the connection model → manage access → record & audit → operate → go deep.**
New here? Start with a quick-start, then skim [Bastion Architecture](bastion-architecture.md)
and [Access & Permissions](permissions.md).

## Start here

| Document                                           | Description                                          |
| -------------------------------------------------- | ---------------------------------------------------- |
| [Docker demo](../quick-start/README.md)            | LLNG portal + a self-enrolling SSH server in ~2 min  |
| [Shell installer quick-start](shell-quickstart.md) | Generate + run a self-extracting installer per host  |
| [Ansible quick-start](ansible-quickstart.md)       | Generate + apply bastion/backend roles to a fleet    |
| [Deployment builder](../admin-builder/README.md)   | `ob-builder` — produce the shell / Ansible artefacts |
| [Admin guide](admin-guide.md)                      | End-to-end manual walkthrough per role               |

## Connections & architecture

How users reach servers, and how the bastion→backend hop is secured.

| Document                                                        | Description                                                       |
| --------------------------------------------------------------- | ----------------------------------------------------------------- |
| [Bastion architecture](bastion-architecture.md)                 | Bastion→backend certificate vouching; `ob-ssh`/`ob-scp`/`ob-sftp` |
| [PAM authentication modes](pam-modes.md)                        | The A–E matrix (token / key / password / cert)                    |
| [LemonLDAP::NG configuration](llng-configuration.md)            | Server-side: OIDC RP, plugins, SSH CA, server groups              |
| [Design: certificate vouching](design/bastion-cert-vouching.md) | Why and how the ephemeral-cert hop works                          |

## Access & permissions

Who can do what, where — and which knob lives on the SSO vs the server.

| Document                                | Description                                                        |
| --------------------------------------- | ------------------------------------------------------------------ |
| [Access & permissions](permissions.md)  | SSO-side vs Open-Bastion-side controls; the "where do I set X" map |
| [Service accounts](service-accounts.md) | Key-only local accounts (ansible, backup, CI/CD)                   |

## Session recording & audit

| Document                                                                       | Description                           |
| ------------------------------------------------------------------------------ | ------------------------------------- |
| [Session recording](session-recording.md)                                      | Tamper-evident terminal I/O capture   |
| [Primary audit trace](audit.md)                                                | Optional `auditd`-based syscall trail |
| [Design: tamper-evident recording](design/tamper-evident-session-recording.md) | Why recordings stream to a root sink  |

## Offline & resilience

| Document                                               | Description                                   |
| ------------------------------------------------------ | --------------------------------------------- |
| [Offline mode](offline-mode.md)                        | Cached authorization when LLNG is unreachable |
| [Offline cache administration](offline-cache-admin.md) | Cache config, TTLs, lockout, `ob-cache-admin` |

## Security & hardening

| Document                                      | Description                                        |
| --------------------------------------------- | -------------------------------------------------- |
| [Security features](security.md)              | Key policy, rate limiting, cache protection, audit |
| [Session containment hardening](hardening.md) | logind kill, process limits, at/cron allow-lists   |
| [CrowdSec integration](crowdsec.md)           | Pre-auth IP blocking + post-auth reporting         |

## Reference

| Document                                    | Description                                             |
| ------------------------------------------- | ------------------------------------------------------- |
| [Configuration reference](configuration.md) | Every `openbastion.conf` key                            |
| [Desktop SSO](desktop-sso.md)               | LightDM greeter + LLNG login **(experimental / alpha)** |
| [Competitors](competitors.md)               | Comparison with other solutions                         |

## Security analysis (EBIOS)

Detailed threat model and risk study, for audits and compliance (French).

| Document                                        | Description                      |
| ----------------------------------------------- | -------------------------------- |
| [Architecture](security/00-architecture.md)     | Security architecture overview   |
| [Enrollment](security/01-enrollment.md)         | Server enrollment security       |
| [SSH connection](security/02-ssh-connection.md) | SSH authentication flow security |
| [Offboarding](security/03-offboarding.md)       | User and server offboarding      |
| [Risk reduction](security/99-risk-reduce.md)    | Residual risks and mitigations   |
