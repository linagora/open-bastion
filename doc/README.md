# Open Bastion Documentation

Grouped by theme, roughly in reading order: **try it → deploy it → understand
the connection model → manage access → record & audit → operate → go deep.**
New here? Start with a quick-start, then skim [Bastion Architecture](bastion-architecture.md)
and [Access & Permissions](permissions.md).

## Start here

| Document                                           | Description                                          |
| -------------------------------------------------- | ---------------------------------------------------- |
| [Docker demo](../quick-start/README.md)            | LLNG portal + a self-enrolling SSH server in ~2 min  |
| [Configure your SSO](llng-configuration.md)        | Install the plugins + create the OIDC client(s)      |
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
| [LemonLDAP::NG plugin parameters](llng-plugin-parameters.md)    | Reference: optional `[portal]` parameters (indicative)            |
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
| [Troubleshooting](troubleshooting.md)       | Logs, debug mode, endpoint tests, common issues         |
| [Desktop SSO](desktop-sso.md)               | LightDM greeter + LLNG login **(experimental / alpha)** |
| [Competitors](competitors.md)               | Comparison with other solutions                         |
| [Slide deck](slides/README.md)              | HTML meetup presentation (intro talk)                   |

## Security analysis (EBIOS Risk Manager)

Full risk study following the ANSSI EBIOS RM method, for audits and compliance
(French). Start at **[security/README.md](security/README.md)**, which maps each
document to its workshop.

| Workshop                    | Document                                                                                                                    | Description                                                                                          |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| —                           | [Architecture](security/00-architecture.md)                                                                                 | Security target and architecture overview                                                            |
| **1** Scope and baseline    | [Atelier 1](security/04-atelier1-cadrage-socle.md)                                                                          | Perimeter, business values, **scales**, feared events, baseline                                      |
| **2** Risk origins          | [Atelier 2](security/05-atelier2-sources-de-risque.md)                                                                      | Risk sources, target objectives, retained pairs                                                      |
| **3** Strategic scenarios   | [Atelier 3](security/06-atelier3-scenarios-strategiques.md)                                                                 | Ecosystem mapping and seven strategic scenarios                                                      |
| **4** Operational scenarios | [Enrollment](security/01-enrollment.md) · [SSH](security/02-ssh-connection.md) · [LLNG portal](security/09-portail-llng.md) | 47 risk sheets with initial and residual scores, including eight for the LLNG portal and its plugins |
| **5** Treatment             | [Treatment plan](security/07-plan-de-traitement.md) · [Risk reduction](security/99-risk-reduce.md)                          | Dated, owned plan; consolidated residual matrix                                                      |
| Decision                    | [Homologation dossier](security/08-dossier-homologation.md)                                                                 | Perimeter, **conditions of use**, residual risk acceptance                                           |
| Operational                 | [Offboarding](security/03-offboarding.md)                                                                                   | User and server offboarding procedure                                                                |

> Deploying? The twenty **conditions of use** in
> [the homologation dossier](security/08-dossier-homologation.md#2-conditions-demploi)
> are the assumptions the residual scores depend on — and that the product does
> not all enforce for you.
