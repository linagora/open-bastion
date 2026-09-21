# Security Policy

## Reporting a vulnerability

**Please do not open a GitHub issue, pull request or public discussion for a
security vulnerability.** A public report tells everyone at once, including
the people who would use it against the bastions this software guards.

Report it by email to **security@linagora.com**. Everything else on this page
describes what happens next.

### What to include

The more of this you can give us, the sooner we can confirm the issue and the
less we have to ask back:

- what the vulnerability lets an attacker do, and what position they need to
  start from (unauthenticated, a local user on a backend, an enrolled bastion);
- the affected version — `dpkg -l open-bastion`, `rpm -q open-bastion`, or the
  commit — and the operating system;
- the relevant configuration: PAM mode (A–E), whether the host is a bastion, a
  backend or standalone, and the LemonLDAP::NG version with its plugin versions;
- the steps to reproduce, and a proof of concept if you have one;
- anything you already know about mitigations.

Please redact tokens, certificates, cookies and private keys from logs before
sending them. If a value matters to the report, say what it was (an expired
`/pam/verify` token, a bastion voucher) rather than pasting it.

### Sensitive information

If you need to send something that should not travel in plain email, say so in
a first message without the details and we will arrange an encrypted channel.
We do not publish a PGP key for this address yet.

Unless you tell us otherwise, we treat a report as **TLP:AMBER+STRICT** — we
share it inside Linagora with the people who need it to fix the issue, and
nowhere else — until the fix is public.

### What to expect

| Stage                              | Timeline                         |
| ---------------------------------- | -------------------------------- |
| Acknowledgement of your report     | 2 working days                   |
| First assessment (valid, severity) | 7 days                           |
| Fix, for a confirmed vulnerability | depends on severity; we say when |
| Public advisory                    | once the fix is released         |

We will keep you informed as the assessment progresses, tell you plainly if we
conclude the report is not a vulnerability and why, and credit you in the
advisory unless you ask us not to.

Not every security-relevant report is a vulnerability in this project. Hardening
suggestions, questions about a documented trade-off, and issues in
LemonLDAP::NG itself are welcome, but they are ordinary issues: open them
publicly, or send them to the same address and we will redirect them.

### Safe harbour

We will not pursue or support legal action against anyone who reports a
vulnerability to us in good faith: who makes a reasonable effort to avoid
destroying data, degrading service and accessing other people's data, who tests
only against systems they own or are authorised to test, and who gives us a
reasonable opportunity to fix the issue before disclosing it publicly.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.6.x   | Yes       |
| < 0.6   | No        |

Open Bastion has not reached 1.0. Only the latest minor version receives
security updates, so please check that the issue reproduces on it before
reporting — and run it.

## Disclosure

Fixes are prepared privately and released as a new version. The advisory is
published once that release is available, on the
[GitHub advisories page](https://github.com/linagora/open-bastion/security/advisories)
and in [CHANGELOG.md](CHANGELOG.md). A critical vulnerability may be released
on its own, ahead of anything else in progress.

## Security documentation

This file is the reporting policy. What the product actually does is documented
separately:

- [Security reference](doc/security-reference.rst) — every control, how it is
  configured, and what it does not cover
- [Security features](doc/security.rst) — key policy, rate limiting, cache
  protection, audit
- [Session containment hardening](doc/hardening.rst) — logind kill, process
  limits, at/cron allow-lists
- [Security study (EBIOS RM)](doc/security/index.rst) — the full risk study,
  including the [conditions of use](doc/security/08-dossier-homologation.rst#2-conditions-demploi)
  the residual risk ratings depend on
