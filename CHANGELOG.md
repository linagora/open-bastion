# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-04-13

### Added

- **Mode E: Maximum Security** (#100): New security configuration enforcing the
  strictest SSH posture
  - SSH authentication via SSO-signed certificates only (`AuthorizedKeysFile none`)
  - sudo only via fresh LLNG temporary token (PAM-access re-authentication)
  - Mandatory KRL (Key Revocation List) with automatic refresh via `/ssh/revoked`
  - `--max-security` option in `ob-backend-setup` and `ob-bastion-setup` scripts
  - KRL refresh script with proper SSL/timeout option inheritance
- **docker-demo-maxsec**: Full Docker Compose demo for Mode E architecture
- **CI integration tests for Mode E** (`test_integration_maxsec.sh`): Validates
  certificate-only auth, unsigned key rejection, KRL configuration, sudo PAM
  hardening, and password authentication is disabled
- **EBIOS security study refactored** for maximum security target:
  - `doc/security/00-architecture.md` translated to French with Mode E introduction
  - `doc/security/02-ssh-connection.md` simplified to single architecture (Mode E)
  - `doc/security/03-offboarding.md` simplified to Mode E offboarding procedure
  - New risks R-S15 (stale KRL) and R-S16 (sudo escalation) documented

### Fixed

- **`OB_BASTION_JWT` → `LLNG_BASTION_JWT`**: Aligned environment variable name
  across all files to match the actual PAM module code and `ob-ssh-proxy`
- **`AllowAgentForwarding no`** on bastion: Agent forwarding is not needed
  (ob-ssh-proxy handles JWT injection, not ProxyJump)
- **ProxyJump references replaced with `ob-ssh-proxy`** in security documentation:
  native ProxyJump is incompatible with bastion JWT injection
- **KRL format validation**: Verify SSH KRL magic bytes (`SSHKRL`) before replacing
  the revocation file, preventing HTML error pages from breaking sshd

## [0.1.1] - 2026-02-07

### Added

- **Supplementary groups synchronization** (#95): LLNG can now manage Unix supplementary
  groups on target servers via the `managed_groups` configuration
  - **Local whitelist for managed groups** (`allowed_managed_groups`): Defense-in-depth
    option to restrict which groups LLNG can modify on each server
- **CrowdSec IP/CIDR whitelist** (#96): New `crowdsec_whitelist` option to bypass
  CrowdSec checks for trusted IPs/networks (VPN exit nodes, corporate NAT)
  - Supports IPv4, IPv6, and CIDR notation
  - Prevents self-inflicted DoS on shared IPs

### Fixed

- **TOCTOU race condition in cache_key.c** (#97): Use `open()` with
  `O_CREAT|O_EXCL|O_NOFOLLOW` instead of `fopen()` to prevent symlink attacks
- Check `fclose()` return value to detect flush errors before rename

## [0.1.0] - 2025-02-07

Initial release.
