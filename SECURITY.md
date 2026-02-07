# Security Policy

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### Contact

**Email**: security@linagora.com

Please include:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Any suggested fixes (optional)

### Response Timeline

| Stage                    | Timeline              |
| ------------------------ | --------------------- |
| Initial response         | Within 48 hours       |
| Vulnerability assessment | Within 7 days         |
| Fix development          | Depends on severity   |
| Public disclosure        | After fix is released |

### What to Expect

- We will acknowledge your report within 48 hours
- We will keep you informed of our progress
- We will credit you in the security advisory (unless you prefer anonymity)
- We will not take legal action against researchers who follow responsible disclosure

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.x     | Yes       |
| < 1.0   | No        |

Only the latest minor version receives security updates. We recommend always running the latest release.

## Security Disclosure Policy

- Security issues are fixed in private and released as part of a new version
- Security advisories are published after the fix is available
- Critical vulnerabilities may receive expedited patches

## Security Documentation

For detailed information about the security architecture and implementation:

- [Security Architecture](doc/security/00-architecture.md) - Transport security, authentication, encryption
- [Enrollment Security](doc/security/01-enrollment.md) - Server enrollment security analysis
- [SSH Connection Security](doc/security/02-ssh-connection.md) - SSH authentication and authorization
- [Offboarding Procedures](doc/security/03-offboarding.md) - Revocation and deprovisioning
- [Future Improvements](doc/security/99-risk-reduce.md) - Planned security enhancements

## Security Best Practices

When deploying Open Bastion:

1. **Use TLS 1.3** - Set `min_tls_version = 13` in configuration
2. **Enable audit logging** - Set `audit_enabled = true` for security monitoring
3. **Enable rate limiting** - Enabled by default, protects against brute-force
4. **Restrict file permissions** - Configuration files should be `0600` owned by root
5. **Use certificate pinning** - For high-security environments, pin the LLNG server certificate
6. **Never enable debug logging in production** - Debug logs may contain sensitive information
