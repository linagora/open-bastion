# CrowdSec Integration

Open Bastion can integrate with [CrowdSec](https://www.crowdsec.net/) for enhanced security:

- **Bouncer** (pre-authentication): Block IPs that are banned in CrowdSec before authentication
- **Watcher** (post-authentication): Report authentication failures to CrowdSec for threat detection

## Prerequisites

1. A running CrowdSec Local API (LAPI) - either locally or via [Crowdsieve](https://github.com/linagora/crowdsieve)
2. A bouncer API key (for IP checking): `cscli bouncers add open-bastion`
3. A machine ID and password (for alert reporting): `cscli machines add open-bastion --password <password>`

## Configuration

Add to `/etc/open-bastion/openbastion.conf`:

```ini
# Enable CrowdSec integration
crowdsec_enabled = true
crowdsec_url = http://127.0.0.1:8080

# Bouncer: check if IP is banned before authentication
crowdsec_bouncer_key = your-bouncer-api-key
crowdsec_action = reject       # reject or warn
crowdsec_fail_open = true      # allow if CrowdSec unavailable

# Whitelist: IPs/CIDRs that bypass CrowdSec checks (e.g., VPN exit nodes)
crowdsec_whitelist = 10.0.0.0/8, 192.168.1.0/24, 2001:db8::/32

# Watcher: report authentication failures
crowdsec_machine_id = open-bastion
crowdsec_password = your-machine-password
crowdsec_scenario = open-bastion/ssh-auth-failure
crowdsec_send_all_alerts = true   # send all alerts, not just bans
crowdsec_max_failures = 5         # auto-ban after N failures
crowdsec_block_delay = 180        # time window in seconds
crowdsec_ban_duration = 4h        # ban duration
```

## Using Crowdsieve

[Crowdsieve](https://github.com/linagora/crowdsieve) is a filtering proxy between local CrowdSec instances
and the Central API (CAPI). It provides:

- Alert filtering before forwarding to the cloud
- Local web dashboard for visualization
- Decision synchronization across multiple LAPI servers
- Manual IP banning from the dashboard

To use Open Bastion with Crowdsieve, point the `crowdsec_url` to your Crowdsieve instance:

```ini
crowdsec_url = http://crowdsieve.internal:8080
```

## Configuration Options

| Option                     | Default                         | Description                            |
| -------------------------- | ------------------------------- | -------------------------------------- |
| `crowdsec_enabled`         | `false`                         | Enable CrowdSec integration            |
| `crowdsec_url`             | `http://127.0.0.1:8080`         | CrowdSec LAPI URL                      |
| `crowdsec_timeout`         | `5`                             | HTTP timeout in seconds                |
| `crowdsec_fail_open`       | `true`                          | Allow auth if CrowdSec unavailable     |
| `crowdsec_bouncer_key`     | (none)                          | Bouncer API key for IP checking        |
| `crowdsec_action`          | `reject`                        | Action on ban: `reject` or `warn`      |
| `crowdsec_whitelist`       | (none)                          | Comma-separated IPs/CIDRs to bypass    |
| `crowdsec_machine_id`      | (none)                          | Machine ID for alert reporting         |
| `crowdsec_password`        | (none)                          | Machine password                       |
| `crowdsec_scenario`        | `open-bastion/ssh-auth-failure` | Scenario name for alerts               |
| `crowdsec_send_all_alerts` | `true`                          | Send all alerts or only bans           |
| `crowdsec_max_failures`    | `5`                             | Auto-ban after N failures (0=disabled) |
| `crowdsec_block_delay`     | `180`                           | Time window for counting failures      |
| `crowdsec_ban_duration`    | `4h`                            | Ban duration (e.g., `4h`, `1d`)        |

## IP Whitelist

The `crowdsec_whitelist` option allows you to specify IPs and networks that should bypass CrowdSec
checks entirely. This is useful for:

- **VPN exit nodes**: Multiple users sharing the same public IP could trigger false positives
- **Corporate networks**: Trusted internal networks that should never be blocked
- **Bastion hosts**: If traffic is forwarded through a bastion with a known IP

### Format

Comma-separated list of:

- Single IPv4 addresses: `192.168.1.1`
- IPv4 CIDR networks: `10.0.0.0/8`
- Single IPv6 addresses: `::1`
- IPv6 CIDR networks: `2001:db8::/32`

Example:

```ini
crowdsec_whitelist = 10.0.0.0/8, 192.168.1.0/24, 172.16.0.0/12, ::1, 2001:db8::/32
```

### Security Considerations

**Warning**: Whitelisted IPs bypass all CrowdSec checks, including:

- Pre-authentication ban detection (bouncer)
- Authentication failure reporting (watcher)

Use this feature carefully:

- Only whitelist IPs you fully trust
- Prefer specific IPs over large CIDR ranges
- Consider using `crowdsec_action = warn` for monitoring whitelisted traffic

See [Security Analysis](#security-considerations-1) for the DoS prevention use case.

## Security Considerations

### DoS Prevention via Whitelist

**Problem**: When multiple users share a single public IP (e.g., corporate VPN exit node, NAT gateway),
legitimate authentication failures from different users can trigger CrowdSec's auto-ban, effectively
causing a Denial of Service for all users behind that IP.

**Solution**: Add shared IPs to `crowdsec_whitelist`:

```ini
# VPN exit nodes that serve many users
crowdsec_whitelist = 203.0.113.10, 198.51.100.0/24
```

**Best practices**:

1. Only whitelist IPs you control and trust
2. Monitor whitelisted IPs separately (e.g., via SIEM or separate CrowdSec scenario)
3. Consider using `crowdsec_action = warn` instead of whitelist for partial protection
4. Document whitelisted IPs and review periodically

### Fail-Open vs Fail-Closed

The `crowdsec_fail_open` setting determines behavior when CrowdSec LAPI is unavailable:

- `crowdsec_fail_open = true` (default): Allow authentication if CrowdSec is down
- `crowdsec_fail_open = false`: Deny authentication if CrowdSec is down

**Recommendation**: Use `fail_open = true` for most deployments to avoid self-inflicted DoS when
CrowdSec is temporarily unavailable. Use `fail_open = false` only in high-security environments
where blocking access is preferable to allowing potentially malicious IPs.

## See Also

- [Configuration Reference](configuration.md) - All configuration options
- [Security Features](security.md) - Other security features
- [Security Architecture](security/00-architecture.md) - Detailed security analysis
- [Admin Guide](admin-guide.md) - Complete administration guide
