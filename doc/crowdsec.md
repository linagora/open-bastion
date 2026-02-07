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
| `crowdsec_machine_id`      | (none)                          | Machine ID for alert reporting         |
| `crowdsec_password`        | (none)                          | Machine password                       |
| `crowdsec_scenario`        | `open-bastion/ssh-auth-failure` | Scenario name for alerts               |
| `crowdsec_send_all_alerts` | `true`                          | Send all alerts or only bans           |
| `crowdsec_max_failures`    | `5`                             | Auto-ban after N failures (0=disabled) |
| `crowdsec_block_delay`     | `180`                           | Time window for counting failures      |
| `crowdsec_ban_duration`    | `4h`                            | Ban duration (e.g., `4h`, `1d`)        |

## See Also

- [Configuration Reference](configuration.md) - All configuration options
- [Security Features](security.md) - Other security features
- [Admin Guide](admin-guide.md) - Complete administration guide
