# Windows Target Server Setup

This document describes how to configure a Windows Server for use with
the RDP proxy PoC.

## Prerequisites

- Windows Server 2016 or later (or Windows 10/11 Pro)
- Network connectivity from Docker host
- Administrator access

## Quick Setup

### 1. Enable Remote Desktop

```powershell
# Run as Administrator
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

Or via GUI:
1. Open **System Properties** → **Remote** tab
2. Select **Allow remote connections to this computer**
3. Uncheck **Allow connections only from computers running Remote Desktop with Network Level Authentication** (for PoC only)

### 2. Configure Firewall

```powershell
# Allow RDP from Docker network
New-NetFirewallRule -DisplayName "RDP from Docker" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow
```

### 3. Create Test User

For the PoC, create a local user matching your LLNG username:

```powershell
# Create user 'dwho' with password 'dwho'
New-LocalUser -Name "dwho" -Password (ConvertTo-SecureString "dwho" -AsPlainText -Force) -FullName "Doctor Who"
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "dwho"
```

### 4. Disable NLA (for PoC only)

For easier testing, disable Network Level Authentication:

```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 0
```

**Warning**: This reduces security. Re-enable NLA for production.

## Network Configuration

### Option A: Docker Host Network

If the Docker host can reach the Windows server directly:

```bash
export WINDOWS_TARGET_HOST=192.168.1.100
```

### Option B: Docker Bridge Network

If using Docker bridge network, ensure routing is configured:

```bash
# On Docker host (Linux)
ip route add 192.168.1.0/24 via <gateway_ip>
```

### Option C: Host Mode (Docker Desktop)

On Docker Desktop for Windows/Mac, use `host.docker.internal`:

```bash
export WINDOWS_TARGET_HOST=host.docker.internal
```

## Testing Connectivity

From the Docker host:

```bash
# Test RDP port
nc -zv $WINDOWS_TARGET_HOST 3389

# Or with nmap
nmap -p 3389 $WINDOWS_TARGET_HOST
```

## Common Issues

### Connection Refused

- Verify RDP is enabled in Windows
- Check Windows Firewall rules
- Ensure network connectivity

### Authentication Failed

- Verify user exists on Windows server
- Check password matches
- Ensure user is in "Remote Desktop Users" group

### NLA Error

- Disable NLA for PoC (see step 4 above)
- Or configure proper certificate chain

## Security Recommendations for Production

When moving beyond PoC:

1. **Re-enable NLA**: Network Level Authentication
2. **Use domain accounts**: Instead of local users
3. **Configure certificates**: Proper TLS certificates
4. **Network segmentation**: Isolate RDP traffic
5. **Enable RDP logging**: Windows Event Log

## Useful Commands

```powershell
# Check RDP service status
Get-Service TermService

# View RDP port
netstat -an | findstr 3389

# Check firewall rules
Get-NetFirewallRule -DisplayGroup "Remote Desktop"

# View connected users
query user

# View RDP logs
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -MaxEvents 10
```
