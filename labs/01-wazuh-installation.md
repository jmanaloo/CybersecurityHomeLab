# Lab 01 — Wazuh Dashboard Access and Troubleshooting

**Status:** Completed — dashboard access restored and login verified  
**Scope:** Troubleshooting an existing Wazuh installation; not a fresh installation from scratch

## Lab Overview

**Objective:** Deploy Wazuh SIEM using VMware Workstation Pro, configure network connectivity, troubleshoot dashboard access, and prepare for Windows agent deployment.

### Lab Environment

| Component | Configuration |
|---|---|
| Hypervisor | VMware Workstation Pro |
| Operating System | Rocky Linux 9.5 |
| SIEM Platform | Wazuh |
| RAM | 8 GB |
| CPU | 4 vCPUs |
| Disk | 30 GB |
| Network Adapter | NAT (VMnet8) |
| Wazuh Server IP | 192.168.17.130 |
| Windows Host | Windows 11 |

**Note:** This documents troubleshooting an existing Wazuh installation, not the original installation commands. For a fresh deployment, first import the official Wazuh virtual appliance or follow the official installation guide.

## Command reference — purpose and verification

Commands below are shown in separate code blocks with their purpose and observed results in the corresponding sections. **Run commands on the specified host**; `firewall-cmd` changes were made on the isolated Rocky Linux VM. A successful dashboard login was verified after HTTPS was permitted.

## 1. Verify Linux OS and IP Address

Open the Wazuh VM terminal.

```bash
cat /etc/os-release
```

Identifies the Linux distribution.

```bash
ip -4 addr
```

Displays IPv4 addresses assigned to network interfaces.

**Result:** Rocky Linux 9.5 with IP `192.168.17.130`.

## 2. Check Wazuh Services

```bash
systemctl status wazuh-manager --no-pager
systemctl status wazuh-indexer --no-pager
systemctl status wazuh-dashboard --no-pager
```

All three services should display:

```text
Active: active (running)
```

**Result:** All three Wazuh components were installed and running.

## 3. Test Connectivity from Windows

Open Windows Command Prompt:

```cmd
ping 192.168.17.130
```

Tests network connectivity between the Windows host and Wazuh VM.

Open PowerShell:

```powershell
Test-NetConnection 192.168.17.130 -Port 443
```

Tests access to the Wazuh dashboard's HTTPS port.

**Initial results:**
- Ping: Successful (0% packet loss)
- TCP port 443: Failed

**Diagnosis:** Basic network connectivity was working, but HTTPS access was blocked.

## 4. Check Dashboard Listening Port

Inside the Wazuh Linux terminal:

```bash
ss -tlnp | grep -E ':(443|5601)\b'
```

Checks whether the dashboard is listening on HTTPS ports.

```bash
grep -E '^[[:space:]]*server\.(host|port):' /etc/wazuh-dashboard/opensearch_dashboards.yml
```

Checks the dashboard's configured IP binding and port.

**Result:**

```yaml
server.host: 0.0.0.0
server.port: 443
```

The dashboard was configured to listen on all IPv4 interfaces.

## 5. Check the Linux Firewall

```bash
systemctl is-active firewalld
firewall-cmd --list-all
```

Checks whether the firewall is active and which services are allowed.

**Problem found:** The firewall allowed SSH and Cockpit but did not allow HTTPS.

### Fix: Allow HTTPS

```bash
firewall-cmd --permanent --zone=public --add-service=https
firewall-cmd --reload
```

Verify:

```bash
firewall-cmd --zone=public --list-services
```

Expected output includes:

```text
cockpit dhcpv6-client https ssh
```

**Result:** HTTPS was allowed through the firewall.

## 6. Test the Dashboard Locally

```bash
curl -k -I --connect-timeout 5 https://127.0.0.1:443
```

Checks whether the dashboard responds from within the Linux VM.

**Result:**

```text
HTTP/1.1 302 Found
location: /app/login?
```

This confirmed that the web server was responding.

## 7. Access the Wazuh Dashboard

From the Windows host, open:

```text
https://192.168.17.130
```

A self-signed certificate warning may appear in the browser.

**Result:** Successfully reached the Wazuh login page after fixing the firewall.

## 8. Retrieve Wazuh Administrator Credentials

Search for the installation archive:

```bash
find /root -name "wazuh-install-files.tar" 2>/dev/null
```

Check for the password file:

```bash
tar -tf /root/wazuh-install-files.tar | grep wazuh-passwords.txt
```

Display the credentials locally:

```bash
tar -xOf /root/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

Find the generated password associated with the `admin` account.

**Security reminder:** Never commit passwords, installation archives, private keys, or credentials to GitHub.

**Result:** Successfully logged into the Wazuh dashboard.

## 9. Windows Agent Deployment — Subsequent Lab

From the Wazuh dashboard:

1. Navigate to **Deploy new agent**.
2. Select **Windows MSI 32/64 bits**.
3. Enter the Wazuh Manager IP: `192.168.17.130`.
4. Assign a unique agent name, such as `WinServer-Lab`.
5. Copy the generated PowerShell installation command.
6. Run it as Administrator on the Windows machine being monitored.

After installation, start the agent:

```powershell
Start-Service WazuhSvc
```

Verify its status:

```powershell
Get-Service WazuhSvc
```

Test connectivity to the manager:

```powershell
Test-NetConnection 192.168.17.130 -Port 1514
Test-NetConnection 192.168.17.130 -Port 1515
```

**Historical scope:** At the end of Lab 01, agent deployment was pending. It was subsequently completed and verified in [Lab 02](02-windows-server-wazuh-agent.md). The examples above are preparatory steps, not evidence that Lab 01 performed deployment.

## Key Lessons Learned

- A successful ping does not guarantee application connectivity.
- `systemctl` helps diagnose Linux services.
- `ss` identifies listening network ports.
- `firewall-cmd` manages Rocky Linux firewall rules.
- HTTPS requires TCP port 443 to be accessible.
- Wazuh Manager, Indexer, and Dashboard are separate components.
- Troubleshoot networking, services, and firewall rules before reinstalling software.

## Lab Progress

- [x] Configure VMware NAT networking
- [x] Verify Wazuh server IP address
- [x] Verify Wazuh services
- [x] Diagnose HTTPS connection timeout
- [x] Configure Rocky Linux firewall
- [x] Access Wazuh dashboard
- [x] Log in to Wazuh
- [x] Install Windows Wazuh agent — **completed later in Lab 02**
- [x] Verify agent enrollment — **completed later in Lab 02**
- [x] Generate and investigate security alerts — **completed later in Labs 03–05**

## SOC analyst takeaway

**Observed issue:** ICMP ping worked, but HTTPS access failed. **Resolution:** Investigated the dashboard listener and Rocky Linux firewall, permitted HTTPS, and confirmed the dashboard login page responded. A successful ping does not prove TCP application access.

## References

- [Wazuh Documentation](https://documentation.wazuh.com/current/)
- [Wazuh Virtual Machine Deployment](https://documentation.wazuh.com/current/deployment-options/virtual-machine/virtual-machine.html)
- [Wazuh Agent Deployment](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)

