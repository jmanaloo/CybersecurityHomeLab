# Lab 06 — Active Directory IAM Monitoring with Wazuh

**Date:** November 18–19, 2026 (VM and dashboard timestamps vary by timezone)  
**Status:** Completed — Windows Security events verified and new IAM changes detected in Wazuh  
**Scope:** Authorized, isolated home-lab activity; no malicious activity or unauthorized privilege escalation demonstrated.

## Objective

Deploy a Windows Server 2022 Active Directory Domain Controller (DC), practice identity and group administration, audit changes locally, onboard the DC to Wazuh, and investigate account creation and security-group membership alerts with evidence-based SOC triage.

## Lab environment

| Component | Verified setup |
|---|---|
| Hypervisor | VMware Workstation Pro; NAT VMnet8, subnet `192.168.17.0/24` |
| Domain controller | Windows Server 2022, `AD-DC01`, static IP `192.168.17.10` |
| Active Directory | Forest/domain `corp.example.test`, NetBIOS `CORP` |
| AD layout | `IT` organizational unit; users `juan` and `maria`; global security group `IT-STAFF` |
| Wazuh manager | Rocky Linux, `192.168.17.130` |
| DC Wazuh agent | Agent `004`, name `AD-DC01`, Wazuh Windows MSI 4.12.0 |
| Existing Windows endpoint | Kept separate; existing agent registrations preserved |
| Host limitation | One working 16 GB RAM stick; other VMs kept powered off when not required |

## 1. Prepare and promote the domain controller

Created a separate Windows Server 2022 Standard Evaluation (Desktop Experience) VM with 2 GB RAM, 2 vCPUs, and 60 GB virtual disk. This preserved the existing Windows endpoint used in earlier labs.

Renamed the VM:

```powershell
Rename-Computer -NewName "AD-DC01"
Restart-Computer
hostname
```

The VMware NAT DHCP range was `192.168.17.128–254`; selected `192.168.17.10` outside that pool for the domain controller. A preliminary ping and ARP check found no response, though this alone does not guarantee an address is unused.

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.17.10 -PrefixLength 24 -DefaultGateway 192.168.17.2
Get-NetIPConfiguration -InterfaceAlias "Ethernet0"
Get-NetIPInterface -InterfaceAlias "Ethernet0" -AddressFamily IPv4 | Select-Object InterfaceAlias, Dhcp
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 192.168.17.10
```

Installed Active Directory Domain Services:

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
```

In **Server Manager → Promote this server to a domain controller**, created a **new forest** `corp.example.test`, enabled DNS and Global Catalog, used the Windows Server 2016 forest/domain functional levels, set a private DSRM password, retained default NTDS/SYSVOL paths, and installed. Nonblocking prerequisite warnings appeared; promotion and reboot succeeded.

```powershell
Get-ADDomain
```

Verified the domain, `CORP` NetBIOS name, and domain-controller FSMO role ownership.

## 2. Create identities and a security group

In **Active Directory Users and Computers (ADUC)**:

1. Created an `IT` organizational unit with accidental-deletion protection.
2. Created `juan` (`CORP\juan`) with a temporary password and **User must change password at next logon**.
3. Created `IT-STAFF` as a **Global / Security** group.
4. Added `juan` to `IT-STAFF`.
5. After onboarding Wazuh, created `maria` (`maria@corp.example.test`, display name `maria test`) with the same first-logon password-change requirement.
6. Added `maria` to `IT-STAFF`.

**IAM distinction:** Group membership is not by itself proof of elevated privileges; the group's actual permissions determine access.

## 3. Investigate Windows Security logs on AD-DC01

Opened **Event Viewer → Windows Logs → Security**, filtered by Event ID, and inspected the General tab's **Subject**, **New Account/New Group**, and **Member/Group** sections.

| Windows event | Meaning | Evidence |
|---|---|---|
| `4720` | User account created | `CORP\Administrator` created `CORP\juan` |
| `4727` | Security-enabled global group created | `CORP\Administrator` created `CORP\IT-STAFF` |
| `4728` | Member added to security-enabled global group | `CORP\Administrator` added `CORP\juan` to `CORP\IT-STAFF` |

The initial local Windows timeline showed Juan's account creation at **7:20:05 AM** and his group membership change at **7:24:22 AM**, as displayed by Event Viewer. Times in the Wazuh interface later used a different displayed timezone.

Checked audit policy:

```powershell
auditpol /get /subcategory:"Security Group Management"
auditpol /get /category:"Account Management"
```

Observed **Success** for Computer Account Management, Security Group Management, and User Account Management; **No Auditing** for Distribution Group Management, Application Group Management, and Other Account Management Events. These are observed settings, not a blanket security-hardening recommendation.

## 4. Onboard AD-DC01 to Wazuh

On the Wazuh Rocky Linux VM:

```bash
systemctl status wazuh-manager
ip -4 addr
/var/ossec/bin/agent_control -l
```

Verified the manager was **active (running)** at `192.168.17.130`. Existing Windows agent registrations remained present (disconnected while their VMs were off).

On AD-DC01:

```powershell
Test-NetConnection 192.168.17.130 -Port 1514
```

Observed `TcpTestSucceeded : True`.

In **Wazuh Dashboard → Agents → Deploy new agent**, selected **Windows MSI 32/64 bits**, manager `192.168.17.130`, name `AD-DC01`, and default agent group. Copied and executed the dashboard-generated MSI download/install command in elevated Windows PowerShell. No passwords or enrollment secrets were recorded in this portfolio.

```powershell
Get-Service -Name WazuhSvc
```

Observed **Running**. On the manager, `agent_control -l` showed **AD-DC01 Active**. In Threat Hunting, the dashboard showed **370 hits** for `AD-DC01` in the selected one-day range, including Windows logon/logoff alerts and Security Configuration Assessment findings. An active agent alone does not prove every desired event type is collected or alerted.

## 5. Detect a new account creation in Wazuh

The earlier Juan events predated agent deployment, so a search for old `4728` alerts returned no results. Rather than treating that as a monitoring failure, generated a **new authorized test** by creating `maria` while the agent was active.

In **Threat Hunting → Events**, searched for Windows Event ID `4720` from `AD-DC01`. One matching alert appeared.

| Field | Verified value |
|---|---|
| `agent.name` | `AD-DC01` |
| `agent.id` | `004` |
| `data.win.system.eventID` | `4720` |
| `data.win.eventdata.targetUserName` | `maria` |
| `data.win.eventdata.userPrincipalName` | `maria@corp.example.test` |
| `data.win.eventdata.subjectUserName` | `Administrator` |
| `rule.id` | `60109` |
| `rule.level` | `8` |
| Alert description | User account enabled or created |

**Assessment:** Expected, authorized test-account creation. Alert severity does not establish malicious intent.

## 6. Detect group membership change in Wazuh

Added `maria` to `IT-STAFF` using ADUC while the Wazuh agent was online. A fresh matching alert appeared in Threat Hunting.

| Field | Verified value |
|---|---|
| `agent.name` / `agent.id` | `AD-DC01` / `004` |
| `data.win.system.eventID` | `4728` |
| `data.win.eventdata.memberName` | `CN=maria test,OU=IT,DC=corp,DC=example,DC=test` |
| `data.win.eventdata.targetUserName` | `IT-STAFF` |
| `data.win.eventdata.subjectUserName` | `Administrator` |
| `data.win.system.computer` | `AD-DC01.corp.example.test` |
| `rule.id` | `60141` |
| `rule.level` | `5` |
| `rule.description` | Security Enabled Global Group Member Added, followed by member SID |
| Rule MITRE mapping | `T1484` (Domain Policy Modification); Defense Evasion / Privilege Escalation |

**Assessment:** Expected, authorized test membership change. Wazuh's MITRE mapping identifies a potentially relevant attack technique, **not proof** that privilege escalation or domain-policy modification occurred. No privileged access for `IT-STAFF` was demonstrated.

## 7. Validation, recovery, and lessons learned

- Confirmed Windows event creation **locally** before relying on the SIEM.
- Verified manager health, network reachability, agent service status, agent enrollment, and then actual dashboard alerts as **separate checkpoints**.
- Correlated actor (`subjectUserName`), affected account (`targetUserName` or `memberName`), group, event ID, and Wazuh rule.
- Recognized that historic events before agent deployment might not produce corresponding Wazuh alerts; generated fresh controlled tests.
- Differentiated alert rule level and MITRE mapping from incident confirmation.
- Conserved limited host RAM by powering off unused VMs.
- Shut down `AD-DC01` safely and created VMware snapshot **`Lab06-AD-Wazuh-Working`**. Snapshots are not substitutes for backups.

### SOC analyst disposition

**Benign / authorized administrative activity**, supported by the documented test procedure. In a production investigation, verify the actor's authorization, group sensitivity, change ticket, timing, and related events before closing an alert.

### Skills demonstrated

Active Directory Domain Services deployment; DNS and domain configuration; IAM user/group provisioning; Windows Security auditing; Event Viewer investigation; PowerShell/network troubleshooting; Wazuh agent enrollment; SIEM alert triage; Windows-to-Wazuh event correlation; and evidence-based incident disposition.

---

*Hands-on cybersecurity portfolio project toward a SOC Analyst L1 role. All activities were performed in an authorized home lab.*
