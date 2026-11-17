# Lab 04 — Wazuh File Integrity Monitoring (FIM)

**Date:** November 16, 2026  
**Environment:** VMware Workstation Pro | Rocky Linux 9.5 | Wazuh 4.12.0 | Windows Server 2022  
**Type:** Authorized home-lab exercise  
**Outcome:** Successfully detected file creation, modification, and deletion.

## Objective

Configure real-time File Integrity Monitoring (FIM) on a Windows Server endpoint, verify that alerts reach the Wazuh dashboard, and practice evidence-driven troubleshooting when the monitoring pipeline fails.

## Lab environment

| Component | Role | Lab address |
|---|---|---|
| Rocky Linux VM | Wazuh manager | `192.168.17.130` |
| Windows Server 2022 VM | Wazuh agent endpoint | `192.168.17.134` |
| Wazuh agent ID | Active endpoint registration | `002` |
| Test directory | Monitored folder | `C:\WazuhLab` |

> The addresses above belong to an isolated VMware home-lab network. No production systems were involved.

## Command reference — commands used and why

The commands below are highlighted for reproducibility. Each explanation states what was checked or changed during the lab.

**Command: Restart the Windows Wazuh agent after saving FIM configuration**

```powershell
Restart-Service -Name WazuhSvc
```

*Purpose:* Reloads the Windows agent configuration so the real-time monitoring entry can take effect.

**Command: Check whether the Wazuh manager service is running**

```bash
systemctl status wazuh-manager
```

*Purpose:* Checks the Linux service state; an active service alone does not guarantee that TCP 1514 is listening.

**Command: Inspect the agent communication listener**

```bash
ss -lntp | grep 1514
```

*Purpose:* Checks for a TCP listener on port 1514, used for normal Wazuh agent communication.

**Command: Inspect Wazuh listening sockets**

```bash
ss -lntup | grep wazuh
```

*Purpose:* Helps distinguish the enrollment listener on TCP 1515 from the normal agent communication listener on TCP 1514.

**Command: Check the remoted process**

```bash
ps -ef | grep '[w]azuh-remoted'
```

*Purpose:* Checks whether the process responsible for agent communications is actually running.

**Command: Stop and restart the manager during recovery**

```bash
systemctl stop wazuh-manager
systemctl start wazuh-manager
```

*Purpose:* Restarts the manager components after verifying the service state and investigating the suspected stale PID record. No unrelated process or PID file was manually removed.

## Configuration

1. Backed up the Windows agent configuration file `C:\Program Files (x86)\ossec-agent\ossec.conf`.
2. Verified that the agent's manager address was `192.168.17.130`.
3. Created the isolated test directory `C:\WazuhLab`.
4. Added the following line inside the existing `<syscheck>` block without removing the other entries:

```xml
<directories realtime="yes">C:\WazuhLab</directories>
```

5. Confirmed that the saved file contained the rule, then restarted the Windows agent:

```powershell
Restart-Service -Name WazuhSvc
```

The existing `<frequency>43200</frequency>` setting represents a scheduled scan interval of 12 hours; the new directory rule requests real-time monitoring for the test folder.

## Troubleshooting: Agent disconnected

During setup, the Windows agent disconnected from the manager. I used logs and service/network checks rather than immediately reinstalling the software.

### Evidence and investigation

- Windows agent log reported `ERROR (1216)`: connection to `192.168.17.130:1514/tcp` was actively refused.
- `systemctl status wazuh-manager` reported the manager service active, but `ss -lntp | grep 1514` returned no listener.
- Manager configuration included `<port>1514</port>` and `<protocol>tcp</protocol>`.
- `ss -lntup | grep wazuh` showed `wazuh-authd` listening on TCP 1515 (enrollment), but not `wazuh-remoted` on TCP 1514 (normal agent communication).
- `ps -ef | grep '[w]azuh-remoted'` found no running remoted process.
- The manager startup journal reported `wazuh-remoted already running`.
- A `wazuh-remoted-2038.pid` file referred to PID 2038, which was actually an `sd-pam` process. This supported a **suspected stale PID record**, not a confirmed sole root cause.

### Recovery

Stopped the Wazuh manager using `systemctl stop wazuh-manager`, verified the service was inactive, and checked remaining processes. The separate dashboard and indexer services were still running, but manager components were no longer present. The suspected stale remoted PID file had disappeared after the manager stop; **no PID file was manually deleted and the unrelated `sd-pam` process was not terminated**.

Started the manager again:

```bash
sudo systemctl start wazuh-manager
sudo ss -lntp | grep 1514
```

The listener returned as `wazuh-remoted` on `0.0.0.0:1514`, and the Windows agent reconnected.

### Agent registration observation

The dashboard showed two registrations for the same lab endpoint:

| ID | Name | Status during investigation |
|---|---|---|
| 001 | Win-serverlab | Disconnected |
| 002 | WIN-E80G02SELAT | Active |

I verified that the Windows agent's `client.keys` began with ID `002` **without sharing its secret key**. FIM investigations therefore used agent `002`. The old registration was left untouched during this lab.

### Missing monitoring rule

Initial file-change tests produced no FIM events. Searching the active Windows `ossec.conf` for `WazuhLab` returned no matches, showing the test directory rule was absent from the configuration in use. After adding the rule, verifying it was saved, and restarting the agent, its operational log showed:

```text
Connected to the server ([192.168.17.130]:1514/tcp).
FIM sync module started.
Real-time file integrity monitoring started.
```

This reinforced the difference between **agent connectivity**, **FIM initialization**, and **confirmed coverage of a specific directory**.

## Detection validation

I generated authorized file activity in `C:\WazuhLab` and inspected **File Integrity Monitoring → Events** for agent `002`. The dashboard recorded these events for `C:\WazuhLab\sex.txt`:

| Action | syscheck.event | Wazuh rule | Rule level | Rule description |
|---|---|---|---|---|
| Create file | `added` | 554 | 5 | File added to the system. |
| Change file contents | `modified` | 550 | 7 | Integrity checksum changed. |
| Delete file | `deleted` | 553 | 7 | File deleted. |

**Result: 3/3 detection tests passed.** The modification alert indicated a change to the file's integrity checksum. Adjusting the dashboard time filter helped locate the events.

## SOC Analyst interpretation

The alerts accurately reported the file operations, but the activity was **authorized and benign** because I performed it as part of this test. A Wazuh severity level does not, by itself, prove malicious intent.

In a production investigation involving an important deleted configuration file, my initial triage would be to validate the alert, identify the affected asset and file, correlate relevant account/process activity where available, check approved change or maintenance records, assess impact, and escalate according to incident-response procedures if suspicious.

## Skills practiced

- Wazuh File Integrity Monitoring and real-time directory configuration
- Windows PowerShell and agent operational log review
- Linux systemd, journal, process, and socket inspection
- TCP 1514 agent communication versus TCP 1515 enrollment
- Troubleshooting a suspected stale process ID record
- Verifying configuration persistence and post-change service health
- SOC alert triage: separating true detections from malicious activity

## Key takeaway

**An active service is not proof that its network listener works; an active agent is not proof that a directory is monitored; and a detection alert is not proof of an attack.** Verify each stage with evidence.

---

*Personal hands-on learning project. This documents a simulated home-lab exercise, not professional SOC employment.*
