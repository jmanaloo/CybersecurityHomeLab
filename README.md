# Cybersecurity Home Lab

**Aspiring SOC Analyst | Hands-on security monitoring, alert investigation, and troubleshooting**

I'm building this home lab from scratch to develop practical skills for an entry-level Security Operations Center (SOC) role. This repository is both a record of my learning and a reference I can return to when I need to rebuild, troubleshoot, or explain a setup.

My professional background is in real-time workforce monitoring, where I work with operational alerts, escalation, root-cause analysis, and documentation. Here, I'm applying that investigative mindset to cybersecurity through **authorized, isolated lab exercises**.

## Lab environment

| Component | Purpose |
| --- | --- |
| VMware Workstation Pro | Virtualized lab environment |
| Rocky Linux 9.5 | Wazuh manager host |
| Wazuh | Security event monitoring, alert investigation, and File Integrity Monitoring (FIM) |
| Windows Server 2022 | Monitored endpoint running the Wazuh agent |
| Windows Event Viewer and PowerShell | Event validation and endpoint troubleshooting |
| Linux service and network tools | Checking processes, service status, logs, and listening ports |

All tests described here are performed in my own home-lab environment, not on production systems.

## Hands-on lab journal

| Lab | Focus | What I practiced |
| --- | --- | --- |
| [01 — Wazuh Installation](labs/01-wazuh-installation.md) | Build the monitoring environment | Installing, accessing, and troubleshooting the Wazuh lab |
| [02 — Windows Server Wazuh Agent](labs/02-windows-server-wazuh-agent.md) | Endpoint monitoring | Setting up a Windows Server endpoint and connecting its agent |
| [03 — Failed Login Investigation](labs/03-wazuh-failed-login-investigation.md) | Authentication alert triage | Generating an authorized failed login, finding Windows Event ID 4625 in Wazuh, and documenting why the activity was benign |
| [04 — File Integrity Monitoring](labs/04-wazuh-file-integrity-monitoring.md) | FIM and troubleshooting | Restoring agent communication, correcting monitoring configuration, and validating file creation, modification, and deletion alerts |
| [05 — PowerShell Monitoring and Detection](labs/05-wazuh-powershell-detection.md) | Windows event collection and alert triage | Enabling Event ID 4104 logging, tracing raw events, inspecting built-in rules, and validating three benign test alerts |

## Featured investigation: PowerShell detection and alert triage

In [Lab 05](labs/05-wazuh-powershell-detection.md), I enabled PowerShell Script Block Logging, configured the Wazuh agent to collect Windows Event ID **4104**, and traced an authorized test from Windows into Wazuh's raw archives. I then tested an existing detection rule (**91843**) using a harmless string assignment and confirmed **three alerts** in Threat Hunting.

**Key lesson:** Collecting an event is different from generating an alert, and a correct pattern match does not prove that a registry change or malicious action occurred.

## Featured investigation: Wazuh File Integrity Monitoring

In [Lab 04](labs/04-wazuh-file-integrity-monitoring.md), I configured monitoring for a test directory on Windows Server 2022 and validated **three out of three** file-change scenarios: creation, modification, and deletion.

The exercise also involved troubleshooting a disconnected agent. I checked service status, logs, processes, and TCP listeners, then restored Wazuh manager communication before confirming that FIM was actually monitoring the intended directory.

**Key lesson:** An active service does not necessarily mean its network listener is working; a connected agent does not necessarily mean a directory is monitored; and a detection alert does not automatically mean malicious activity.

## Skills I'm developing

- Security event monitoring and basic alert triage
- Windows Security and PowerShell event investigation, including Event IDs 4625 and 4104
- Wazuh agent configuration and File Integrity Monitoring
- Windows and Linux troubleshooting
- Network/service diagnostics and log review
- Evidence-based investigation notes and alert disposition
- Clear documentation of findings, limitations, and next steps

## How I document each lab

Each lab records the **objective, environment and parameters, emphasized commands with short explanations, observed evidence, troubleshooting and resolution, validation checks, analyst interpretation, and lessons learned**. I distinguish controlled test activity from actual malicious behavior and identify later milestones separately from the original lab scope.

**Career objective:** Transition into a SOC Analyst L1 role by combining professional experience in real-time monitoring, incident escalation, root-cause analysis, and documentation with practical cybersecurity skills developed through hands-on security investigations and home-lab projects.

## Personal note

This repository is also my own reference — a place to come back to whenever I feel lost while building a home lab from scratch.

Dedicated to my late wife, Sherryl. May she rest in peace. I will continue our dreams and aspirations for our daughter.
