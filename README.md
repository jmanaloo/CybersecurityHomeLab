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
| [06 — Active Directory IAM Monitoring](labs/06-active-directory-iam-monitoring.md) | Identity management and SIEM detection | Deploying a domain controller, auditing user/group changes, and verifying Wazuh detections for Events 4720 and 4728 |
| [07 — AD RBAC & File Share Monitoring](labs/07-active-directory-rbac-file-share-monitoring.md) | Access control and SIEM investigation | Restricting departmental SMB shares, investigating Event 5145, and fixing a Wazuh collection exclusion |
| [08 — Custom Wazuh Detection Rules](labs/08-custom-wazuh-detection-rules.md) | Detection engineering and rule validation | Creating rule 100100, troubleshooting a decoder mismatch, and validating a level 10 alert for denied Finance-share access |
| [09 — SOC Alert Triage & Investigation](labs/09-soc-alert-triage-investigation.md) | Windows authentication investigation | Investigating 10 failed Administrator logons, correlating 23 successful-logon alerts, and practicing evidence-based incident disposition and escalation |
| [10 — Brute-Force Attack Investigation](labs/10-brute-force-investigation.md) | SOC investigation and incident response | Comparing a simulated critical exfiltration incident with actual Wazuh authentication correlation and documenting analyst development |
| [11 — PowerShell Threat Investigation](labs/11-powershell-threat-investigation.md) | SOC investigation and monitoring RCA | Simulated phishing triage, restoring PowerShell telemetry on AD-DC01, and validating built-in rule 91843 from endpoint to dashboard |

## Featured investigation: PowerShell threat investigation and monitoring RCA

In [Lab 11](labs/11-powershell-threat-investigation.md), I investigated a simulated phishing incident and then resolved practical PowerShell monitoring gaps on AD-DC01. I verified Windows Event 4104 (records 622 and 627), raw event reception, and a benign pattern-based alert (rule 91843, record 632). The write-up documents unsuccessful tests, configuration corrections, evidence limitations and analyst development.

**Key lesson:** A configured monitoring component is not necessarily a validated detection. Test the entire pipeline and distinguish events, alerts and actual impact.

## Featured investigation: Brute-force investigation and analyst development

In [Lab 10](labs/10-brute-force-investigation.md), I completed a simulated privileged-account compromise and exfiltration investigation, then examined actual Wazuh alerts: 11 failed logons, 23 successful-logon hits and selected account-management events. Matching local authentication context supported a likely benign password retry, pending owner verification. The report records containment recommendations, investigation limitations and how I refined my reasoning through feedback.

**Key lesson:** Suspicion warrants investigation; risk warrants escalation; evidence warrants conclusions.

## Featured investigation: SOC authentication alert triage

In [Lab 09](labs/09-soc-alert-triage-investigation.md), I investigated **10 failed Administrator logons (Event 4625)** on AD-DC01, searched for related successful logons (**23 Event 4624 hits** across seven days), and examined a workstation unlock (logon type 7). I practiced writing conditional incident dispositions for hypothetical administrator confirmation versus denial, clearly separating observed events from simulated interview scenarios.

**Key lesson:** Authentication alerts require event correlation, logon-type context, careful evidence handling, and willingness to revise conclusions when new information emerges.

## Featured investigation: Custom Wazuh detection engineering

In [Lab 08](labs/08-custom-wazuh-detection-rules.md), I built and deployed a custom Wazuh rule (**100100, level 10**) for failed access attempts against a restricted Finance share. I corrected an XML structure error, traced a failed simulated test to a decoder mismatch, and verified the rule with a real Windows Event **5145** generated by an authorized access-denied test.

**Key lesson:** Correct event fields alone do not guarantee an alert; the decoder, parent rule chain, and end-to-end test path must also match.

## Featured investigation: File share access monitoring

In [Lab 07](labs/07-active-directory-rbac-file-share-monitoring.md), I configured department-specific NTFS and SMB permissions, verified authorized and restricted access, and investigated a controlled denied attempt against the Finance share. I enabled Detailed File Share auditing, traced Windows Event **5145**, and resolved a Wazuh agent filter that was excluding the event. Wazuh then generated an audit-failure alert (**rule 60104, level 5**).

**Key lesson:** A working agent does not guarantee complete event visibility. Verify auditing, collection filters, and alert rules separately before drawing conclusions.

## Featured investigation: Active Directory identity monitoring

In [Lab 06](labs/06-active-directory-iam-monitoring.md), I deployed a Windows Server 2022 domain controller, created domain users and a security group, and investigated Windows Security Events **4720, 4727, and 4728**. After onboarding the domain controller as Wazuh agent **004**, I verified a new account creation alert (**rule 60109, level 8**) and a group membership change alert (**rule 60141, level 5**).

**Key lesson:** The actor, target identity, and group must be verified from event fields. An alert severity or MITRE ATT&CK mapping does not prove malicious behavior or privilege escalation.

## Featured investigation: PowerShell detection and alert triage

In [Lab 05](labs/05-wazuh-powershell-detection.md), I enabled PowerShell Script Block Logging, configured the Wazuh agent to collect Windows Event ID **4104**, and traced an authorized test from Windows into Wazuh's raw archives. I then tested an existing detection rule (**91843**) using a harmless string assignment and confirmed **three alerts** in Threat Hunting.

**Key lesson:** Collecting an event is different from generating an alert, and a correct pattern match does not prove that a registry change or malicious action occurred.

## Featured investigation: Wazuh File Integrity Monitoring

In [Lab 04](labs/04-wazuh-file-integrity-monitoring.md), I configured monitoring for a test directory on Windows Server 2022 and validated **three out of three** file-change scenarios: creation, modification, and deletion.

The exercise also involved troubleshooting a disconnected agent. I checked service status, logs, processes, and TCP listeners, then restored Wazuh manager communication before confirming that FIM was actually monitoring the intended directory.

**Key lesson:** An active service does not necessarily mean its network listener is working; a connected agent does not necessarily mean a directory is monitored; and a detection alert does not automatically mean malicious activity.

## Skills I'm developing

- Security event monitoring and basic alert triage
- Windows Security and PowerShell event investigation, including Event IDs 4625, 4104, 4720, 4727, 4728, and 5145
- Active Directory IAM, Windows account/group auditing, and SIEM correlation
- Wazuh custom detection rules, rule inheritance, and decoder troubleshooting
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
