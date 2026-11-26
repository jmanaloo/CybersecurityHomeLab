# Lab 11 — PowerShell Threat Investigation and Detection Validation

**Date:** November 26, 2026  
**Environment:** Authorized home lab; Windows Server 2022 domain controller AD-DC01 (agent 004, 192.168.17.10), Wazuh manager on Rocky Linux, VMware Workstation Pro.

## Objectives

Investigate suspicious PowerShell behavior, practice escalation and containment decisions, identify monitoring gaps, and validate telemetry from endpoint execution through SIEM alert visibility.

## Part A — Simulated phishing investigation

This was a guided fictional SOC scenario, not a real compromise. The scenario involved a Word document opened by Anna, suspicious encoded PowerShell, network discovery, file creation/download activity, external communication and possible persistence or credential collection. I recommended escalation to the SOC lead, continued investigation and authorized endpoint isolation. The exercise described 12 targeted emails, one compromised endpoint, another endpoint without established compromise and nine remaining under observation; email and endpoint counts should not be treated as interchangeable.

My final simulated classification was phishing and persistence, Critical severity, with the incident remaining open pending containment and higher-tier review. Critical was a scenario-specific judgment based on potential organizational impact, not proof that all endpoints were compromised. Initial access was suspected to involve the document; the exact delivery and execution mechanism required further evidence. HTTPS alone did not establish legitimacy or maliciousness. File creation and network connectivity did not establish data theft. An endpoint without observed indicators was not necessarily safe.

Recommended response: preserve email, endpoint and network evidence; isolate confirmed affected endpoints with authorization; investigate other recipients, quarantine malicious messages, assess credential exposure and coordinate password/session remediation where warranted. Confirm scope, eradication and recovery before closure. No actual attack or containment occurred in this part.

## Part B — Practical investigation and RCA

### 1. Initial symptom

Threat Hunting returned no results for:

```text
agent.name: "AD-DC01" AND data.win.system.eventID: "4104"
```

Windows had historical Event 4104 records, but that alone did not prove comprehensive logging or current Wazuh collection.

### 2. Agent collection configuration

Inspected local event collection blocks:

```powershell
Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Pattern "<localfile>" -Context 0,6
```

Application, Security and System channels were present; the PowerShell Operational channel was missing from the inspected local configuration. Existing FIM entries for powershell.exe monitored file integrity, not script execution.

Added the following localfile block and restarted the agent:

```xml
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

The service was running, and the agent log confirmed channel recognition:

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 100 | Select-String -Pattern "PowerShell|ERROR|WARNING"
```

Observed INFO (1951): Analyzing event log: 'Microsoft-Windows-PowerShell/Operational'.

### 3. Windows Script Block Logging

Initial benign commands and unique Write-Output markers did not appear in the searched 4104 records. Historical archive matches belonged to Win-serverlab (agent 003), dated November 17, not the current domain controller. This was an important source and timestamp validation lesson.

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging
```

The registry path was initially absent. Local Group Policy showed Not Configured under Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging.

Enabled the policy, leaving invocation start/stop logging unchecked, then ran:

```powershell
gpupdate /force
```

Computer and user policy updates succeeded. Registry verification returned EnableScriptBlockLogging : 1. A subsequent interactive test still did not appear in the queried records, so I tested a separate process:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'LAB11-FRESH-PROCESS'"
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=(Get-Date).AddMinutes(-2)} | Select-Object TimeCreated,RecordId,LevelDisplayName
```

Two new Verbose records appeared, 622 and 623. Record 622 contained the exact test command; 623 contained $global:?. This validated Windows script block generation, not yet manager reception.

### 4. Raw event visibility

Searching archives.json for AD-DC01 returned no matches for the test record. The manager configuration revealed both logall and logall_json set to no. This was a visibility limitation, not proof of failed ingestion.

```bash
sudo grep -E 'logall|logall_json' /var/ossec/etc/ossec.conf
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.lab11.bak
sudo nano /var/ossec/etc/ossec.conf
```

Temporarily set logall=no and logall_json=yes. Initially I selected the wrong setting; screenshot review caught the mistake before restart.

```bash
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

Manager returned active. Generated a fresh test:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'LAB11-FINAL-VALIDATION'"
```

```bash
sudo grep 'LAB11-FINAL-VALIDATION' /var/ossec/logs/archives/archives.json | grep '"name":"AD-DC01"' | tail -n 1
```

Observed agent 004, AD-DC01, Event 4104, record 627, decoder windows_eventchannel, VERBOSE, and the exact marker. Manager timestamp November 26 14:11:24 +0800. This established endpoint-to-manager collection.

### 5. Event versus alert

The dashboard still showed no matching 4104 alerts. An initial keyword search of alerts.json returned rule 5402 (successful sudo to ROOT) from agent 000: my own grep command. Refining by agent and event ID returned no matching alert:

```bash
sudo grep 'LAB11-FINAL-VALIDATION' /var/ossec/logs/alerts/alerts.json | grep '"name":"AD-DC01"' | grep '"eventID":"4104"' | tail -n 1
```

A collected benign event need not trigger an alert. Investigative activity can itself generate alerts; verify the source and context.

### 6. Built-in rule validation

```bash
ls /var/ossec/ruleset/rules/ | grep -i powershell
grep -A 10 'id="91843"' /var/ossec/ruleset/rules/0915-win-powershell_rules.xml
```

Rule 91843, level 3, parent 91802, matches New-ItemProperty followed by -Path in win.eventdata.scriptBlockText. MITRE mappings T1059.001 (PowerShell) and T1112 (Modify Registry). No built-in rules were modified.

```powershell
powershell.exe -NoProfile -Command "Write-Output 'New-ItemProperty -Path LAB11-DETECTION-TEST'"
```

This prints text only; it does not invoke New-ItemProperty.

```text
agent.name: "AD-DC01" AND rule.id: "91843"
```

Dashboard returned one hit, November 26 around 15:23:31, level 3. Expanded details confirmed Event 4104, record 632, AD-DC01.corp.example.test, VERBOSE, and exact scriptBlockText: Write-Output 'New-ItemProperty -Path LAB11-DETECTION-TEST'. Windows systemTime was 2026-11-26T07:23:33.8010283Z; dashboard and endpoint timestamps are recorded separately rather than assumed identical.

## Final disposition

Authorized benign detection test; low incident severity (informal lab classification). The rule matched a command pattern, not an actual registry modification. The monitoring pipeline was validated from execution to dashboard alert. No real phishing, persistence, registry modification or exfiltration was demonstrated by the practical test.

Cleanup: restore logall=no and logall_json=no to limit storage use, retain PowerShell logging and collection configuration. I reported restarting the manager after cleanup instructions; final saved values and post-cleanup service status were not independently verified in the supplied evidence. Recommended closure: verify both settings and manager health, preserve evidence and confirm monitoring remains functional.

## Analyst development and reflection

My initial practical answers correctly classified the activity as benign and low severity, but described configuration changes rather than evidence and did not enumerate the specific gaps. My closure answer focused on improving my wording rather than technical closure checks. Feedback: name each configuration gap, distinguish archive visibility from collection failure, cite exact event and rule identifiers, and specify verification actions.

During the simulation I recognized suspicious encoded PowerShell, recommended escalation and isolation, and kept the incident open. I learned to avoid treating suspicious patterns, HTTPS, file transfers or absence of alerts as conclusive evidence of compromise or safety.

My own takeaway: "Make sure that just because it's configured doesn't mean it's detected, gotta check everything."

This exercise reinforced end-to-end validation, evidence correlation, competing hypotheses, and the importance of precise incident communication. My next development focus is SOC incident reporting and escalation.

## Evidence

Screenshots were captured during the exercise, including policy verification, Windows record 622, raw archive record 627, rule 91843 configuration, dashboard hit and expanded record 632. Screenshot upload is pending; no unverified image links are included.
