Lab 03 — Investigating a Failed Windows Login with Wazuh
Date: November 15, 2026
Environment: VMware Workstation Pro, Rocky Linux 9.5 Wazuh manager (192.168.17.130), Windows Server 2022 Wazuh agent (Win-serverlab, 192.168.17.134)
Status: Completed — alert detected and investigated
Objective
Simulate one authorized failed login on a Windows Server endpoint, verify the Windows Security event, find the matching event in Wazuh, and document the analyst's assessment.
Lab scope
This exercise was performed only on my own isolated Windows Server lab VM. No production accounts or systems were targeted.
Step 1 — Generate a failed authentication attempt
Open PowerShell inside the Windows Server 2022 VM and run:
runas /user:Administrator cmd
When prompted for the password, intentionally enter an incorrect password once.

Observed result:
RUNAS ERROR: Unable to run - cmd
1326: The user name or password is incorrect.
This confirmed that Windows rejected the attempted login.
Step 2 — Confirm the Windows event
1. Press Win + R, enter eventvwr.msc, and press Enter.
2. Open Windows Logs → Security.
3. Select Filter Current Log and enter 4625 under Event IDs.
4. Locate the event corresponding to the test time.
Observed: Windows Event Viewer showed Event ID 4625 (failed logon).
Step 3 — Find the event in Wazuh
1. Open the Wazuh dashboard: https://192.168.17.130.
2. Navigate to Threat Hunting → Events (navigation may vary by version).
3. Select a time range that includes the test, such as Last 15 minutes or Last 1 hour.
4. Search for:
data.win.system.eventID:4625
Observed: A matching event appeared in Wazuh.
Step 4 — Inspect the alert fields
The following values were verified in the Wazuh event details:
Field	Observed value
data.win.system.eventID	4625
rule.description	Logon Failure - Unknown user or bad password
rule.level	5
data.win.eventdata.targetUserName	Administrator
Wazuh agent	Win-serverlab


Interpretation: Wazuh collected the failed-authentication event and classified it with a level-5 rule. A single level-5 alert does not, by itself, establish an attack.
Analyst assessment
Finding: A failed login targeting the Administrator account was recorded on the Windows Server endpoint and detected in Wazuh.

Context: I deliberately supplied an incorrect password while running runas as part of this authorized lab test.

Disposition: Benign / expected test activity. No escalation required for this known test. In a real SOC, I would also review the source address, logon type, frequency of attempts, related events, and account history before deciding on escalation.
Skills practiced
- Generating a controlled authentication failure
- Finding Windows Security Event ID 4625 in Event Viewer
- Searching Wazuh Threat Hunting events by event ID
- Reading rule.description, rule.level, and targeted username
- Distinguishing a detected event from a confirmed security incident
- Writing a concise SOC investigation summary
Next lab
Configure File Integrity Monitoring (FIM) in the Windows agent's ossec.conf, safely test file creation/modification/deletion, and review resulting alerts. Back up the working configuration before making changes.
Security note: Do not publish real passwords, agent enrollment keys, or sensitive system information in screenshots or repository files.
