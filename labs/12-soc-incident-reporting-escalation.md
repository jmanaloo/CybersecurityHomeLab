# Lab 12 — SOC Incident Reporting, Ticketing and Escalation

**Date:** November 27–28, 2026 (PHT)  
**Exercise:** Guided fictional SOC incident INC-0012; L1 analyst roleplay with AI coaching. No live SIEM investigation, malware execution, ticketing platform or actual containment was performed.

## Employer-facing summary

Following the technical troubleshooting in Lab 11, I deliberately practiced a development area: communicating evidence and handing investigations over to another analyst. My professional RTA experience in monitoring, escalation and RCA provides a foundation for this work.

**Demonstrated improvement:** My initial alert summary omitted user context and the reason for suspicion. After feedback, I produced a more complete evidence timeline and a structured L2 escalation ticket distinguishing confirmed compromise, suspected activity, completed containment and pending actions. The escalation checkpoint scored 89/100 versus 60/100 for my initial summary under informal, AI-generated coaching rubrics. These are different tasks, not standardized or independently validated measures of job readiness.

## Scenario and evidence timeline

All evidence below was supplied by the fictional exercise, not collected from my own systems. Parent-process context was supplied as correlated telemetry, not inferred from Event 4104 alone.

| Time (PHT) | Simulated evidence |
|---|---|
| 23:58:12 | Wazuh alert, Event 4104, FIN-PC03, CORP\\Mark; Excel spawns PowerShell with an encoded command |
| 23:58:13 | Decoded content: Get-LocalUser and Get-NetIPConfiguration |
| 23:58:19 | Outbound HTTPS connection to 198.51.100.27:443 (documentation address) |
| 23:58:21 | finance_update.ps1 created in user temporary directory |
| 23:58:24 | New PowerShell process executes the script |
| 23:58:30 | Unauthorized scheduled task created to execute script at logon |
| 00:02:15 (next day) | Mark confirms opening an Excel attachment, denies intentional PowerShell execution |

No approved maintenance was scheduled. Destination reputation, script contents and execution were initially unknown; execution was later confirmed. L2 ultimately confirmed phishing delivery and malicious remote command execution. Data exfiltration, credential theft and lateral movement were not evidenced after investigation.

## Checkpoint 1 — Initial alert reporting (60/100)

### My original response

> A suspicious powershell activity occured at 23:58 PHT. Endpoint was FIN-PC03 and it was captured by Wazuh SIEM, with the event ID 4104. Parent process was Excel.exe and the process was powershell.exe. Investigation is ongoing

**Feedback:** Accurate basic facts and no premature malicious classification. Missing user context, encoded command, why the process relationship is suspicious and what remains unknown.

**Coached revision:** Wazuh detected suspicious PowerShell activity at 23:58:12 PHT on FIN-PC03 under CORP\\Mark (Event 4104). Associated process telemetry showed EXCEL.EXE spawning powershell.exe with an encoded command. This unusual process relationship warrants investigation; encoded content and intent remain unverified.

## Checkpoint 2 — Evidence and timeline (85/100)

### My original response

> At 23:58:12, it was discovered that excel.exe spawned the powershell.exe that was an encoded command in the parent process. Upon further investigation, decoded content from powershell.exe shows the commands for Get-LocalUser and Get-NetIPConfiguration, which is highly suspicious in itself due to no IT maintenance was approved. At 23:58:19, Powershell established an outbound connection to 198.51.100.27 via port 443 and a file named finance_update.ps1 was created inside the user's temporary directory, and the external destination of the IP is unknown. While the contents and execution of the file has not been confirmed, Endpoint remains online, and investigation is ongoing.

**Improvement:** I incorporated chronology, command details, network and file evidence, limitations and endpoint status. I also independently noticed that I had omitted Mark from the first report, although I did not include him in this second response either.

**Feedback:** The encoded command belonged to PowerShell, not Excel. Discovery commands are legitimate in isolation; context raises suspicion. The IP was known but its reputation was not. Include the file creation timestamp.

**Coached revision:** On FIN-PC03 under CORP\\Mark, Excel spawned encoded PowerShell at 23:58:12 PHT. Decoded content revealed local account and network discovery commands; the process relationship and lack of scheduled maintenance warrant investigation. At 23:58:19 PowerShell connected to 198.51.100.27:443 over HTTPS; finance_update.ps1 was created at 23:58:21. Destination reputation, script contents and execution remain unverified; endpoint remains online.

## Checkpoint 3 — Severity justification (63/100)

### My original response

> 1. Phishing email that has an embedded file that executes code to steal information.
> 2. Medium, as persistence and suspected phishing as well as potential data exfiltration will occur.
> 3. As long as this issue is contained and escalated to our SOC team and acted upon quickly, isolation of the PC infected may help reduce the damage. However, further investigation is needed if the email sent affected other users. Otherwise, an increase in severity is warranted
> 4. Containment, investigation of infected computer/email and complete sweep to see if the program sent it to other users.

**Strength:** Recommended isolation, escalation and broader email investigation.

**Correction:** Information theft was not established. High severity was justified under the exercise matrix by unauthorized execution and scheduled-task persistence, even without confirmed exfiltration. Anticipated containment does not establish lower severity.

**Coached revision:** Suspected phishing-related unauthorized PowerShell execution with confirmed persistence mechanism; High. Escalate to L2, recommend authorized isolation, preserve evidence, investigate email and script, and hunt for related activity. Exfiltration, credential theft and lateral movement remain unconfirmed.

## Checkpoint 4 — L2 escalation (89/100)

### My original response

> - **Incident ID and severity: INC-0012 High**
> - **Incident summary: Suspected phishing-related unauthorized Powershell execution with confirmed persistence mechanism**
> - **Confirmed findings: 8 finance employees were affected and 3 of them opened the attachment**
> - **Affected scope: 8 Finance employees, 3 computers (1 with execution and persistence, 1 having suspicious PowerShell Activity, 1 pc with attachment opened, but no related execution detected)**
> - **Actions taken: FIN-PC03 Isolated, FIN-PC05 isolation and email quarantine is pending.**
> - **Recommended next steps: Continue isolation of PC05 and quarantine of affected emails as well continuous investigation on PC08**
> - **Outstanding investigation: Escalation to L2 for further containment and prevention of possible Data Exfilitration (still unconfirmed, investigation warranted)**

**Demonstrated improvement:** Applied High severity correction, avoided claiming exfiltration, separated completed isolation from pending actions, and distinguished three endpoint evidence states. This was my strongest checkpoint.

**Feedback:** Recipients are not necessarily compromised; include hostnames, evidence preservation, remaining recipients, credential theft, lateral movement and script analysis.

### Coached L2 handover — work sample

**INC-0012 | High | Open — partially contained | L1 to L2**

**Summary:** Suspected phishing-related unauthorized PowerShell execution with scheduled-task persistence on FIN-PC03.

**Confirmed findings and scope:** Eight Finance employees received the email; three opened the attachment. FIN-PC03 has confirmed unauthorized execution and persistence; FIN-PC05 has matching suspicious activity requiring validation; FIN-PC08 opened the attachment but has no related execution detected. Five remaining recipients have no related detections so far.

**Completed:** FIN-PC03 isolated.

**Pending:** FIN-PC05 isolation and email quarantine.

**Recommendations:** Complete authorized isolation, quarantine messages across recipient mailboxes, preserve endpoint/network/email evidence and investigate FIN-PC08 and remaining recipients. Determine script functionality, assess exfiltration, credential theft and lateral movement, and verify containment before eradication and recovery.

## Checkpoint 5 — Final disposition (79/100)

### My original response

> 1. Phishing with confirmed Persistence Mechanism
> 2. Medium, threat has been contained for now, pending eradication and recovery.
> 3. 2 confirmed compromise endponts, 6 endpoints has no evidence of compromise after investigation. A total of 8 recipients, 3 attachment openings
> 4. Partially open pending completion of eradication adn recovery
> 5. Conduct seminars/webinars on Phishing Prevention and preventive measures of emails that may be suspicious as well as specifically classify emails with links/programs attached.

**Strength:** Correct recipient/opening/compromised endpoint counts, recognized containment was insufficient for closure, and recommended awareness training.

**Remaining development:** I again reduced severity based on containment. Under this exercise matrix, High remains justified. Do not assume one endpoint per recipient. Use Open — contained, pending eradication and recovery, rather than partially open.

### Coached final disposition

Confirmed phishing-delivered malware with remote command execution and scheduled-task persistence. High severity. Eight recipients, three attachment openings, two confirmed compromised endpoints (FIN-PC03 and FIN-PC05). No evidence of compromise on FIN-PC08 or among remaining investigated recipients and associated endpoints; no evidence of exfiltration, credential theft or lateral movement identified.

Both compromised endpoints isolated, malicious emails quarantined and external destination blocked in the simulation. Incident remains open pending eradication, recovery, validation and authorized closure. Recommend awareness training, attachment sandboxing, URL filtering, Office child-process restrictions and scheduled-task monitoring.

## Learning progression

| Checkpoint | Informal coaching score | Development |
|---|---:|---|
| Initial alert summary | 60/100 | Accurate basic facts; missing context |
| Evidence timeline | 85/100 | More complete evidence and limitations |
| Severity justification | 63/100 | Strong response instincts; severity and assumptions need work |
| L2 escalation | 89/100 | Structured handover; completed versus pending actions |
| Final disposition | 79/100 | Accurate scope and closure reasoning; severity reassessment needs practice |
| Mean | 75.2/100 | Continued development, not a certification result |

Scores are subjective AI coaching assessments recorded during the exercise. The original responses above preserve my wording (question prompts omitted); coached revisions are assisted examples, not independent work. Progress was not linear and severity remains a priority.

## Next development priorities

- Apply the organization's severity matrix consistently; distinguish severity from containment status.
- Include actor, endpoint, timestamp, evidence, uncertainty and why the activity matters.
- Preserve evidence and communicate explicit ownership and pending actions.
- Practice an independent mock SOC shift and incident handover without immediate coaching.

**Key lesson:** Assess severity from evidence and policy, manage risk through containment, and close only after verified remediation and recovery.
