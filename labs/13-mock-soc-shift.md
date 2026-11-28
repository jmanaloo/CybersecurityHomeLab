# Lab 13 — Mock SOC Shift and Independent Incident Investigation

**Date:** November 28, 2026 (PHT)  
**Environment:** Fictional enterprise SOC, guided by AI acting as SOC lead. No live systems, SIEM queries, malware execution or containment actions were performed.

## Employer-facing summary

Building on Lab 12, I practiced managing four concurrent alerts, revising priorities as evidence changed, correlating privileged account compromise with ransomware, and handing over an open major incident.

**Observable improvement:** In Lab 12 I reduced incident severity because containment had succeeded. In this exercise I independently prioritized an active suspected ransomware incident over an already partially contained High-severity incident without lowering the latter's severity. I also independently linked two alerts using a shared source endpoint and unauthorized account, and recommended validating containment before recovery.

My professional RTA background in monitoring, prioritization, escalation and RCA is directly relevant to these exercises. This is a simulated work sample, not production SOC experience.

## Alert queue and investigation evidence

| Alert | Initial rating | Asset | Evidence and final disposition |
|---|---|---|---|
| ALT-1301 | High | AD-DC01 | 36 failed Administrator network logons followed by success four seconds later, source FIN-PC04 (192.168.17.85). Owner denied activity; unauthorized account svc_maintenance created (4720) and added to Domain Admins (4728). Escalated and correlated with ALT-1304. |
| ALT-1302 | Medium | HR-PC07 | Word spawned encoded PowerShell; decoded Get-ComputerInfo. Anna and IT verified authorized diagnostics, valid change ticket and matching approved script hash. Closed benign, Low. |
| ALT-1303 | Low | FILE-SRV01 | One denied Finance folder access by CORP\\Anna (5145), no successful access detected. User confirmed accidental selection; closed benign, Low. |
| ALT-1304 | High | FILE-SRV01 | 487 modifications in 60 seconds, unfamiliar extensions; later 1,842 files affected, encryption and ransom note confirmed. Remote SMB source FIN-PC04, account CORP\\svc_maintenance. Finance and HR shares inaccessible. Correlated with ALT-1301; major incident Critical under exercise criteria. |

All evidence was supplied by the simulation. Event 4104 was accompanied by separate process telemetry. The SMB session was established before FIN-PC04 isolation; the precise encryption onset relative to isolation was not independently established.

## Checkpoint 1 — Prioritization

**My response:** Medium first, High second, Low last. I reasoned that encoded PowerShell could affect other priorities and that authentication and denied access might be user errors. I also proposed investigating Medium and High concurrently.

**Strength:** Did not blindly follow SIEM ratings; recognized suspicious process activity and low urgency of denied access.

**Feedback:** Domain controller criticality and privileged account exposure justify prioritizing ALT-1301. Encoded commands are not inherently malicious; user error is unverified. Concurrent investigation is reasonable if capacity and procedures allow.

## Checkpoint 2 — Initial investigation

**My response (ALT-1301):** Privileged account compromise, High; multiple failures and one success may indicate brute force. Verify administrator whereabouts and login difficulties; possible account lockup.

**My response (ALT-1302):** Potential malicious script execution, Medium; Word spawned PowerShell with Get-ComputerInfo. Check approved maintenance, Anna's knowledge and document origin, possible phishing; investigate further.

**Strength:** Both severity ratings matched the exercise criteria. Independently sought user verification and document provenance.

**Feedback:** Use suspected compromise until evidence establishes it; investigate source workstation and post-login account changes. Coordinate account restrictions with IAM. Get-ComputerInfo is legitimate in isolation; investigate process context rather than assuming an embedded script.

## Checkpoint 3 — Disposition

**My response:** ALT-1301 possible AD compromise, High, contain/isolate and escalate. ALT-1302 possible phishing, Low, close because IT authorized diagnostics. ALT-1303 restricted file access, Low, contact Anna and close based on likely accidental selection.

**Strength:** Maintained High for unauthorized account activity and lowered severity for verified legitimate diagnostics, not merely because of containment.

**Feedback:** Unauthorized account creation and Domain Admin membership establish unauthorized privileged activity. ALT-1302 should be classified benign authorized diagnostics, not phishing. ALT-1303 should remain open pending user verification under this exercise's closure criteria.

## Checkpoint 4 — Prioritization under pressure

**My original response (question prompts omitted):**

> Close since user confirmed misclick. Send reminder to agent to refrain from checking restricted folders
>
> Possible Ransomware and its classification is high
>
> 1304, as 1301 has been contained but still under investigation pending any changes on compromised accounts.
>
> Contain and inform my lead for escalation to L2
>
> Check the rootcause of the ransomware for 1304 and who opened a file that contained it or check the user who introduced/opened the file into the system

**Demonstrated improvement:** Distinguished severity from urgency. Correctly closed ALT-1303 after verification and prioritized the rapidly developing ransomware alert while retaining the existing incident's High severity.

**Feedback:** Specify authorized isolation, infrastructure coordination and evidence preservation. Do not assume a file opening caused ransomware; investigate processes, accounts, SMB sessions and related alerts.

## Checkpoint 5 — Correlation and major incident

**My original response (question prompts omitted):**

> Yes. 1301 created a file named svc_maintenance awhile ago and while it was contained, it released the ransomware before FIN-PC04 was isolated
>
> Yes, as the source of it was FIN-PC04 with the user svc_maintenance as the source, but since it was isolated, it can be treated as the root cause
>
> AD Compromise from PC04 which resulted to ransomware attack
>
> High
>
> Confirm if Data Exfiltration was successful. Containment and eradication of ransomware as well as revisit isolation of PC04 if successful and no other files or virus were found to move around the network

**Strength:** Independently correlated the alerts and recommended one major incident, containment validation, exfiltration investigation and eradication before recovery.

**Feedback:** svc_maintenance is an account, not a file. FIN-PC04 is the source endpoint, not an established root cause. The initial attack vector remains unknown. Critical is justified under the exercise matrix by confirmed encryption and significant business disruption; exfiltration is not required. Verify backup integrity before recovery. The evidence establishes the SMB session began before isolation, not necessarily the exact onset of encryption.

## Checkpoint 6 — Shift handover

### My original response

> - **Shift summary:** 4 alerts were handles
> - **Closed alerts:** 2 alerts closed
> - **Active major incident and severity:** Major incident (1304) is critical
> - **Confirmed findings:** the AD incident and the ransomware issue are connected. 2 other incidents are an IT related maintenance and the other's a misclick of the file from HR to a finance folder
> - **Completed containment actions:** isolated pc04 but its better to still check.
> - **Pending actions:** Monitor Active Major incident
> - **Outstanding risks and investigation:** Issue with more files infected than previously thought MAY arise, however if contained then just coordinate with L2, and checking PC04 for complete isolation and checking
> - **Next shift priority:** Check the open major incident and investigate and coordinate with L2 if any help is needed still from us

**Strength:** Correct queue counts, Critical severity after feedback, ongoing incident ownership and containment validation.

**Feedback:** Include both alert IDs, specific evidence, both isolated hosts, account actions, verified backup status, unknown initial vector and explicit eradication/recovery status. Concise reports must still be actionable.

### Coached handover — employer-facing work sample

**Shift summary:** Four alerts handled; two closed benign; two correlated into one open Critical major incident.

**Closed:** ALT-1302 authorized IT PowerShell diagnostics (change ticket and script hash verified); ALT-1303 accidental restricted folder access (user verified, no successful unauthorized access detected).

**Major incident:** ALT-1301 + ALT-1304 — unauthorized privileged account activity and ransomware. FIN-PC04 originated the remote SMB session using unauthorized Domain Admin account CORP\\svc_maintenance. Encryption confirmed; 1,842 files affected; Finance and HR shares inaccessible.

**Completed containment:** FIN-PC04 and FILE-SRV01 isolated; svc_maintenance disabled; Administrator password reset by IAM. Backup integrity verified as a separate recovery-readiness check.

**Pending:** Eradication ongoing, recovery not started. Validate containment and coordinate authorized recovery with L2 and Incident Response.

**Outstanding:** Initial attack vector unknown. No additional compromised endpoints or evidence of exfiltration identified so far; continue scope validation.

**Next shift:** Prioritize the open Critical incident, monitor related alerts, coordinate with L2/IR and track eradication and recovery. Do not close until authorized closure criteria are met.

## Learning progression — Lab 12 to Lab 13

| Skill | Lab 12 | Lab 13 |
|---|---|---|
| Severity vs urgency | Reduced severity after containment | Independently reprioritized an active threat without downgrading existing incident |
| Evidence and uncertainty | Assumed information theft | Recommended investigating whether exfiltration occurred |
| Incident scope | Single incident, guided scope | Independently linked two alerts by account and endpoint |
| Queue management | Single incident | Managed four alerts with changing priorities |
| Containment | Focused on immediate isolation | Recommended validating isolation and broader scope before recovery |
| Reporting | Structured escalation after feedback | Correct handover decisions, but omitted several key facts |

## Qualitative coaching assessment

| Demonstrated independently in this exercise | Developing |
|---|---|
| Incident prioritization (after initial feedback) | Consistent severity calibration |
| Adapting to new evidence | Technical terminology |
| Incident correlation | Evidence gathering specificity |
| Escalation judgment | Handover completeness |
| Closure judgment (after verification feedback) | Recovery planning |
| Containment validation | |

Six competencies demonstrated independently at relevant checkpoints; five developing. These are subjective AI coaching observations, not standardized assessments or evidence of independent production readiness. Feedback was provided between checkpoints; the coached handover is an assisted example. Checkpoints 1–3 are summaries of my responses; checkpoints 4–6 preserve my answer wording with question prompts and formatting normalized.

## Next development priorities

Practice concise but complete handovers using alert IDs, affected assets, evidence, completed actions, pending actions, ownership and uncertainty. Apply severity matrices consistently, distinguish source from root cause, and verify backup integrity and containment before recovery.

**Key lesson:** Severity, urgency, containment and closure are distinct decisions. Correlate evidence across alerts and communicate enough detail for the next analyst to act.
