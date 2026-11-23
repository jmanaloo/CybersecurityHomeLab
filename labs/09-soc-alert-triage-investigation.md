# Lab 09 — SOC Alert Triage and Windows Authentication Investigation

## Objective

Practice an entry-level SOC analyst workflow: identify an authentication alert, investigate relevant Windows Security events in Wazuh, correlate failed and successful logons, evaluate competing explanations, and write an evidence-based disposition and escalation recommendation.

This is a **guided, authorized home-lab investigation**. The authentication events were observed in Wazuh. The administrator's later confirmation and denial were **alternative hypothetical interview scenarios**, not real-world verification.

## Environment

| Component | Details |
| --- | --- |
| Virtualization | VMware Workstation Pro |
| SIEM | Wazuh Threat Hunting / Events |
| Endpoint | Windows Server 2022 domain controller `AD-DC01` |
| Domain | `corp.example.test` |
| Account investigated | `CORP\Administrator` |
| Event IDs | `4625` (failed logon), `4624` (successful logon) |
| Investigation date | November 23, 2026 |
| Historical event date | November 21, 2026 |

## 1. Initial alert and triage decision

**Scenario:** Multiple failed authentication events were reported from the domain controller. Before taking action, the analyst chose to identify the targeted account, source, and timestamps, and determine whether any attempts succeeded.

**Reasoning:** Investigate frequency and timing, establish the source where possible, assess account risk, and avoid prematurely blocking or escalating without understanding the evidence.

## 2. Failed authentication search

In Wazuh Threat Hunting → Events, set the time range to **Last 7 days** and searched:

```text
agent.name: "AD-DC01" AND data.win.system.eventID: "4625"
```

**Observed result:** **10 hits**, clustered on November 21, 2026, around 01:05 in the dashboard's displayed time zone.

| Field | Observed value |
| --- | --- |
| Endpoint | `AD-DC01` |
| Windows Event ID | `4625` |
| Wazuh rule ID | `60122` |
| Wazuh alert level | `5` |
| Description | Logon Failure - Unknown user or bad password |
| Target account | `Administrator` |
| Target domain | `CORP` |
| Logon type | `2` — interactive |
| Status | `0xC000006D` — logon failure |
| Substatus | `0xC000006A` — incorrect password |
| Reported workstation | `AD-DC01` |
| Process | `C:\Windows\System32\svchost.exe` |

**Analyst interpretation:** Repeated incorrect-password attempts against a privileged account warrant investigation. Event 4625 alone does not prove account compromise or attacker intent. The screenshot inspected did not establish a remote source IP for the failed attempt.

## 3. Correlation with successful logons

To check whether the account logged on successfully, searched:

```text
agent.name: "AD-DC01" AND data.win.system.eventID: "4624" AND data.win.eventdata.targetUserName: "Administrator"
```

**Observed result:** **23 hits across the selected seven-day range**. The table displayed **15 rows per page**, not 15 total hits. Several successful events were visible around 01:05:47–01:05:55 on November 21, after the cluster of failed events around 01:05:21–01:05:40.

**Important limitation:** A successful Event 4624 near a failed Event 4625 is a correlation lead, not proof that the same actor successfully authenticated. The Wazuh alerts view may also omit events that were not indexed as alerts.

## 4. Expanded successful-logon evidence

Inspected one of the successful events near 01:05:55.

| Field | Observed value |
| --- | --- |
| Windows Event ID | `4624` |
| Account | `Administrator` |
| Domain | `CORP` |
| Logon type | `7` — workstation unlock |
| IP address | `127.0.0.1` — loopback |
| Workstation | `AD-DC01` |
| Logon process | `User32` |
| Authentication package | `Negotiate` |
| Process | `C:\Windows\System32\svchost.exe` |
| Logon ID | `0x5d26bb` |

**Interpretation:** This particular successful event represents a workstation unlock, not necessarily a new remote interactive session. The loopback address does not identify an external attacker. The evidence is consistent with a legitimate user mistyping a password before unlocking a session, but it does not independently establish who was at the console.

## 5. Analyst reasoning and incident classification

The analyst prioritized the account, source, timeline, related successful logons, and any unusual actions after authentication.

A useful distinction emerged:

- **Detection validity:** The failed authentication events genuinely occurred and Wazuh detected them.
- **Threat determination:** Whether the activity was malicious requires additional evidence and context.
- **Benign true positive:** Under one common SOC taxonomy, a valid detection of legitimate but unusual activity can be closed as a benign true positive. Organizations may define their alert-disposition labels differently.

### Scenario A — Administrator confirms legitimate activity (hypothetical)

**Scenario-only information:** An authorized administrator states that they repeatedly mistyped their password and then unlocked the server; no other suspicious activity was identified.

**Proposed disposition:** Benign true positive, provided the identity and explanation are appropriately verified.

**Proposed action:** Document the events and verification, close according to the team's playbook, and recommend approved credential-management practices if login difficulties recur.

**Crucial caveat:** The administrator confirmation was supplied as part of the guided exercise. It was **not obtained from a real administrator during this lab**.

### Scenario B — Administrator denies the activity (hypothetical)

**Scenario-only information:** The administrator states they were asleep and did not access the server at the relevant time.

**Revised disposition:** Suspicious activity; investigation ongoing, **not confirmed compromise**.

**Proposed action:** Promptly notify the SOC lead / escalate under the organization's privileged-account incident procedures. Preserve evidence; investigate source and session context, other authentication activity, account changes, process execution, and related endpoint events. Any containment should be authorized and follow the incident-response playbook.

**Key decision:** New evidence that contradicts the benign hypothesis must change the assessment. An analyst should not delay urgent escalation of a potentially compromised privileged account while attempting to investigate every possible trail.

## 6. Sample SOC ticket (conditional training scenario)

**Title:** Multiple failed Administrator authentication attempts on AD-DC01

**Detection:** 10 Windows Event 4625 alerts; Wazuh rule 60122 (level 5).

**Evidence:** Incorrect-password substatus `0xC000006A`, interactive logon type 2, and nearby Event 4624 success with unlock type 7 and loopback address.

**Assessment from logs alone:** Repeated failed privileged-account authentication with a temporally related workstation unlock. Actor identity and malicious intent **not established**.

**Disposition:** **Pending verification** based on observed evidence alone. If Scenario A is independently verified, a benign true positive disposition may be appropriate; if Scenario B occurs, escalate as suspicious.

**Next steps:** Confirm authorized usage, correlate additional relevant events, preserve timestamps and event details, and follow the SOC playbook.

## 7. Evidence screenshots — pending upload

Screenshots were reviewed during the guided session but have **not yet been committed to this repository**:

1. Wazuh failed-login search showing 10 Event 4625 hits.
2. Expanded failed event showing `Administrator`, logon type 2, and incorrect-password substatus.
3. Wazuh successful-login search showing 23 Event 4624 hits.
4. Expanded successful event showing logon type 7, `127.0.0.1`, and `User32`.

Once uploaded, the screenshots can be embedded here with captions. No screenshot files are claimed to be present yet.

## 8. Lessons learned

1. Investigate privileged-account authentication anomalies without assuming an attack.
2. Check the **total hit count**, not merely the number of visible rows per page.
3. Use Windows logon types to interpret authentication context: type 2 is interactive, type 7 is unlock.
4. Correlation in time does not establish a shared actor or confirmed compromise.
5. Distinguish observed telemetry from hypothetical statements and verified human confirmation.
6. Update an incident disposition when contradictory evidence appears.
7. Escalate possible privileged-account compromise promptly under organizational procedures.
8. Clear documentation should state the evidence, interpretation, uncertainty, and next actions.

## Conclusion

Completed a guided SOC L1 investigation using real Wazuh authentication alerts from an authorized Windows Server home lab. Located 10 failed Administrator logons, correlated them with 23 successful-logon search results, examined a workstation-unlock event, and practiced conditional benign and suspicious incident dispositions. The exercise reinforced evidence-based triage, careful interpretation of Windows Event IDs, and escalation judgment.

---

*Authorized home-lab activity. Scenario-based administrator statements were hypothetical; no production SOC incident or independently confirmed account compromise is claimed.*
