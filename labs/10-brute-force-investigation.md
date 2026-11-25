# Lab 10 — Brute-Force Attack Investigation

**Date:** November 25, 2026  
**Environment:** Authorized home lab (Wazuh, Rocky Linux, VMware Workstation, Windows Server 2022 / AD-DC01).  
**Objective:** Correlate authentication events, evaluate competing hypotheses, assess impact, recommend containment and document evidence-based dispositions.

## Part A — Simulated SOC incident (INC-0010)

This tabletop exercise used fictional telemetry, not actual attacks or home-lab detections.

| Time | Simulated finding |
| --- | --- |
| 01:01–01:03 | 48 failed Administrator network logons (4625), HR-PC01 / 192.168.100.55 |
| 01:03:52 | Successful logon (4624) |
| 01:03:53 | Special privileges assigned (4672) |
| 01:05:12 | svc_backup02 created (4720) |
| 01:05:36 | Account added to Domain Admins (4728) |
| 01:07:14 | New account authenticated to FILE-SRV01 |
| 01:08:23 | Finance share access check (5145) |
| Later | File reads (4663), 850 MB outbound versus normal upper range of 50 MB |
| Final evidence | Session correlation, administrator denial, EDR file collection, completed unauthorized DLP upload and matching archive hash |

### Simulated incident report

**Disposition:** Confirmed privileged-account compromise and data exfiltration in the exercise. **Severity:** Critical (proposed P1). **Status:** Escalation and containment recommended, not executed.

Scope: HR-PC01, AD-DC01, FILE-SRV01, Administrator, svc_backup02 and confidential Finance data. The authentication pattern suggests password guessing; the initial endpoint compromise, credential acquisition method and responsible individual remain unknown.

Recommended authorized actions: promptly notify the lead and incident response team, preserve evidence, isolate HR-PC01, block relevant malicious network destinations, disable the newly created account and revoke privileged membership, coordinate Administrator credential remediation and session revocation, and investigate wider domain exposure. Do not delete evidence-bearing accounts prematurely. IP blocking alone is insufficient.

Candidate MITRE ATT&CK mappings: T1110 Brute Force, T1078 Valid Accounts, T1136.002 Domain Account Creation, T1098 Account Manipulation and T1036 Masquerading. These describe suspected behavior, not independently verified intent.

## Part B — Actual Wazuh investigation (INC-0010-P)

### 1. Authentication failures

Threat Hunting → Events, Last 7 days (November 18–25 dashboard time).

```text
agent.name: "AD-DC01" AND data.win.system.eventID: "4625"
```

11 hits: ten on November 21 and one on November 23. Rule 60122, level 5. The latest failure was at approximately 23:32:00 on November 23.

### 2. Successful authentication correlation

```text
agent.name: "AD-DC01" AND data.win.system.eventID: "4624" AND data.win.eventdata.targetUserName: "Administrator"
```

23 hits across seven days. The latest successful logon was at approximately 23:32:05, rule 60118, level 3.

| Field | Failed | Successful |
| --- | --- | --- |
| Target account | Administrator | Administrator |
| Domain | CORP | CORP |
| Source IP | 127.0.0.1 | 127.0.0.1 |
| Workstation | AD-DC01 | AD-DC01 |
| Logon type | 2 (interactive) | 2 (interactive) |
| Logon process | User32 | User32 |
| Process | svchost.exe | svchost.exe |
| Process ID | 0x4b8 | 0x4b8 |
| Authentication package | Negotiate | Negotiate |
| Failure status/substatus | 0xC000006D / 0xC000006A (incorrect password) | Not applicable |

Matching context and approximately five seconds between events support a related local password retry, but do not identify the human actor.

### 3. Post-authentication review

```text
agent.name: "AD-DC01" AND (data.win.system.eventID: "4720" OR data.win.system.eventID: "4728" OR data.win.system.eventID: "4732")
```

Ten visible alerts, all dated November 19 or 21, before the November 23 logon. Rules 60109 (level 8) and 60141 (level 5). An expanded 4728 event showed Administrator adding Mark Santos to Finance-staff, consistent with earlier IAM exercises. No subsequent account creation or group additions were visible in the selected results. Dashboard timestamps are used for the timeline; raw event system time may differ.

### Practical incident report

**Classification:** Likely benign authentication failure (true positive for failed authentication). **Severity:** Low, preliminary. **Status:** Pending account-owner verification.

The observed evidence supports an incorrect local interactive password attempt followed by a successful retry. No evidence of malicious brute force or subsequent account modification was identified within the selected alerts. Confirm activity with the account owner, review further relevant telemetry if needed, continue monitoring and close as benign only after verification. Reinforce password policy without assuming a violation.

Limitations: actor identity, intent, password compliance, complete event collection and wider post-logon activity were not established. Data compromise cannot be ruled out by these queries. No real exfiltration or malicious account creation was demonstrated.

## Troubleshooting — VMware connectivity

VMware initially reported all pipe instances busy. The VM startup issue resolved during authorization-service troubleshooting. Later the Wazuh dashboard timed out despite an active manager. Linux `ip a` showed ens160 administratively up but NO-CARRIER and no IPv4 address. VMware adapter settings showed Connected, Connect at power on and NAT; reconnecting did not resolve the issue. Host VMnet8 was enabled, with NAT and DHCP configured on 192.168.17.0. NAT/DHCP service status was investigated and starting services was recommended; dashboard access subsequently returned. Exact underlying cause and individual corrective action were not independently verified. No network reset or reinstall was required.

## Analyst Development & Lessons Learned

| Initial reasoning | Refined approach |
| --- | --- |
| High frequency proves brute force | Consider automated legitimate services, authorized testing and malicious guessing |
| Failures stopped because attacker gave up | Check successful logons, lockout and telemetry gaps |
| Source workstation identifies insider | Separate endpoint attribution from human identity |
| 4672 proves privilege escalation | Correlate session IDs; existing privileges may explain event |
| Block IP immediately | Communicate layered endpoint and identity containment; preserve evidence |
| Large outbound transfer proves theft | Require evidence linking actual content to unauthorized completed transfer |
| Weak password caused compromise | Keep credential-policy hypotheses separate from verified root cause |
| No later account changes means no compromise | State query scope and verify with account owner |

My strengths in this exercise were connecting small clues, early escalation and proposing immediate mitigation while investigating. My development goals are to verbalize the full containment plan, actively test competing explanations and distinguish confirmed facts from hypotheses. In the practical exercise I explicitly acknowledged uncertainty about the actor and sought post-authentication evidence before disposition.

Informal coaching assessments: simulated exercise 84/100 (revised after clarifying intended endpoint isolation); practical exercise 88/100. These are subjective feedback from different exercises, not standardized scores or certifications.

**Key lesson:** Suspicion warrants investigation; risk warrants escalation; evidence warrants conclusions.

## Evidence inventory

Screenshots captured during the practical exercise: 4625 search results, expanded failed event, 4624 search results, expanded successful event, account-management search results and expanded 4728 event. Binary screenshot upload remains pending; no image links are claimed until files are uploaded.
