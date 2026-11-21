# Lab 08 — Custom Wazuh Detection Rule Engineering

## Objective

Create, validate, deploy, and test a custom Wazuh SIEM detection rule for failed access attempts against a restricted Finance SMB share. Build on the generic Windows audit-failure alert investigated in [Lab 07](07-active-directory-rbac-file-share-monitoring.md), and distinguish rule syntax, event decoding, rule matching, and analyst interpretation.

All activity was performed in an authorized home-lab environment.

## Lab Environment

| Component | Configuration |
|---|---|
| Virtualization | VMware Workstation Pro |
| Wazuh Manager | Rocky Linux |
| Windows endpoint | Windows Server 2022 domain controller `AD-DC01` |
| Active Directory domain | `corp.example.test` |
| Wazuh agent | `004` |
| Windows Security event | `5145` — Detailed File Share |
| Existing Wazuh rule | `60104` — Windows audit failure event (level 5) |
| New custom Wazuh rule | `100100` — Restricted Finance share access denied (level 10) |

## 1. Investigation: Existing Wazuh Rule

Located built-in rule `60104`:

```bash
sudo grep -Rn -F '<rule id="60104"' /var/ossec/ruleset/rules/
sudo sed -n '50,70p' /var/ossec/ruleset/rules/0580-win-security_rules.xml
```

The rule matches Windows audit failures and depends on parent rule `60001`:

```xml
<rule id="60104" level="5">
  <if_sid>60001</if_sid>
  <field name="win.system.severityValue">^AUDIT_FAILURE$|^failure$</field>
  <description>Windows audit failure event</description>
  <options>no_full_log</options>
</rule>
```

**Finding:** Rule `60104` is a generic audit-failure alert, not a Finance-share-specific detection.

## 2. Custom Rule Configuration

Inspected the local custom rules file:

```bash
sudo ls -l /var/ossec/etc/rules/
sudo cat /var/ossec/etc/rules/local_rules.xml
```

The file contained Wazuh's default example SSH rule (`100001`). Created a backup before editing:

```bash
sudo cp -p /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Added the following rule inside the existing `<group>` element, preserving the example rule:

```xml
<!-- Lab 08: Restricted Finance Share Access Detection -->
<rule id="100100" level="10">
  <if_sid>60104</if_sid>
  <field name="win.system.eventID">^5145$</field>
  <field name="win.eventdata.shareName" type="pcre2">(?i)\\Finance$</field>
  <description>LAB08: Restricted Finance share access denied</description>
  <group>access_denied,windows,lab08,</group>
</rule>
```

The rule depends on the existing audit-failure rule and additionally matches Windows Event ID `5145` and a Finance share name. The `(?i)` expression makes the share-name comparison case-insensitive.

**Scope:** This rule matches Finance-share audit failures. It does not prove malicious intent or distinguish authorized testing from an actual intrusion. Level 10 was selected for this lab exercise; production severity should be tuned to the environment and alert volume.

## 3. Configuration Validation and XML Troubleshooting

Validated the XML:

```bash
sudo xmllint --noout /var/ossec/etc/rules/local_rules.xml
```

**Initial result:** `Extra content at the end of the document` at the custom rule.

**Root cause:** The new rule had been placed outside the closing `</group>` element.

**Correction:** Moved the custom rule inside the existing group and saved the file. Re-ran `xmllint` and received no errors.

Validated the Wazuh analysis engine:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

**Result:** No configuration errors were reported.

## 4. Simulated Event Test and Decoder Investigation

Started the built-in test utility:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Submitted a simulated JSON event with Event ID `5145`, `AUDIT_FAILURE`, and the Finance share.

**Observed result:**
- Phase 2 decoded the event as `json` and extracted the expected fields.
- Phase 3 matched generic rule `1002` (level 2), **not** custom rule `100100`.

Investigated the built-in Windows rule chain:

```bash
sudo grep -Rn -A 12 -F '<rule id="60001"' /var/ossec/ruleset/rules/
sudo grep -Rn -A 10 -F '<rule id="60000"' /var/ossec/ruleset/rules/
```

The chain was:

```text
60000 (Windows Event Channel decoder)
  -> 60001 (Windows Security channel)
    -> 60104 (Windows audit failure)
      -> 100100 (Event 5145 and Finance share)
```

Rule `60000` requires:

```xml
<decoded_as>windows_eventchannel</decoded_as>
```

**Root cause of the simulated-test mismatch:** The manually submitted event was decoded as `json`, not `windows_eventchannel`, so it did not satisfy the parent rule chain. This was a test-format limitation, not evidence that the deployed custom rule was invalid.

Also checked the archive directory and searched for Event 5145:

```bash
sudo ls -lh /var/ossec/logs/archives/
sudo grep -m 1 '"eventID":"5145"' /var/ossec/logs/archives/archives.json
```

The archive search returned no matching Event 5145. A separate alert search confirmed previously processed Windows events used the `windows_eventchannel` decoder, but an alert record is not necessarily suitable as original input to `wazuh-logtest`.

## 5. Deployment

Restarted the Wazuh manager after validation:

```bash
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

**Result:** `active`.

## 6. Live Access-Denied Test

On `AD-DC01`, opened a network-authenticated command prompt using the HR test account:

```cmd
runas /netonly /user:CORP\anna cmd
```

From the new command prompt, attempted to list the restricted Finance share:

```cmd
dir \\AD-DC01\Finance
```

**Observed Windows result:** `Access is denied.`

The `/netonly` option supplies Anna's credentials for network access without changing the local interactive identity; the event fields were used to verify the account involved.

## 7. Successful Wazuh Detection

In **Wazuh Threat Hunting**, filtered for:

```text
rule.id: 100100
```

The dashboard returned **one matching alert** from the controlled test.

| Field | Verified result |
|---|---|
| Agent | `AD-DC01` |
| Agent ID | `004` |
| Custom rule | `100100` |
| Alert level | `10` |
| Description | `LAB08: Restricted Finance share access denied` |
| Windows Event ID | `5145` |
| Windows audit result | `AUDIT_FAILURE` |
| Subject | `CORP\anna` |
| Share | `\\*\Finance` |
| Share path | `C:\DepartmentShares\Finance` |
| Access mask | `0x100080` |

**Validation outcome:** The real Windows Event Channel event satisfied the parent rule chain and triggered the custom rule as intended.

## 8. Analyst Assessment

**Finding:** The HR test account `CORP\anna` attempted to access the restricted Finance share.

**Access-control outcome:** Windows denied access, consistent with the least-privilege permissions established in Lab 07.

**Detection outcome:** Wazuh produced the intended custom level 10 alert, improving the specificity of the generic audit-failure classification.

**Disposition:** Authorized home-lab test; not a real security incident.

**Production consideration:** Investigate user context, access frequency, authentication history, business need, and other correlated events before escalating. A custom alert description and severity alone do not establish malicious activity.

## 9. Lessons Learned

1. Inspect existing SIEM rules and their parent dependencies before writing custom detections.
2. Back up configurations and validate both XML structure and the Wazuh analysis engine before deployment.
3. Correctly decoded fields do not guarantee a rule will fire; parent rules and decoder identity matter.
4. A simulated JSON test may not reproduce the Windows Event Channel decoder pipeline.
5. A live, authorized test is useful for validating the end-to-end detection path.
6. Document unsuccessful tests and root-cause findings, not just successful alerts.
7. A detection is a signal for investigation, not proof of an attack.

## 10. Evidence Screenshots

Evidence captured during the lab (to be uploaded into the [Lab 08 evidence folder](08-evidence/)):

| Planned file | Evidence |
|---|---|
| `01-custom-rule-configuration.png` | `local_rules.xml` showing rule `100100`, parent rule, Event 5145 and Finance share matching |
| `02-custom-alert.png` | Wazuh Threat Hunting showing rule `100100`, level 10, description and `AD-DC01` |
| `03-alert-event-details.png` | Expanded event showing `CORP\anna`, Finance share, Event 5145 and `AUDIT_FAILURE` |

Image embeds can be added once the files are uploaded, to avoid broken image links.

## Conclusion

Created and deployed a custom Wazuh detection rule to identify Windows audit failures involving a restricted Finance SMB share. Diagnosed an XML placement error and a simulated-event decoder mismatch, then verified the rule through a controlled live access-denied test. Wazuh generated the expected **rule 100100, level 10** alert with the relevant account, share and event fields.

**Skills practiced:** Wazuh custom rules, XML validation, rule inheritance, decoder troubleshooting, Windows Event 5145, SMB access monitoring, live detection validation, alert triage, root-cause analysis, and evidence-based documentation.

---

*All activity was performed in an authorized home-lab environment for cybersecurity learning and portfolio development.*
