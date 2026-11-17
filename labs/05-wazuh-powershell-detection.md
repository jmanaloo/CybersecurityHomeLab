# Lab 05 — PowerShell Script Block Monitoring and Wazuh Detection Investigation

**Date:** November 17, 2026  
**Environment:** VMware Workstation Pro; Rocky Linux 9.5 / Wazuh 4.12.0 manager (`192.168.17.130`); Windows Server 2022 endpoint (`192.168.17.134`)  
**Status:** Completed — Windows Event ID 4104 collected, archived, and a built-in detection verified in Threat Hunting  
**Scope:** Authorized, isolated home-lab exercise. No malicious command or registry change was performed.

## Objective

Enable PowerShell Script Block Logging, collect the Windows PowerShell Operational channel with Wazuh, distinguish raw telemetry from generated alerts, examine built-in PowerShell detection rules, and validate a harmless pattern-matching alert end to end.

## Observed configuration and parameters

| Setting | Value / observation |
|---|---|
| Wazuh manager | `192.168.17.130` |
| Agent-to-manager communication | TCP `1514` |
| Agent shown in **this lab's archived events and alerts** | `003`, `Win-serverlab` |
| Windows event channel | `Microsoft-Windows-PowerShell/Operational` |
| Windows event ID | `4104` (script block logging) |
| Script Block Logging policy | `EnableScriptBlockLogging = 1` |
| PowerShell detection parent chain | `91801` → `91802` (both level 0) |
| Tested built-in detection | Rule `91843`, level `3` |
| Manager alert logging threshold | `<log_alert_level>3</log_alert_level>` |
| Temporary raw archive setting | `<logall_json>yes</logall_json>`, later restored to `no` |
| Final manager state | `active` |

> Agent ID `002` was used in the previous FIM lab; **agent `003`** was directly observed in Lab 05's event archive and alerts. Agent identity is verified per event rather than assumed from previous sessions.

## 1. Establish agent connectivity

At first, the Windows Wazuh agent service was running, but the agent log showed connection timeouts. The Linux Wazuh VM was powered off. After starting the VM and its manager service, the agent reconnected.

**Command: Check the Windows Wazuh agent service**

```powershell
Get-Service -Name WazuhSvc
```

*Purpose:* Confirms the Windows service is running. This alone does **not** prove connectivity to the manager.

**Command: Read recent Windows agent logs**

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 15
```

*Purpose:* Reviews connection attempts, startup messages, and errors.

**Command: Test TCP 1514 connectivity**

```powershell
Test-NetConnection 192.168.17.130 -Port 1514
```

*Purpose:* Tests reachability of the Wazuh manager's agent communication port. The initial test failed while the manager VM was off; after startup, `TcpTestSucceeded` was `True`.

**Command: Check and start the manager**

```bash
sudo systemctl status wazuh-manager
sudo systemctl start wazuh-manager
```

*Purpose:* Checks the Linux manager and starts it when needed. Windows agent logs subsequently showed connection to `192.168.17.130:1514/tcp` and `Agent is now online`.

## 2. Enable Windows PowerShell Script Block Logging

The Windows `Microsoft-Windows-PowerShell/Operational` log existed and was enabled, but an initial test marker did not appear in the expected 4104 results. The Group Policy setting had not been applied. After selecting **Apply**, refreshing policy, and opening a **fresh PowerShell session**, the test appeared.

**Command: Check whether the PowerShell Operational log is enabled**

```powershell
(Get-WinEvent -ListLog "Microsoft-Windows-PowerShell/Operational").IsEnabled
```

*Purpose:* Verifies that the Windows event channel itself is enabled.

**Policy:** In `gpedit.msc`, open **Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging**; set **Enabled**, click **Apply**.

**Command: Refresh computer policy**

```powershell
gpupdate /target:computer /force
```

*Purpose:* Requests an immediate computer policy refresh.

**Command: Confirm Script Block Logging policy**

```powershell
Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging
```

*Purpose:* Verifies that the effective registry policy value is `1`. Before clicking Apply, the expected policy registry path was absent.

**Command: Generate a fresh-session marker**

```powershell
Write-Output "SOC-LAB05-FRESH-SESSION"
```

*Purpose:* Generates an identifiable, harmless script block after reopening PowerShell. Event ID `4104`, Record ID `471` was confirmed for this marker.

**Command: Search for the specific script block**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 20 |
Where-Object {$_.Properties[2].Value -eq 'Write-Output "SOC-LAB05-FRESH-SESSION"'} |
Select-Object TimeCreated, Id, RecordId
```

*Purpose:* Matches the exact script text rather than assuming the newest event belongs to the test. Investigation commands can themselves create additional PowerShell events.

## 3. Configure the Wazuh agent to collect PowerShell events

The existing Windows agent configuration collected Application, Security, and System channels, but did not yet include the PowerShell Operational channel.

**Command: Inspect the agent's existing event collection entries**

```powershell
Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Pattern "<localfile>" -Context 0,4
```

*Purpose:* Shows the configured event sources before modifying the file.

**Command: Back up the Windows agent configuration**

```powershell
Copy-Item "C:\Program Files (x86)\ossec-agent\ossec.conf" "C:\Program Files (x86)\ossec-agent\ossec.conf.lab05.bak"
```

*Purpose:* Preserves the original configuration for recovery.

**Configuration added:** One new `<localfile>` block inside the existing `<ossec_config>`:

```xml
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

**Command: Verify the saved entry**

```powershell
Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Pattern "Microsoft-Windows-PowerShell/Operational" -Context 1,1
```

*Purpose:* Confirms the new event channel appears in the saved file.

**Command: Validate XML syntax**

```powershell
[xml]$config = Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf" -Raw
```

*Purpose:* Parses the XML and catches malformed syntax. This does not validate every Wazuh-specific setting.

**Command: Restart the agent**

```powershell
Restart-Service -Name WazuhSvc
```

*Purpose:* Loads the updated Windows agent configuration.

**Command: Verify agent startup and event-channel initialization**

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 30
```

*Purpose:* Checks that the agent initialized `Microsoft-Windows-PowerShell/Operational`, connected to TCP 1514, and reported online.

## 4. Separate collected events from generated alerts

**Command: Generate a harmless PowerShell event**

```powershell
Write-Output "SOC-LAB05-WAZUH-TEST"
```

*Purpose:* Creates a unique marker to trace through Windows logging and Wazuh.

**Command: Find its Windows Event ID 4104**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 30 |
Where-Object {$_.Message -like '*SOC-LAB05-WAZUH-TEST*'} |
Select-Object TimeCreated, Id, RecordId
```

*Purpose:* Confirms the Windows log recorded the script block. The test marker was found with **Record ID `498`**.

The dashboard searches `rule.id: 91802` and `win.system.eventID: 4104` returned no matching alerts. The initial view also had an agent filter; removing it still showed no matching alerts. **Absence of an alert was not evidence of absent collection.**

**Command: Inspect manager archive settings**

```bash
sudo grep -A 5 '<global>' /var/ossec/etc/ossec.conf
```

*Purpose:* Checks `logall` and `logall_json`; both were initially `no`.

For troubleshooting, `<logall_json>yes</logall_json>` was set temporarily in `/var/ossec/etc/ossec.conf`.

**Command: Verify archive setting**

```bash
sudo grep -n '<logall_json>' /var/ossec/etc/ossec.conf
```

*Purpose:* Confirms the temporary setting was saved before restarting.

**Command: Test manager analysis configuration**

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

*Purpose:* Checks that the analysis daemon accepts its configuration before restart.

**Command: Restart the manager**

```bash
sudo systemctl restart wazuh-manager
```

*Purpose:* Applies the temporary archive setting. Events not previously archived cannot be recovered by enabling it afterward.

**Command: Generate a new marker after enabling archives**

```powershell
Write-Output "SOC-LAB05-ARCHIVE-TEST"
```

*Purpose:* Produces fresh PowerShell telemetry while archiving is enabled.

**Command: Find the marker in raw archives**

```bash
sudo grep -F 'SOC-LAB05-ARCHIVE-TEST' /var/ossec/logs/archives/archives.json
```

*Purpose:* Searches collected events regardless of whether they triggered an alert.

**Verified archive evidence:** Agent `003` (`Win-serverlab`), Event ID `4104`, Event Record ID `508`, channel `Microsoft-Windows-PowerShell/Operational`, and script text `Write-Output "SOC-LAB05-ARCHIVE-TEST"`.

**Command: Check alerts for the same marker**

```bash
sudo grep -F 'SOC-LAB05-ARCHIVE-TEST' /var/ossec/logs/alerts/alerts.json
```

*Purpose:* Searches alert records. This initially matched a **Linux sudo alert** (rule `5402`) generated by the analyst's own `sudo grep` command, not the Windows test event.

**Command: Require both marker and PowerShell channel**

```bash
sudo grep -F 'SOC-LAB05-ARCHIVE-TEST' /var/ossec/logs/alerts/alerts.json | grep -F 'Microsoft-Windows-PowerShell/Operational'
```

*Purpose:* Excludes the unrelated Linux sudo match. No matching Windows PowerShell alert was found in the current alert log.

**SOC interpretation:** The manager received and archived the harmless PowerShell event, but the specific event was not found as an alert. A keyword match alone is not sufficient attribution.

## 5. Inspect built-in PowerShell detection rules

**Command: Check the configured alert threshold**

```bash
sudo grep -A 4 '<alerts>' /var/ossec/etc/ossec.conf
```

*Purpose:* Verifies `<log_alert_level>3</log_alert_level>`; this affects logged alerts, not collection.

**Command: Locate PowerShell-related rule files**

```bash
sudo grep -ril 'powershell' /var/ossec/ruleset/rules/ | head -20
```

*Purpose:* Finds built-in rules mentioning PowerShell. Located `0915-win-powershell_rules.xml` among other files.

**Command: Read PowerShell rules**

```bash
sudo cat /var/ossec/ruleset/rules/0915-win-powershell_rules.xml
```

*Purpose:* Inspects rule IDs, levels, descriptions, and match conditions without changing vendor rules.

**Command: Inspect the parent rule chain**

```bash
sudo grep -A 12 '<rule id="91802"' /var/ossec/ruleset/rules/0915-win-powershell_rules.xml
sudo grep -A 8 '<rule id="91801"' /var/ossec/ruleset/rules/0915-win-powershell_rules.xml
```

*Purpose:* Shows how rule `91801` identifies the PowerShell Operational channel, and rule `91802` (level `0`) groups script block events. More specific child rules can generate logged alerts when their conditions match.

## 6. Validate an existing detection safely

The built-in rule `91843` (level `3`) matches a PowerShell text pattern containing `New-ItemProperty -Path`. We tested the **pattern as a string**, without modifying any registry value.

**Command: Generate a harmless detection test**

```powershell
$Lab05Test = 'New-ItemProperty -Path'
```

*Purpose:* Includes the rule's pattern in a script block while only assigning a string to a variable.

**Command: Verify the Windows script block event**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 30 |
Where-Object {$_.Message -like '*New-ItemProperty -Path*'} |
Select-Object TimeCreated, Id, RecordId
```

*Purpose:* Finds matching Windows Event ID `4104`. The original test was found as **Record ID `510`**.

**Command: Search Wazuh alerts by rule ID**

```bash
sudo grep -F '"id":"91843"' /var/ossec/logs/alerts/alerts.json
```

*Purpose:* Confirms whether the built-in rule generated alerts. Matching alerts were found for agent `003`, including Windows Record IDs `510`, `512`, and `513`.

**Dashboard verification:** In **Threat Hunting → Events**, searching `rule.id: 91843` with a suitable time range displayed **three alerts**.

**Interpretation:** The rule correctly matched its configured text pattern. The additional matches included investigation commands that repeated the same text. **These were true matches to the detection pattern, but authorized benign activity — not proof that the registry changed.**

## 7. Restore the temporary archive setting

After confirming collection and alerting, restored `<logall_json>no</logall_json>` to avoid unnecessary archive growth.

**Command: Verify the restored setting**

```bash
sudo grep -n '<logall_json>' /var/ossec/etc/ossec.conf
```

*Purpose:* Confirmed the file once again specified `no`.

**Command: Validate, restart, and check the manager**

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

*Purpose:* Checks configuration, applies the restored setting, and verifies the manager is operational. **Final observed output: `active`**.

## Results and SOC analyst assessment

| Check | Observed result |
|---|---|
| Windows PowerShell Script Block Logging | Enabled; Event ID 4104 verified |
| Wazuh Windows PowerShell channel collection | Initialized in agent log |
| Agent communication | Reconnected successfully to manager TCP 1514 |
| Raw PowerShell event reception | Confirmed in `archives.json` |
| Built-in PowerShell detection | Rule `91843` matched |
| Analyst dashboard | Three rule `91843` alerts visible |
| Registry modification | **Not performed or established** |
| Raw JSON archiving cleanup | Restored to `no`; manager `active` |

**Disposition:** Authorized benign test activity. No security incident established.

## Troubleshooting and lessons learned

- A running agent service is not the same as an online agent; the manager VM was initially powered off.
- A Group Policy change must actually be **applied**; a fresh PowerShell session was needed for the test to appear as expected.
- A Windows event, Wazuh-collected event, archived raw event, and generated alert are distinct stages.
- Rule level `0` can be used for grouping; a child rule at level `3` or above may generate a logged alert when matched.
- A search marker can appear in an **unrelated Linux sudo alert** because investigation commands are also logged.
- Pattern matching can generate benign alerts and alert noise; verify what a command actually did before concluding malicious behavior.
- Validate configuration and service health after changes, then restore temporary troubleshooting settings.

## Skills demonstrated

Windows Event Viewer and PowerShell, Group Policy and registry verification, Wazuh agent eventchannel configuration, Linux service management, event archiving, rule-chain analysis, alert triage, evidence correlation, and safe detection testing.

---

*Hands-on cybersecurity portfolio exercise toward a SOC Analyst L1 role. All tests were performed in an authorized isolated lab; the findings do not represent professional SOC employment.*
