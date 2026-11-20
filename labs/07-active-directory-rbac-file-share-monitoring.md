# Lab 07 — Active Directory RBAC & File Share Access Monitoring

## Objective

Implement Role-Based Access Control (RBAC) in an Active Directory environment, enforce least-privilege access to departmental file shares, and investigate unauthorized access attempts using Windows Security logs and Wazuh SIEM.

This exercise demonstrates access-control administration, security auditing, SIEM troubleshooting, and evidence-based investigation in a controlled home lab.

## Lab Environment

| Component | Configuration |
|---|---|
| Virtualization | VMware Workstation Pro |
| Domain Controller | Windows Server 2022 |
| Active Directory Domain | `corp.example.test` |
| Server Hostname | `AD-DC01` |
| SIEM | Wazuh |
| Windows Wazuh Agent | Agent ID `004` |
| Monitored Event | Windows Security Event ID `5145` |

## 1. Active Directory and RBAC Configuration

Created departmental Organizational Units (OUs) to organize users according to their business functions:

- IT
- HR
- Finance

Configured departmental security groups to manage access through group membership rather than assigning permissions individually.

Example accounts used during testing:

| User | Department | Access requirement |
|---|---|---|
| Anna Reyes | HR | Authorized access to HR resources |
| Mark Santos | Finance | Authorized access to Finance resources |

**Security principle:** Group-based permissions simplify administration and help enforce the Principle of Least Privilege.

A user's access should be determined by their responsibilities and approved business requirements.

## 2. Departmental File Share Configuration

Created departmental folders under:

`C:\DepartmentShares\`

Configured NTFS permissions and SMB share permissions for the HR and Finance folders.

### HR Share

- Share name: `HR`
- Path: `C:\DepartmentShares\HR`
- HR STAFF: Modify (NTFS), Change (SMB share)
- Domain Admins: Full Control

### Finance Share

- Share name: `Finance`
- Path: `C:\DepartmentShares\Finance`
- Finance-staff: Modify (NTFS), Change (SMB share)
- Domain Admins: Full Control

Removed broad access entries from the departmental folder permissions and share permissions to restrict access to authorized groups.

Verified SMB share paths and permissions using:

```cmd
net share HR
net share Finance
```

### Configuration Troubleshooting

During initial testing, the HR share incorrectly pointed to:

`C:\DepartmentShares`

Instead of:

`C:\DepartmentShares\HR`

This caused the share to display the parent directory containing multiple departmental folders.

The incorrect share was removed and recreated using the intended HR folder path.

**Lesson learned:** Always verify the actual resource path and permissions after configuring a network share. A successful connection does not necessarily prove that the configuration is correct.

## 3. Effective Access Verification

Used Windows **Advanced Security Settings → Effective Access** to evaluate departmental permissions.

### Authorized User — Anna Reyes

The Effective Access evaluation showed that Anna had the permissions needed to work with the HR folder without Full Control.

### Restricted User — Mark Santos

The Effective Access evaluation showed that Mark did not have the permissions required to read, modify, or manage the HR folder.

These results were consistent with the intended departmental access restrictions.

**Note:** Effective Access evaluates permissions; it does not itself generate an actual access-denied event.

## 4. Unauthorized Access Test

Performed a controlled attempt to access the Finance share using Anna's network credentials.

The test used:

```cmd
runas /netonly /user:CORP\anna cmd
```

Followed by:

```cmd
dir \\AD-DC01\Finance
```

**Observed result:**

```text
Access is denied.
```

Because `/netonly` retains the local process identity while supplying different credentials for network authentication, the Windows Security logs were examined to confirm which account performed the access attempt.

## 5. Windows Security Auditing

Initially, no Event ID 5145 entries appeared in Event Viewer.

Checked the auditing configuration:

```cmd
auditpol /get /subcategory:"Detailed File Share"
```

**Initial result:** `No Auditing`

Enabled successful and failed detailed file-share auditing:

```cmd
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
```

Verified the updated setting:

`Detailed File Share — Success and Failure`

Repeated the access attempt and confirmed that Windows generated Event ID **5145 — Detailed File Share**, marked as an audit failure.

### Windows Event 5145 Findings

| Field | Observed value |
|---|---|
| Account | `CORP\anna` |
| Target share | `\\*\Finance` |
|
