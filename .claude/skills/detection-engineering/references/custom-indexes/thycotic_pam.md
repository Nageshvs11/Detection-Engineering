# Thycotic Secret Server (Delinea) — Splunk Custom Index Reference

**Index pattern:**    `*-pam`
**Sourcetype(s):**    `thycotic:secretserver` *(confirm with your Add-on; may vary)*
**Data source:**      Thycotic Secret Server / Delinea Secret Server
**Collection method:** <!-- Splunk Add-on for Thycotic / HEC / Syslog / UF on app server -->
**Category:**         `identity/`
**SPL directory:**    `/opt/DetectionEngineering/splunk/identity/`
**Use case prefix:**  `Identity-DET-Thycotic-`
**Last schema verified:** <!-- fill in date after running discovery queries -->

> **KQL counterpart:** `references/custom-tables/thycotic_cl.md`
> Same data source; same detection logic — different syntax and exclusion mechanism.

---

## How to verify this index is current

Run these in Splunk Search before writing any rule:

```spl
| tstats count WHERE index="*-pam" earliest=-24h
    by index, sourcetype
| sort - count

index="*-pam" earliest=-1h
| head 10

index="*-pam" earliest=-7d
| fieldsummary maxvals=10
| where count > 0
| table field, count, distinct_count, min, max, values

index="*-pam" earliest=-24h
| stats count by EventType
| sort - count
```

---

## Index and Sourcetype Reference

| Index name | Sourcetype | What it captures | Volume estimate |
|---|---|---|---|
| `*-pam` | `thycotic:secretserver` | Secret access, session launches, admin changes | <!-- fill in --> |
| <!-- add if multiple sourcetypes exist --> | | | |

---

## Field Reference

> Fill from `| fieldsummary` and `| head 10` against your live index.
> Update `Last schema verified` date when you run these.

| Field | Type | Description | Example value |
|---|---|---|---|
| `_time` | timestamp | Event timestamp | `2026-05-27T10:00:00` |
| `host` | string | Server that generated the log | `secretserver01.contoso.com` |
| `sourcetype` | string | Splunk sourcetype | `thycotic:secretserver` |
| `EventType` | string | Action category | `SECRET - CHECKOUT` |
| `UserName` | string | Actor — account that performed the action | `jsmith` |
| `SecretName` | string | Name of the secret accessed | `PROD-DC01 Local Admin` |
| `SecretId` | number | Numeric secret ID | `1042` |
| `FolderPath` | string | Folder path of the secret | `Servers\Production\DCs` |
| `ComputerName` | string | Target machine for session launch | `PRODDC01.contoso.com` |
| `ClientIPAddress` | string | IP of the user's browser/client | `10.1.5.22` |
| `Result` | string | Outcome of the action | `SUCCESS`, `FAILURE` |
| `Details` | string | Free-text event detail | `Session recorded` |
| <!-- field --> | <!-- type --> | <!-- description --> | <!-- example --> |

> **Note:** Splunk field names for Thycotic do NOT use `_s`/`_d` suffixes
> (those are KQL `_CL` table conventions). Confirm exact casing from your Add-on.

---

## Event Type Reference

> Confirm values against your environment:
> `index="*-pam" | stats count by EventType | sort - count`

| EventType value | What it means | ATT&CK |
|---|---|---|
| `SECRET - VIEW` | Secret viewed without password reveal | T1078 |
| `SECRET - CHECKOUT` | Password revealed / credential checked out | T1078 |
| `SECRET - EDIT` | Secret metadata or credential value modified | T1098.001 |
| `SECRET - DELETE` | Secret permanently deleted | T1485 |
| `SECRET - COPY` | Secret duplicated to another folder | T1078 |
| `SESSION - START` | Privileged remote session launched | T1078.002 |
| `SESSION - END` | Privileged session closed | — |
| `USER - LOGIN` | Successful login to PAM console | — |
| `USER - LOGIN FAILED` | Failed login to PAM console | T1110 |
| `ROLE - MODIFY` | Permission/role changed on a secret or folder | T1098 |
| `CONFIGURATION - EDIT` | PAM system configuration changed | T1562 |
| <!-- add more --> | <!-- description --> | <!-- ATT&CK --> |

---

## Key Field Values (fill from sample events)

### Actor / user field
```
Field name:   UserName
Sample values:
  - jsmith
  - DOMAIN\svc_backup
  - admin@contoso.com
Notes: may be sAMAccountName or UPN depending on Add-on version
```

### Action / event type field
```
Field name:   EventType
Values:       (see Event Type Reference table above)
```

### Result / outcome field
```
Field name:   Result
Values:       SUCCESS, FAILURE
```

### Source IP field
```
Field name:   ClientIPAddress
Notes:        Browser/client IP; may be a proxy or jump host IP in some environments
```

### Target / secret field
```
Field name:   SecretName (human-readable), SecretId (numeric ID)
Notes:        Use SecretId for joins; SecretName for human-readable output
```

### Target host field
```
Field name:   ComputerName
Notes:        Populated only for SESSION events; empty for SECRET-only events
```

---

## Lookup Table Exclusions

| Lookup file | Join field | Exclusion syntax |
|---|---|---|
| `service_accounts.csv` | `UserName` | `NOT [inputlookup service_accounts.csv \| rename account AS UserName \| table UserName]` |
| `high_value_assets.csv` | `ComputerName` | `lookup high_value_assets.csv hostname AS ComputerName OUTPUT criticality AS asset_criticality` |
| `vpn_egress_ips.csv` | `ClientIPAddress` | `NOT [inputlookup vpn_egress_ips.csv \| rename ip AS ClientIPAddress \| table ClientIPAddress]` |
| `admin_workstations.csv` | *N/A for PAM rules* | PAM logs don't expose a Splunk `host` for the client workstation |
| `sanctioned_tools.csv` | *N/A for PAM rules* | PAM logs are not process-based |

---

## High-Value Detection Patterns

### After-hours privileged credential checkout
```spl
`comment("ATT&CK: T1078 — Valid Accounts")`
index="*-pam" sourcetype="thycotic:secretserver"
    earliest=-1d latest=now
    EventType="SECRET - CHECKOUT"
NOT [| inputlookup service_accounts.csv
     | rename account AS UserName | table UserName]
| eval hour=strftime(_time, "%H"), day=strftime(_time, "%u")
| where (hour < 8 OR hour >= 19) OR day >= 6
| lookup high_value_assets.csv hostname AS ComputerName
    OUTPUT criticality AS asset_criticality
| eval severity=if(asset_criticality="critical", "critical", "high")
| stats
    min(_time) AS first_seen
    max(_time) AS last_seen
    count AS checkout_count
    values(SecretName) AS secrets_accessed
    values(ClientIPAddress) AS source_ips
    latest(severity) AS severity
    by UserName
| table severity, UserName, checkout_count, secrets_accessed,
         source_ips, first_seen, last_seen
```

### Bulk secret access — credential harvesting
```spl
`comment("ATT&CK: T1078 — potential credential harvesting")`
index="*-pam" sourcetype="thycotic:secretserver"
    earliest=-1h latest=now
    EventType IN ("SECRET - VIEW", "SECRET - CHECKOUT")
NOT [| inputlookup service_accounts.csv
     | rename account AS UserName | table UserName]
| stats
    dc(SecretId) AS distinct_secrets
    values(SecretName) AS secret_names
    min(_time) AS first_access
    max(_time) AS last_access
    by UserName, ClientIPAddress
| where distinct_secrets > 10
| eval severity="high"
| table severity, UserName, distinct_secrets, secret_names,
         ClientIPAddress, first_access, last_access
```

### Secret deleted — potential evidence destruction
```spl
`comment("ATT&CK: T1485 — Data Destruction")`
index="*-pam" sourcetype="thycotic:secretserver"
    earliest=-1d latest=now
    EventType="SECRET - DELETE"
NOT [| inputlookup service_accounts.csv
     | rename account AS UserName | table UserName]
| lookup high_value_assets.csv hostname AS ComputerName
    OUTPUT criticality AS asset_criticality
| eval severity=if(asset_criticality="critical", "critical", "high")
| stats
    min(_time) AS first_seen count AS deletion_count
    values(SecretName) AS secrets_deleted
    latest(severity) AS severity
    by UserName, ClientIPAddress
| table severity, UserName, deletion_count, secrets_deleted,
         ClientIPAddress, first_seen
```

### PAM console login failures — brute force or account probing
```spl
`comment("ATT&CK: T1110 — Brute Force")`
index="*-pam" sourcetype="thycotic:secretserver"
    earliest=-1h latest=now
    EventType="USER - LOGIN FAILED"
NOT [| inputlookup vpn_egress_ips.csv
     | rename ip AS ClientIPAddress | table ClientIPAddress]
| stats
    count AS failure_count
    dc(ClientIPAddress) AS distinct_ips
    values(ClientIPAddress) AS source_ips
    min(_time) AS first_failure
    max(_time) AS last_failure
    by UserName
| where failure_count >= 5
| eval severity=if(failure_count >= 10, "high", "medium")
| table severity, UserName, failure_count, distinct_ips,
         source_ips, first_failure, last_failure
```

### Privileged role modification
```spl
`comment("ATT&CK: T1098 — Account Manipulation")`
index="*-pam" sourcetype="thycotic:secretserver"
    earliest=-1d latest=now
    EventType="ROLE - MODIFY"
NOT [| inputlookup service_accounts.csv
     | rename account AS UserName | table UserName]
| stats
    min(_time) AS first_seen count AS change_count
    values(Details) AS change_details
    by UserName, ClientIPAddress
| table first_seen, UserName, change_count, change_details, ClientIPAddress
```

---

## False Positive Notes

| Pattern | Root cause | Mitigation |
|---|---|---|
| Bulk access by password rotation service account | Automated rotation job checks out each secret to rotate | Add rotation service account to `service_accounts.csv` |
| After-hours access by on-call engineer | Incident response; called in outside business hours | Cross-reference with on-call schedule; lower severity if corroborated by ticket |
| High checkout count for admin running deployment | Manual deployment procedure accesses many DB credentials | Correlate with change ticket; suppress by time window if recurrent |
| <!-- add pattern --> | <!-- root cause --> | <!-- mitigation --> |

---

## Rules Written Against This Index

| Rule file | Use case ID | ATT&CK | Type | Status |
|---|---|---|---|---|
| <!-- 001_filename.spl --> | <!-- Identity-DET-Thycotic-001_... --> | <!-- T1078 --> | <!-- SavedSearch --> | <!-- draft --> |
