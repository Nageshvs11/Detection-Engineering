# <Product/Source> — Splunk Custom Index Reference

**Index pattern:**    <!-- e.g. *-pam or *-azure-custom -->
**Sourcetype(s):**    <!-- e.g. thycotic:secretserver, vendor:product -->
**Data source:**      <!-- product name and version -->
**Collection method:** <!-- Splunk UF / HEC / Add-on / Syslog -->
**Category:**         <!-- identity | windows | linux | network | cloud | application | edr -->
**SPL directory:**    `/opt/DetectionEngineering/splunk/<category>/`
**Use case prefix:**  <!-- Identity-DET-<Product>- | OS-DET-WIN- | Network-DET-<Product>- etc. -->
**Last schema verified:** <!-- fill in date after running discovery queries -->

---

## How to verify this index is current

Run these in Splunk Search before writing any rule:

```spl
| tstats count WHERE index="<index-pattern>" earliest=-24h
    by index, sourcetype
| sort - count

index="<index-pattern>" earliest=-1h
| head 10

index="<index-pattern>" earliest=-7d
| fieldsummary maxvals=10
| where count > 0
| table field, count, distinct_count, min, max, values

index="<index-pattern>" earliest=-24h
| stats count by <event_type_field>
| sort - count
```

---

## Index and Sourcetype Reference

| Index name | Sourcetype | What it captures | Volume estimate |
|---|---|---|---|
| `<index-pattern>` | `<sourcetype>` | <!-- description --> | <!-- events/day --> |
| <!-- add rows as sourcetypes are discovered --> | | | |

---

## Field Reference

> Fill from `| fieldsummary` output and a real `| head 10` sample.
> Splunk field names do NOT use type suffixes (_s, _d) unlike KQL _CL tables.

| Field | Type | Description | Example value |
|---|---|---|---|
| `_time` | timestamp | Event timestamp (Splunk internal) | `1748390400` |
| `host` | string | Source host that sent the event | `secretserver01.contoso.com` |
| `source` | string | Log file or input path | `/var/log/secretserver/` |
| `sourcetype` | string | Splunk sourcetype | `<sourcetype>` |
| <!-- field_name --> | string | <!-- description --> | <!-- example --> |
| <!-- field_name --> | number | <!-- description --> | <!-- example --> |
| <!-- field_name --> | boolean | <!-- description --> | <!-- example --> |

---

## Event Type Reference

> Replace with your actual event type values.
> Run: `index="<index>" | stats count by <event_type_field> | sort - count`

| Event type value | What it means | ATT&CK |
|---|---|---|
| <!-- value --> | <!-- description --> | <!-- T1XXX --> |
| <!-- value --> | <!-- description --> | <!-- T1XXX --> |

---

## Key Field Values (fill from sample events)

### Actor / user field
```
Field name:   <!-- e.g. user, actor, username -->
Sample values:
  - domain\username
  - service_account_name
```

### Action / event type field
```
Field name:   <!-- e.g. action, EventType, event_type -->
Values:       <!-- list from | stats count by <field> -->
```

### Result / outcome field
```
Field name:   <!-- e.g. result, outcome, status -->
Values:       <!-- SUCCESS, FAILURE, etc. -->
```

### Source IP field
```
Field name:   <!-- e.g. src_ip, ClientIP, client_address -->
Notes:        <!-- internal only? includes VPN egress? -->
```

### Target / object field
```
Field name:   <!-- e.g. dest, target, object_name -->
Notes:        <!-- what does the actor act on? -->
```

---

## Lookup Table Exclusions

> Reference the standard lookup CSVs that apply to this data source.

| Lookup file | Join field | When to use |
|---|---|---|
| `vpn_egress_ips.csv` | `src_ip` | Rules that filter on source IP |
| `service_accounts.csv` | `user` | Rules that filter on user/account |
| `admin_workstations.csv` | `host` | Rules that filter on source host |
| `sanctioned_tools.csv` | `process` | Process-based rules only |
| `high_value_assets.csv` | `dest` or `host` | All rules — severity graduation |

---

## High-Value Detection Patterns

> Paste working SPL snippets here as you build and validate rules.
> Use `<!-- field_name -->` as placeholder for fields not yet confirmed.

### Pattern 1 — <description>
```spl
`comment("ATT&CK: T1XXX — <technique>")`
index="<index-pattern>" sourcetype="<sourcetype>"
    earliest=-1h latest=now
    <!-- event_type_field -->="<!-- value -->"
NOT [| inputlookup service_accounts.csv | rename account AS user | table user]
| stats
    min(_time)  AS first_seen
    max(_time)  AS last_seen
    count       AS event_count
    by user, <!-- target_field -->, src_ip
| table first_seen, last_seen, event_count, user, <!-- target_field -->, src_ip
```

### Pattern 2 — <description>
```spl
`comment("ATT&CK: T1XXX — <technique>")`
index="<index-pattern>" sourcetype="<sourcetype>"
    earliest=-1h latest=now
    <!-- event_type_field -->="<!-- value -->"
| stats count AS action_count by user, <!-- target_field -->
| where action_count > <!-- threshold -->
```

---

## False Positive Notes

| Pattern | Root cause | Mitigation |
|---|---|---|
| <!-- describe FP --> | <!-- why it fires --> | <!-- how to suppress --> |

---

## Rules Written Against This Index

| Rule file | Use case ID | ATT&CK | Status |
|---|---|---|---|
| <!-- 001_filename.spl --> | <!-- prefix-001_name --> | <!-- T1XXX --> | <!-- draft / SavedSearch / CorrelationSearch --> |
