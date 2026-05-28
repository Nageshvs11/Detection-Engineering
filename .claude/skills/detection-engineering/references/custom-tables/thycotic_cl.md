# Thycotic_CL — Schema Reference

**Source:** Thycotic Secret Server (Delinea)
**Ingestion method:** <!-- HTTP Data Collector API / AMA / Logic App — fill in -->
**Sentinel workspace:** <!-- fill in workspace name -->
**Category:** PAM / Privileged Access Management
**Directory:** `identity/`
**Use case ID prefix:** `Identity-DET-Thycotic-`
**Last schema verified:** <!-- fill in date after running getschema -->

---

## How to verify this schema is current

Run in Log Analytics before writing any rule:

```kql
// Confirm table exists and has recent data
Thycotic_CL
| summarize LastEvent = max(TimeGenerated), EventCount = count()

// Get authoritative field list with types
Thycotic_CL
| getschema

// Sample 10 real events — paste output into the Field Reference section below
Thycotic_CL
| take 10
```

---

## Field Reference

> Fill in each row from your `getschema` output and a real sample event.
> Mark optional fields with `(optional)` — they may be null/empty on some event types.

| Field | Type | Description | Example value |
|---|---|---|---|
| `TimeGenerated` | datetime | Event ingestion timestamp | `2026-05-27T10:00:00Z` |
| <!-- field_s --> | string | <!-- description --> | <!-- example --> |
| <!-- field_s --> | string | <!-- description --> | <!-- example --> |
| <!-- field_d --> | real | <!-- description --> | <!-- example --> |
| <!-- field_b --> | bool | <!-- description --> | <!-- example --> |
| <!-- field_g --> | guid | <!-- description --> | <!-- example --> |

> **Tip:** Custom `_CL` tables suffix field names with a type indicator:
> `_s` = string, `_d` = double/number, `_b` = boolean, `_g` = GUID,
> `_t` = datetime, `_s` inside a dynamic field = serialised JSON string.

---

## EventType Reference

> Replace the rows below with your actual event type values.
> Run this query to discover them:
>
> ```kql
> Thycotic_CL
> | summarize Count = count() by EventType_s   // replace EventType_s with your actual field name
> | sort by Count desc
> ```

| EventType value | What it means | ATT&CK |
|---|---|---|
| `SECRET - VIEW` | Secret viewed (password not revealed) | T1078 |
| `SECRET - CHECKOUT` | Credential checked out — password revealed to user | T1078 |
| `SECRET - EDIT` | Secret metadata or credential value modified | T1098.001 |
| `SECRET - DELETE` | Secret permanently deleted | T1485 |
| `SECRET - COPY` | Secret duplicated | T1078 |
| `SESSION - START` | Privileged remote session launched via launcher | T1078.002 |
| `SESSION - END` | Privileged session closed | |
| `USER - LOGIN` | Successful login to PAM console | |
| `USER - LOGIN FAILED` | Failed login to PAM console | T1110 |
| `ROLE - MODIFY` | Permission/role changed on a secret or folder | T1098 |
| `FOLDER - CREATE` | New secret folder created | |
| `CONFIGURATION - EDIT` | PAM system/site configuration changed | T1562 |
| <!-- add more --> | <!-- description --> | <!-- ATT&CK --> |

---

## Key Field Values (fill in from sample events)

### Actor field
```
Field name:   <!-- e.g. UserName_s -->
Sample values:
  - domain\username
  - service_account_name
  - SYSTEM (automated workflows)
```

### Target / secret field
```
Field name:   <!-- e.g. SecretName_s -->
Sample values:
  - "PROD-DC01 Local Admin"
  - "AWS Root Account"
```

### Result / outcome field
```
Field name:   <!-- e.g. Result_s -->
Values:
  - SUCCESS
  - FAILURE
  - <!-- others from your environment -->
```

### Source IP field
```
Field name:   <!-- e.g. ClientIPAddress_s -->
Notes:        <!-- Internal only? Includes VPN egress? -->
```

### Folder / container field
```
Field name:   <!-- e.g. FolderPath_s -->
Sample path:  <!-- e.g. "Servers\\Production\\Domain Controllers" -->
```

---

## High-Value Detection Patterns

Paste working KQL snippets here as you build and validate rules.
These become the baseline the skill references when writing new Thycotic detections.

### After-hours privileged credential checkout
```kql
// T1078 — suspicious access outside business hours
Thycotic_CL
| where TimeGenerated > ago(1d)
| where <!-- EventType field --> == "SECRET - CHECKOUT"
| where hourofday(TimeGenerated) !between (8 .. 18)
    or dayofweek(TimeGenerated) in (0d, 6d)    // weekend
| project TimeGenerated,
          <!-- actor field -->,
          <!-- secret field -->,
          <!-- folder field -->,
          <!-- source IP field -->
```

### Bulk secret access — potential credential harvesting
```kql
// T1078 — one account accessing many secrets in a short window
Thycotic_CL
| where TimeGenerated > ago(1h)
| where <!-- EventType field --> in ("SECRET - VIEW", "SECRET - CHECKOUT")
| summarize
    SecretCount = dcount(<!-- SecretId field -->),
    Secrets     = make_set(<!-- SecretName field -->, 20),
    FirstAccess = min(TimeGenerated),
    LastAccess  = max(TimeGenerated)
    by <!-- actor field -->
| where SecretCount > 10    // tune threshold for your environment
```

### First-ever access to a high-value secret
```kql
// T1078 — account accessing a secret it has never touched before
// Requires 30d of baseline; run as a scheduled hunt, not a 5m analytic
Thycotic_CL
| where TimeGenerated > ago(30d)
| where <!-- EventType field --> in ("SECRET - VIEW", "SECRET - CHECKOUT")
| summarize
    AccessCount = count(),
    FirstSeen   = min(TimeGenerated),
    LastSeen    = max(TimeGenerated)
    by <!-- actor field -->, <!-- SecretId field -->, <!-- SecretName field -->
| where AccessCount == 1 and FirstSeen > ago(1d)    // first access happened in last 24h
```

### Privileged secret deletion
```kql
// T1485 — secret deleted; may indicate cover-up or insider threat
Thycotic_CL
| where TimeGenerated > ago(1d)
| where <!-- EventType field --> == "SECRET - DELETE"
| project TimeGenerated,
          <!-- actor field -->,
          <!-- secret field -->,
          <!-- folder field -->,
          <!-- source IP field -->
```

### PAM console login failures — brute force or account probing
```kql
// T1110 — repeated login failures to the PAM console
Thycotic_CL
| where TimeGenerated > ago(1h)
| where <!-- EventType field --> == "USER - LOGIN FAILED"
| summarize
    FailCount  = count(),
    SourceIPs  = make_set(<!-- source IP field -->)
    by <!-- actor field -->
| where FailCount >= 5
```

### Role or permission change on a secret
```kql
// T1098 — permission escalation: user granted access to secrets they shouldn't have
Thycotic_CL
| where TimeGenerated > ago(1d)
| where <!-- EventType field --> == "ROLE - MODIFY"
| project TimeGenerated,
          <!-- actor field -->,
          <!-- target/affected secret or folder -->,
          <!-- change details field -->
```

---

## False Positive Notes

Document environment-specific FP patterns here as you tune rules.

| Pattern | Root cause | Mitigation |
|---|---|---|
| Bulk access by backup/rotation service account | Automated password rotation job | Exclude `<!-- service account name -->` by actor field |
| After-hours access by on-call team | Incident response or maintenance windows | Cross-reference with PagerDuty / ServiceNow on-call schedule |
| <!-- add pattern --> | <!-- root cause --> | <!-- mitigation --> |

---

## Rules Written Against This Table

Track rules here so coverage gaps are visible at a glance.

| Rule file | Use case ID | ATT&CK | Status |
|---|---|---|---|
| <!-- 001_filename.kql --> | <!-- Identity-DET-Thycotic-001_... --> | <!-- T1078 --> | <!-- draft / deployed --> |
