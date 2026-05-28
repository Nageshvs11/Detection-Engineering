---
name: detection-engineering
description: |
  Detection rule development standards. Activate when writing,
  reviewing, or validating Sigma, KQL, or SPL detection rules.
---

# Detection Engineering Standards

## Trigger

Use this skill when:
- Writing, creating, or modifying Sigma/YARA rules
- Reviewing detection rules for quality or completeness
- Discussing detection coverage, gaps, or improvements
- Working with YAML files containing detection logic
- Asked to validate, check, or audit detection rules
- Converting detections between formats (Sigma to KQL, SPL, etc.)

## Standards

Every Sigma rule you write or review must satisfy all five standards below. Flag any violation explicitly before proceeding.

---

### 1. ATT&CK Technique Mapping (Required)

Every rule **must** include at least one specific ATT&CK technique tag in the `tags` field using the format `attack.tXXXX` or `attack.tXXXX.YYY` (sub-technique).

**Valid:**
```yaml
tags:
    - attack.credential-access
    - attack.t1003.001
```

**Invalid** (tactic-only, no technique):
```yaml
tags:
    - attack.credential-access
```

If a rule lacks a technique tag, do not proceed — ask the user to identify the ATT&CK technique before writing the rule. A technique ID is non-negotiable; the tactic tag alone is insufficient.

---

### 2. Severity Level with Justification (Required)

The `level` field must be exactly one of: `low`, `medium`, `high`, `critical`.

When writing a new rule or reviewing an existing one, add a comment block directly above the `level` field explaining **why** that severity was chosen. Base justification on:
- Likelihood of false positives (high FP rate → lower severity)
- Impact if true positive (lateral movement, credential theft → higher severity)
- Whether the activity has any legitimate use case

**Example:**
```yaml
# high: activity has no legitimate use in production; direct path to credential theft
level: high
```

If severity is missing or uses a non-standard value (e.g., `informational`), flag it and request a valid level with justification before continuing.

---

### 3. False Positive Documentation (Required)

The `falsepositives` field must not be left as `Unknown` alone. Every rule must include at least one of:
- A concrete false positive scenario (e.g., specific tooling, admin workflows)
- An explicit statement that no false positives are expected, with reasoning

**Acceptable — known FP scenarios:**
```yaml
falsepositives:
    - Legitimate memory dump by Windows Error Reporting (WER)
    - Authorized security tooling running under dedicated service accounts
```

**Acceptable — no false positives expected:**
```yaml
falsepositives:
    - No false positives expected — this behavior has no known legitimate use case
      in production environments outside of the filtered paths above.
```

**Acceptable — genuinely unknown but documented:**
```yaml
falsepositives:
    - No benign use case has been identified during testing; monitor for tuning
      opportunities in environments with non-standard tooling or legacy software.
```

**Not acceptable:**
```yaml
falsepositives:
    - Unknown
```

**When FPs are genuinely unknown:** `Unknown` alone is never acceptable because it gives responders nothing to act on. If you cannot identify a concrete scenario, write what you *do* know — that no benign use was found during testing, and what environment types might need tuning. This is still more useful than a blank placeholder.

If a rule has only `Unknown`, prompt the user to think through: IT admin workflows, security tools, backup software, legitimate developer activity, or vendor tooling that could trigger the detection. Use these categories as a checklist before falling back to the "no FP identified" form above.

---

### 4. Test Case (Required)

Every rule must be accompanied by at least one test case. The test case must live in one of:
- An inline `tests` block within the rule file (non-standard but acceptable here)
- A companion `<rule_name>.test.yml` file alongside the rule

**Positive test** (event that must match — always required):
```yaml
tests:
    - name: <tool or technique triggering the detection>
      log_source:
          product: windows
          category: <matching logsource category>
      event:
          <field>: <value that should trigger the rule>
      expected: match
```

**Negative test** (event that must NOT match — required when the rule has filters):
```yaml
    - name: <legitimate activity covered by the filter>
      log_source:
          product: windows
          category: <matching logsource category>
      event:
          <field>: <value that the filter should suppress>
      expected: no_match
```

**When to include a negative test:** Any rule that has a `filter_*` condition or an `and not` clause must include at least one negative test confirming the filter works. Without it, there is no evidence the filter is correctly scoped and it may be silently over- or under-filtering.

**Minimum bar:**
- One positive test always.
- One negative test for every distinct `filter_*` block (or at minimum one negative test covering the most critical legitimate-use case).
- Use realistic field values — copy from actual log samples where possible rather than inventing placeholder strings.

If writing a new rule, generate the test cases before declaring the rule complete.

---

### 5. Rule File Naming (Required)

Rule file names must be **all lowercase with underscores** — no hyphens, no spaces, no camelCase.

**Valid:**
- `proc_creation_win_hktl_mimikatz_command_line.yml`
- `win_security_dcsync.yml`

**Invalid:**
- `ProcCreation-Mimikatz.yml`
- `winSecurityDCSync.yml`
- `proc-creation-mimikatz.yml`

The filename should follow the pattern: `<category>_<platform>_<description>.yml`, mirroring the naming convention already in `rules/`.

---

## Enforcement Workflow

Apply this checklist to every rule being written or reviewed. The checklist is
split into three tiers: universal standards that apply to all formats, then
KQL-specific and SPL-specific production requirements.

### Universal standards (Sigma, KQL, SPL — all formats)

```
[ ] U1. ATT&CK technique tag present — attack.tXXXX or // ATT&CK: T1XXX.YYY
        (technique-level required; tactic-only is not acceptable)
[ ] U2. Severity declared as low | medium | high | critical with justification
        comment explaining why that level was chosen
[ ] U3. False positives section lists concrete scenarios — not just "Unknown"
        At minimum: which legitimate tools, accounts, or workflows could trigger this
[ ] U4. At least one positive test case and one negative test case per filter block
[ ] U5. Filename is lowercase_with_underscores (Sigma: .yml  KQL: .kql  SPL: .spl)
[ ] U6. Use case ID present in header — format: <prefix>-{NNN}_{description}
[ ] U7. ATT&CK mappings file updated after writing or modifying a rule
```

### KQL additional standards (Sentinel / Defender XDR rules)

```
[ ] K1. Target console declared in header — Sentinel | DefenderXDR | Both
        Correct timestamp field used: TimeGenerated (Sentinel) or Timestamp (XDR)
[ ] K2. KQL table verified against workspace before writing
        (run: <TableName> | summarize max(TimeGenerated) — must return recent data)
[ ] K3. Rule type declared — // Type: AnalyticRule | HuntingQuery
        New rules default to HuntingQuery unless the technique has zero legitimate use
[ ] K4. Sentinel Watchlist exclusion blocks present for every applicable FP source:
        [ ] VPN-Egress-IPs       (any rule that filters on IP address)
        [ ] Service-Accounts     (any rule that filters on user/account)
        [ ] Admin-Workstations   (any endpoint or lateral movement rule)
        [ ] Sanctioned-Tools     (any process creation or execution rule)
        [ ] High-Value-Assets    (every rule — used for severity graduation)
        Absent block must be justified with a comment in the rule header
[ ] K5. Final output deduplicated — summarize + arg_max before project
        One alert row per entity per time window; never one row per raw event
[ ] K6. Entity fields projected for Sentinel alert mapping:
        Account → AccountName + AccountDomain
        Host    → Computer or DeviceName
        IP      → IPAddress
        Defender XDR rules must include ReportId + DeviceName or AccountObjectId
```

### SPL additional standards (Splunk / Splunk ES rules)

```
[ ] S1. Index pattern declared and matches the routing table:
        *-os-win    → Windows Security Event Logs (Event Viewer / Splunk UF)
        *-os-linux  → Linux /var/log/ (Splunk UF)
        *-network   → Network and security device syslog
        *-edr       → MDE / EDR telemetry
        *-azure     → Azure data sources (SignInLogs, AuditLogs, AzureActivity)
        Index verified before writing: | tstats count WHERE index="*-<cat>" earliest=-24h
[ ] S2. Sourcetype declared — do not rely on index alone; add sourcetype=<type>
        to prevent false matches if multiple sourcetypes share an index
[ ] S3. Rule type declared in header — Type: CorrelationSearch | SavedSearch
        New rules default to SavedSearch unless technique has zero legitimate use
[ ] S4. Lookup table exclusion checklist ticked in header — for every applicable source:
        [ ] vpn_egress_ips.csv      (any rule that filters on src_ip or dest_ip)
        [ ] service_accounts.csv    (any rule that filters on user or account)
        [ ] admin_workstations.csv  (any endpoint or lateral movement rule)
        [ ] sanctioned_tools.csv    (any process creation or execution rule)
        [ ] high_value_assets.csv   (every rule — severity graduation)
        Absent lookup must be justified in the rule header comment
[ ] S5. Final output deduplicated — stats ... by <entity_field> before table
        One notable event per entity per window; never one row per raw event
[ ] S6. RBA (Risk-Based Alerting) considered for noisy signals
        If the rule fires > 10 times/day in testing, use the RBA block instead
        of direct notable event creation
```

---

Do not mark a rule complete until all universal items and all applicable
format-specific items are checked. If a user asks to skip any standard, explain
the risk and ask for explicit confirmation before proceeding.

### Exclusion decision rule (KQL watchlists and SPL lookup tables)

Before writing any exclusion as a hardcoded value in the query body, ask:

| Question | Answer | Action |
|---|---|---|
| Could this value change without a rule edit? | Yes | KQL: `_GetWatchlist()` join · SPL: `NOT [inputlookup ...]` |
| Is this a known-legitimate IP, account, host, or tool? | Yes | KQL: Watchlist · SPL: Lookup CSV |
| Is this a structural invariant that never changes? | Yes | Hardcode is acceptable (e.g. `$` suffix, `NT AUTHORITY`) |
| Is this a one-off quirk for one environment? | Yes | Document in header comment AND add to lookup for auditability |

**Every rule targeting identity, network, cloud, or endpoint data has at least
one exclusion opportunity. A rule with no exclusion blocks and no justification
comment is incomplete regardless of whether it passes the other checks.**

### Platform terminology mapping

| Concept | Sentinel / Defender XDR | Splunk ES |
|---|---|---|
| Auto-alerting rule | Analytics Rule | Correlation Search |
| Analyst-reviewed query | Hunting Query | Saved Search / Report |
| Risk accumulation | UEBA / Fusion | Risk-Based Alerting (RBA) |
| Exclusion store | Watchlist (`_GetWatchlist()`) | Lookup CSV (`inputlookup`) |
| Alert suppression | Suppress field in rule | Throttling in Correlation Search |
| Entity-aware alert | Entity mapping in rule wizard | Risk object (`risk_object`) |
| Incident creation | Incident in Sentinel | Notable event in ES |

## ATT&CK Coverage Update

After writing or modifying a rule, check whether `mappings/` needs updating. If the rule introduces a new technique mapping, add the technique ID and rule ID to the appropriate mapping file so `server.py` can expose it via the coverage query tool.

## Validation

After creating or modifying a rule, validate it:

```bash
python .claude/skills/detection-engineering/scripts/validate-rule.py path/to/rule.yml
```

Use `--exit-code` in CI to fail the pipeline on validation errors:

```bash
python .claude/skills/detection-engineering/scripts/validate-rule.py --exit-code path/to/rule.yml
```

## Output Directories and File Routing

KQL and SPL rules are written to a shared output tree. Sigma rules remain in
the project `rules/` directory (YAML). Use the table below to determine the
correct output path for every new rule.

### Root paths

| Format | Root |
|--------|------|
| KQL (Microsoft Sentinel / MDE) | `kql/` |
| SPL (Splunk) | `splunk/` |

### KQL table selection — data source → Sentinel table

Before writing any KQL rule, identify the data source and select the correct
Sentinel table. Using the wrong table produces silent non-matches in production.

| Data source | Collection method | KQL table(s) |
|---|---|---|
| Windows Security Event Logs | Windows Event Viewer / Log Analytics agent | `SecurityEvent` |
| Linux system logs | `/var/log/` via Log Analytics agent | `Syslog` |
| Network & security devices (firewall, router, IDS/IPS, switch, VPN) | Syslog push from device to Sentinel | `CommonSecurityLog` |
| Microsoft Defender for Endpoint (MDE) telemetry | MDE agent on endpoint | `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceImageLoadEvents`, `DeviceEvents` |
| Azure platform data sources | Microsoft Azure data connectors | `SignInLogs`, `AuditLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AzureActivity`, `AzureDiagnostics`, `OfficeActivity` |

**Decision rules:**

- **Windows host activity detected via endpoint agent** → use MDE tables
  (`DeviceProcessEvents` etc.), not `SecurityEvent`.
- **Windows authentication and privilege events** (logon, account changes,
  policy, object access) → use `SecurityEvent`.
- **Both host behaviour and auth context needed** → join `DeviceProcessEvents`
  with `SecurityEvent` on `DeviceName` / `Computer`.
- **Azure AD / Entra ID sign-in and directory events** → use `SignInLogs` or
  `AuditLogs`, never `SecurityEvent`.
- **Network device logs arriving via syslog** → use `CommonSecurityLog`
  (CEF-formatted) or `Syslog` (plain syslog); prefer `CommonSecurityLog` when
  the device supports CEF output.

**Always confirm the table exists in the target workspace before deploying.**
Add a comment in the rule header if a prerequisite data connector must be enabled.

---

### SPL index selection — data source → index pattern

Every SPL rule must declare the correct index in its search. Using the wrong
index returns zero results silently. The index pattern uses a wildcard prefix
(`*`) that represents the client or environment name — replace `*` with the
actual client prefix in production (e.g., `acme-os-win`).

| Data source | Collection method | Index pattern | Common sourcetypes |
|---|---|---|---|
| Windows Security Event Logs | Windows Event Viewer / Splunk UF or HEC | `index="*-os-win"` | `WinEventLog:Security`, `WinEventLog:System`, `XmlWinEventLog:Security`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| Linux system logs | `/var/log/` via Splunk UF | `index="*-os-linux"` | `syslog`, `linux_secure`, `linux_audit`, `auditd` |
| Network & security devices | Syslog push from firewall, router, IDS/IPS, switch, VPN | `index="*-network"` | `cisco:asa`, `paloalto`, `fortinet`, `juniper`, `checkpoint`, `syslog` |
| MDE / EDR telemetry | Microsoft Defender for Endpoint agent, CrowdStrike, SentinelOne | `index="*-edr"` | `ms:defender:atp`, `crowdstrike`, `sentinelone` |
| Azure data sources | Microsoft Azure data connectors (SignInLogs, AuditLogs, AzureActivity, etc.) | `index="*-azure"` | `mscs:azure:eventhub`, `azure:audit`, `azure:signin`, `ms:azure:monitor` |

**Decision rules:**
- Windows host logs from Event Viewer → `*-os-win`
- Linux host logs from `/var/log/` → `*-os-linux`
- Network/security device syslog → `*-network`
- EDR/MDE endpoint telemetry → `*-edr`
- Azure cloud platform (sign-in, audit, activity) → `*-azure`
- When a rule spans two index patterns (e.g., Azure sign-in + Windows host),
  use a union search: `(index="*-azure" OR index="*-os-win")` and add a
  `sourcetype` filter to keep the result set focused.

**Before writing any SPL rule, confirm the index exists and has recent data:**
```spl
| tstats count WHERE index="*-os-win" earliest=-24h by index, sourcetype
| sort - count
```

---

### Console portability — Sentinel vs Defender XDR

Rules must declare their target console in the header (`// Target:`). The
differences below cause silent failures when a rule is deployed to the wrong console.

#### Timestamp field — the most common breakage point

| Console | Correct timestamp field | Notes |
|---|---|---|
| **Microsoft Sentinel** | `TimeGenerated` | All Sentinel tables use `TimeGenerated` |
| **Defender XDR Advanced Hunting** | `Timestamp` | All XDR tables use `Timestamp` |
| **Both (Sentinel with XDR connector)** | `TimeGenerated` | Sentinel exposes both; use `TimeGenerated` for portability |

**Rule:** Always use `TimeGenerated` unless the rule is **exclusively** for Defender XDR Advanced Hunting. If writing for Defender XDR only, use `Timestamp` and note it in the header.

```kql
// Target: Sentinel
| where TimeGenerated > ago(1h)   // correct for Sentinel

// Target: DefenderXDR
| where Timestamp > ago(1h)       // correct for Defender XDR Advanced Hunting
```

#### Table availability by console

| Table | Sentinel | Defender XDR | Notes |
|---|---|---|---|
| `SigninLogs` | Yes | No | Requires Entra ID connector |
| `AuditLogs` | Yes | No | Requires Entra ID connector |
| `AADNonInteractiveUserSignInLogs` | Yes | No | |
| `AADServicePrincipalSignInLogs` | Yes | No | |
| `AzureActivity` | Yes | No | Azure control-plane only |
| `SecurityEvent` | Yes | No | Windows Security Event Log via AMA |
| `CommonSecurityLog` | Yes | No | CEF syslog devices |
| `OfficeActivity` | Yes | No | |
| `DeviceProcessEvents` | Yes (via XDR connector) | Yes | `TimeGenerated` in Sentinel, `Timestamp` in XDR |
| `DeviceNetworkEvents` | Yes (via XDR connector) | Yes | Same timestamp split |
| `DeviceFileEvents` | Yes (via XDR connector) | Yes | Same timestamp split |
| `DeviceRegistryEvents` | Yes (via XDR connector) | Yes | Same timestamp split |
| `DeviceLogonEvents` | Yes (via XDR connector) | Yes | Same timestamp split |
| `AlertEvidence` | Yes (via XDR connector) | Yes | |
| `CloudAppEvents` | Yes (via XDR connector) | Yes | |
| `EmailEvents` | Yes (via XDR connector) | Yes | |
| `IdentityLogonEvents` | Yes (via XDR connector) | Yes | |
| `IdentityDirectoryEvents` | Yes (via XDR connector) | Yes | |
| `IdentityQueryEvents` | Yes (via XDR connector) | Yes | |
| `IdentityInfo` | Yes (via XDR connector) | Yes | User account enrichment |
| `AlertInfo` | No | Yes | Maps to `SecurityAlert` in Sentinel |

#### Workspace discovery — verify tables exist before writing a rule

Run this before writing any rule to confirm the required table is connected and has recent data:

```kql
// Verify a single table has data
SigninLogs
| where TimeGenerated > ago(7d)
| summarize LastEvent = max(TimeGenerated), EventCount = count()

// Verify multiple tables at once
let tables = dynamic(["SigninLogs", "AADNonInteractiveUserSignInLogs",
                       "DeviceProcessEvents", "SecurityEvent"]);
range i from 0 to array_length(tables)-1 step 1
| extend TableName = tostring(tables[i])
| join kind=inner (
    union isfuzzy=true
        (SigninLogs                          | summarize LastEvent=max(TimeGenerated) | extend T="SigninLogs"),
        (AADNonInteractiveUserSignInLogs     | summarize LastEvent=max(TimeGenerated) | extend T="AADNonInteractiveUserSignInLogs"),
        (DeviceProcessEvents                 | summarize LastEvent=max(TimeGenerated) | extend T="DeviceProcessEvents"),
        (SecurityEvent                       | summarize LastEvent=max(TimeGenerated) | extend T="SecurityEvent")
    | project TableName=T, LastEvent
) on TableName
| project TableName, LastEvent, DataFreshness = iff(LastEvent > ago(24h), "OK", "STALE")
```

If a table returns no rows or `LastEvent` is older than 48 hours, do not deploy a rule against it — file a data connector gap ticket instead.

---

### Category routing — data source → subdirectory

| Data source / platform | Category directory |
|---|---|
| Windows Event Logs, Sysmon, MDE, PowerShell, WMI | `windows/` |
| Linux audit, syslog, auditd, journald | `linux/` |
| AWS CloudTrail, Azure Activity, GCP Audit, Office 365, Entra ID sign-in logs | `cloud/` |
| Active Directory, Azure AD / Entra ID, Okta, IAM, LDAP, Kerberos | `identity/` |
| Apache, IIS, Nginx, web application firewalls (WAF), HTTP access logs | `web/` |
| macOS unified log, FSEvents, OpenBSM | `macos/` |
| Application-specific logs: Bitbucket, Jira, Python, Java, custom app logs | `application/` |
| Firewall, router, switch, IDS/IPS, VPN, proxy, NetFlow, packet capture logs | `network/` |

**When a rule spans multiple categories** (e.g., Azure AD identity + cloud audit),
choose the most specific category. Identity takes precedence over cloud for
authentication events; windows takes precedence over application for Windows
app logs.

### File naming and sequence numbering

Every file in a category directory is prefixed with a zero-padded 3-digit
sequence number, followed by an underscore and a lowercase descriptive name.

**Pattern:** `{NNN}_{description}.{ext}`
- `{NNN}` — next available sequence number in that directory (001, 002, … 999)
- `{description}` — lowercase with underscores, no hyphens
- `{ext}` — `kql` for KQL, `spl` for SPL

**Examples:**
```
kql/windows/001_lsass_minidump_api.kql
kql/windows/002_handala_wiper_chain.kql
splunk/identity/001_kerberoasting_spn_enum.spl
splunk/web/001_apache_log4j_exploit.spl
```

### Determining the next sequence number

Before writing a new rule file, run:

```bash
python .claude/skills/detection-engineering/scripts/next-seq.py \
    kql/windows
# → 003   (if 001 and 002 already exist)
```

Then name the file `{result}_{description}.kql` (or `.spl`).

**Never reuse or skip sequence numbers.** If a rule file is deleted, the gap
remains — do not renumber existing files.

### Use case ID prefix convention

Every rule must carry a use case ID in its header comment. The prefix encodes
the platform or category and, where applicable, the specific product.

| Category | Prefix pattern | Example |
|---|---|---|
| Windows | `OS-DET-WIN-<rule_name>` | `OS-DET-WIN-001_lsass_minidump_api` |
| Active Directory | `OS-DET-AD-<rule_name>` | `OS-DET-AD-001_dcsync_non_dc` |
| Linux | `OS-DET-Linux-<rule_name>` | `OS-DET-Linux-001_ssh_brute_force` |
| macOS | `OS-DET-Mac-<rule_name>` | `OS-DET-Mac-001_launchagent_persistence` |
| Web | `Web-DET-<productname>-<rule_name>` | `Web-DET-Nginx-001_path_traversal` |
| Application | `App-DET-<productname>-<rule_name>` | `App-DET-Bitbucket-001_repo_mass_clone` |
| Network | `Network-DET-<productname>-<rule_name>` | `Network-DET-Palo-001_port_scan_outbound` |
| Cloud | `Cloud-DET-<productname>-<rule_name>` | `Cloud-DET-Azure-001_mfa_bypass` |
| Identity (non-AD) | `Identity-DET-<productname>-<rule_name>` | `Identity-DET-Okta-001_mfa_fatigue` |

**Distinguishing Windows from Active Directory:**
- Use `OS-DET-WIN-` for rules based on Windows host-level log sources
  (Sysmon, Security event logs, MDE process/file/registry events).
- Use `OS-DET-AD-` for rules based on Active Directory domain controller
  events (Security EID 4662, 4768, 4769, 4776, DCSync, replication traffic,
  LDAP queries, GPO changes). AD rules land in the `identity/` directory.

**Rules for `<productname>`:**
- Use the vendor or product short name in PascalCase: `Nginx`, `Apache`, `IIS`,
  `Palo`, `Fortinet`, `Cisco`, `Bitbucket`, `Jira`, `Python`, `Azure`, `AWS`.
- OS and AD prefixes already encode the platform — no product name needed.
- If a rule spans multiple products, use the primary log source product name.

**Where to place the use case ID:**
Add it as the first line of the rule file header comment block.

KQL example:
```kql
// Use case ID: OS-DET-WIN-001_lsass_minidump_api
// ATT&CK:      T1003.001 — LSASS Memory
// Severity:    high
```

```kql
// Use case ID: OS-DET-AD-001_dcsync_non_dc
// ATT&CK:      T1003.006 — DCSync
// Severity:    critical
```

SPL example:
```spl
`comment("Use case ID: Network-DET-Palo-001_port_scan_outbound")`
`comment("ATT&CK:      T1046 — Network Service Discovery")`
`comment("Severity:    medium")`
```

### Splunk Lookup Table Infrastructure

Before deploying SPL rules, create these five lookup CSV files in Splunk
(`Settings → Lookups → Lookup table files`). They are referenced by every
SPL rule template as the standard exclusion mechanism — equivalent to Sentinel
Watchlists. Without them, the lookup exclusions silently pass all events through.

#### Standard lookup files

| CSV filename | Key field | What to put in it | Rules that use it |
|---|---|---|---|
| `vpn_egress_ips.csv` | `ip` | VPN gateway exit IPs, ZTNA egress, corporate proxy IPs | Login anomaly, geo-based, network rules |
| `service_accounts.csv` | `account` | Service accounts, automation accounts, sync accounts | Every identity, sign-in, and process rule |
| `admin_workstations.csv` | `hostname` | PAW machines, jump hosts, bastion servers | Endpoint, lateral movement, credential access rules |
| `sanctioned_tools.csv` | `process_name` | Approved security/admin tool process names (lowercase) | Process creation, credential access, defense evasion rules |
| `high_value_assets.csv` | `hostname` | Domain controllers, CA servers, PAM servers, critical app servers | Severity graduation in all endpoint rules |

**Minimum CSV structure** (add columns as needed for your environment):

```csv
# vpn_egress_ips.csv
ip,description,last_updated
203.0.113.10,Corporate VPN gateway EU,2026-05-27
198.51.100.5,ZTNA egress node US-East,2026-05-27

# service_accounts.csv
account,description,owner,last_updated
svc_backup,Backup agent service account,IT Ops,2026-05-27
msol_abc123,Azure AD Connect sync account,Identity team,2026-05-27

# admin_workstations.csv
hostname,ip,description,last_updated
PAW-ADMIN01,10.1.0.10,Privileged Access Workstation,2026-05-27
JUMPHOST01,10.1.0.11,Jump server for DC access,2026-05-27

# sanctioned_tools.csv
process_name,description,approved_by,last_updated
psexec.exe,Sysinternals PsExec - approved for IT,CISO,2026-05-27
procdump.exe,Sysinternals ProcDump - approved for support,CISO,2026-05-27

# high_value_assets.csv
hostname,asset_type,criticality,last_updated
PRODDC01,Domain Controller,critical,2026-05-27
CASERVER01,Certificate Authority,critical,2026-05-27
```

**Verify a lookup is populated before deploying a rule that uses it:**
```spl
| inputlookup vpn_egress_ips.csv | stats count
| inputlookup service_accounts.csv | stats count
```

#### Standard SPL lookup exclusion patterns

```spl
`comment("── Lookup exclusions — remove blocks that don't apply to this rule ──")`

`comment("Exclude known VPN / proxy source IPs (login and network rules)")`
NOT [| inputlookup vpn_egress_ips.csv | rename ip AS src_ip | table src_ip]

`comment("Exclude service / automation accounts (identity and process rules)")`
NOT [| inputlookup service_accounts.csv | rename account AS user | table user]

`comment("Exclude admin workstations (endpoint and lateral movement rules)")`
NOT [| inputlookup admin_workstations.csv | rename hostname AS host | table host]

`comment("Exclude sanctioned security / admin tools (process rules)")`
NOT [| inputlookup sanctioned_tools.csv | rename process_name AS process | table process]

`comment("Severity amplifier — elevate if host is a high-value asset")`
| lookup high_value_assets.csv hostname AS host OUTPUT criticality AS asset_criticality
| eval severity = if(asset_criticality="critical" AND severity="high", "critical", severity)
```

#### Lookup exclusion decision checklist

For every FP source in the rule header, apply the same logic as for KQL watchlists:

```
Could this exclusion value change without a rule edit? → use lookup CSV
Is this a known-good IP, account, host, or tool?      → use lookup CSV
Is this a structural invariant (e.g. SYSTEM account)?  → hardcode is acceptable
```

---

### Custom Indexes (SPL)

Custom Splunk indexes are environment-specific and may not follow the standard
routing table. Before writing any rule against a custom index, its schema must
be documented in `references/custom-indexes/`. Without it, field names are
guesses and rules will silently match nothing or fire on the wrong events.

#### How to add a new custom index (process)

1. **Confirm the index exists and is ingesting**: run
   `| tstats count WHERE index="<index-pattern>" earliest=-24h by index, sourcetype | sort - count`
2. **Sample the data**: run `index="<index-pattern>" earliest=-1h | head 10`
   and `| fieldsummary maxvals=10` to enumerate real field names and values.
3. **Create the schema file**: copy
   `references/custom-indexes/_template.md` to
   `references/custom-indexes/<product_lower>.md` and fill in all sections
   from live query output. **Do not guess field names** — confirm each one
   against real events.
4. **Identify the use case prefix and SPL directory**: match the index's log
   category to the routing table above, then choose the corresponding
   directory under `splunk/<category>/`.
5. **Register the index here**: add a row to the table below and cross-link
   to the KQL custom table reference if one exists.

> **Note:** Splunk field names extracted by Add-ons or props/transforms do
> **not** use `_s` / `_d` type suffixes — those are KQL `_CL` table conventions.
> Always confirm exact field names and casing from your Add-on documentation or
> a live `| head 10` sample.

#### Registered custom indexes

| Index pattern | What it captures | Category | Schema reference | KQL counterpart |
|---|---|---|---|---|
| `*-pam` | Thycotic/Delinea Secret Server — privileged credential checkouts, secret access, PAM session launches, admin activity | `identity/` | [`references/custom-indexes/thycotic_pam.md`](references/custom-indexes/thycotic_pam.md) | [`references/custom-tables/thycotic_cl.md`](references/custom-tables/thycotic_cl.md) |
| <!-- *-<product> --> | <!-- description --> | <!-- category --> | <!-- references/custom-indexes/<product>.md --> | <!-- references/custom-tables/<table>_cl.md or N/A --> |

---

### SPL rule template

The template below is the canonical form for all SPL rules. Fill every header
field — blank fields are deployment blockers.

```spl
`comment("============================================================
Use case ID:  <prefix>-{NNN}_{description}
Rule:         {NNN}_{description}.spl
ATT&CK:       T1XXX.YYY — <technique name>
Severity:     low | medium | high | critical
Author:       <author>
Date:         YYYY-MM-DD

Type:         CorrelationSearch | SavedSearch
  CorrelationSearch  auto-creates notable event in Splunk ES; use when
                     high-confidence and fewer than 10 hits/day expected
  SavedSearch        analyst-reviewed report; use for new/noisy rules
                     during 2-week probation before promoting

Index:        <pattern from SPL index routing table>
  index=*-os-win     Windows Security Event Logs
  index=*-os-linux   Linux /var/log/ logs
  index=*-network    Network and security device syslog
  index=*-edr        MDE / EDR telemetry
  index=*-azure      Azure data sources (SignInLogs, AuditLogs, etc.)

Schedule:     cron=<expression>  e.g. cron=*/5 * * * *
Lookback:     earliest=-1h latest=now
Suppress:     <field>:<Xh>  e.g. user:4h

Prerequisite: <forwarder or data connector that must be active>

Lookup exclusions applied:
  [ ] vpn_egress_ips.csv      (IP-based rules)
  [ ] service_accounts.csv    (identity and process rules)
  [ ] admin_workstations.csv  (endpoint and lateral movement rules)
  [ ] sanctioned_tools.csv    (process creation rules)
  [ ] high_value_assets.csv   (severity graduation - all rules)
  Unchecked = not applicable; document why if unexpected.

False positives:
  - <concrete scenario 1>  mitigated by <lookup or filter>
  - <concrete scenario 2>  mitigated by <lookup or filter>
============================================================")`

`comment("── Core search ────────────────────────────────────────────────────")`
index="*-<category>" sourcetype=<sourcetype>
    earliest=-1h latest=now
    <field>=<value>

`comment("── Lookup exclusions (delete blocks that do not apply) ────────────")`
NOT [| inputlookup vpn_egress_ips.csv
     | rename ip AS src_ip | table src_ip]
NOT [| inputlookup service_accounts.csv
     | rename account AS user | table user]
NOT [| inputlookup admin_workstations.csv
     | rename hostname AS host | table host]
NOT [| inputlookup sanctioned_tools.csv
     | rename process_name AS process | table process]

`comment("── Structural exclusions (invariants — hardcode acceptable) ───────")`
NOT (user="SYSTEM" OR user="NT AUTHORITY\\SYSTEM" OR user="")

`comment("── High-value asset enrichment and severity amplifier ─────────────")`
| lookup high_value_assets.csv hostname AS host
    OUTPUT criticality AS asset_criticality
| eval severity=if(asset_criticality="critical" AND severity="high",
                   "critical", severity)

`comment("── [OPTIONAL] Identity enrichment — uncomment when CSV available ──")`
`comment("| lookup user_identity.csv account AS user                         ")`
`comment("    OUTPUT department, job_title, manager, mfa_registered          ")`

`comment("── [OPTIONAL] Baseline / first-occurrence detection ──────────────")`
`comment("| lookup baseline_summary.csv user AS user                         ")`
`comment("    OUTPUT earliest_seen AS baseline_first_seen                    ")`
`comment("| eval is_first_occurrence=if(isnull(baseline_first_seen), 1, 0)  ")`

`comment("── [OPTIONAL] Risk-Based Alerting (Splunk ES RBA) ────────────────")`
`comment("  Use for noisy signals: accumulate risk per entity across rules.  ")`
`comment("  Alert fires from risk_notable when entity score exceeds threshold")`
`comment("| eval risk_score=case(                                            ")`
`comment("    is_first_occurrence=1 AND asset_criticality=\"critical\", 75,  ")`
`comment("    is_first_occurrence=1, 50,                                     ")`
`comment("    asset_criticality=\"critical\", 40,                            ")`
`comment("    true(), 25)                                                    ")`
`comment("| eval risk_object=\"user\", risk_object_type=user                 ")`
`comment("| eval risk_message=\"<description of the risk>\"                  ")`
`comment("| collect index=risk_index sourcetype=stash_new                   ")`

`comment("── Rule metadata ──────────────────────────────────────────────────")`
| eval
    attck_technique = "T1XXX.YYY",
    rule_id         = "<prefix>-{NNN}_{description}",
    triage          = "1. <investigation step>. 2. <escalation step>."

`comment("── Deduplication: one row per entity, not one row per raw event ───")`
| stats
    min(_time)              AS first_seen
    max(_time)              AS last_seen
    count                   AS event_count
    values(<evidence_field>) AS evidence
    latest(severity)        AS severity
    latest(attck_technique) AS attck_technique
    latest(rule_id)         AS rule_id
    latest(triage)          AS triage
    latest(asset_criticality) AS asset_criticality
    by <entity_field>

`comment("── Output ─────────────────────────────────────────────────────────")`
| table
    severity, <entity_field>,
    first_seen, last_seen, event_count,
    evidence, asset_criticality,
    attck_technique, rule_id, triage
| sort - severity, - event_count
```

### Watchlist Infrastructure

Before deploying rules to production, create these five watchlists in Sentinel.
They are referenced by name in every rule template. Without them the watchlist
joins silently return empty sets and exclusions do not apply.

#### Standard watchlists

| Watchlist name | SearchKey field | What to put in it | Used by |
|---|---|---|---|
| `VPN-Egress-IPs` | IP address (CIDR or exact) | All VPN gateway exit IPs, ZTNA egress, corporate proxy IPs | Impossible travel, login anomaly, geo-based rules |
| `Service-Accounts` | UPN or sAMAccountName | Non-human accounts: service accounts, automation accounts, sync accounts (MSOL_*, AADConnect) | Every identity and sign-in rule |
| `Admin-Workstations` | Hostname or IP | PAW machines, jump hosts, bastion servers | NTLM, lateral movement, credential access rules |
| `High-Value-Assets` | Hostname or FQDN | Domain controllers, CA servers, PAM servers, crown-jewel app servers | Severity graduation in endpoint rules |
| `Sanctioned-Tools` | Process name (lowercase) | Approved security/admin tools: sysinternals, backup agents, RMM executables | Credential access, defense evasion, process rules |

#### Creating a watchlist (once per workspace)

```kql
// Verify a watchlist exists and has entries before relying on it
_GetWatchlist('VPN-Egress-IPs')
| summarize EntryCount = count()
// If EntryCount = 0, the watchlist is missing or empty — do not deploy the rule
```

Create via Sentinel portal: **Threat Management → Watchlists → New** or via ARM template.
Minimum required columns: `SearchKey` (the value the KQL joins on), `Description`, `LastUpdated`.

#### Standard watchlist join patterns

```kql
// ── Exclusion: single-value watchlist (IP, hostname, UPN) ────────────────────
let ExcludedVPNIPs = toscalar(
    _GetWatchlist('VPN-Egress-IPs') | summarize make_set(SearchKey));
let ExcludedServiceAccounts = toscalar(
    _GetWatchlist('Service-Accounts') | summarize make_set(SearchKey));
let ExcludedAdminHosts = toscalar(
    _GetWatchlist('Admin-Workstations') | summarize make_set(SearchKey));
let SanctionedTools = toscalar(
    _GetWatchlist('Sanctioned-Tools') | summarize make_set(SearchKey));

// Apply in the query:
| where IPAddress !in (ExcludedVPNIPs)
| where tolower(UserPrincipalName) !in (ExcludedServiceAccounts)
| where tolower(DeviceName) !in (ExcludedAdminHosts)
| where tolower(InitiatingProcessFileName) !in (SanctionedTools)

// ── Severity amplifier: high-value asset lookup ───────────────────────────────
let HighValueAssets = toscalar(
    _GetWatchlist('High-Value-Assets') | summarize make_set(SearchKey));

// Apply as a severity graduation signal:
| extend IsCriticalAsset = tolower(DeviceName) in (HighValueAssets)
| extend Severity = iff(IsCriticalAsset and Severity == "High", "Critical", Severity)
```

#### Watchlist exclusion decision checklist

For every FP source identified in the rule header, ask:

```
Could this exclusion value change without a code review?
  YES → use _GetWatchlist() join
  NO  → hardcode is acceptable (e.g. "NT AUTHORITY", machine account "$" suffix)

Is this a known-legitimate IP range, account, or tool?
  YES → use _GetWatchlist() join

Is this a one-off environment quirk you'd never see elsewhere?
  YES → document it in the rule header comment; consider a Watchlist entry anyway
```

---

### Rule Type Classification

Every KQL and SPL rule must declare its type in the header. This controls
whether it fires automatically (creating incidents / notable events) or returns
results for analyst review.

#### KQL — Sentinel / Defender XDR

| Type | Header value | Behaviour | Daily volume target | When to use |
|---|---|---|---|---|
| **Analytics Rule** | `// Type: AnalyticRule` | Creates Sentinel incident on every match | < 10 alerts/day | High-confidence; rare or binary activity; zero legitimate use |
| **Hunting Query** | `// Type: HuntingQuery` | Returns rows for analyst review; no incident | Unlimited during tuning | New rules in probation; anomaly/baseline detections; noisy signals |

#### SPL — Splunk / Splunk ES

| Type | Header value | Behaviour | Daily volume target | When to use |
|---|---|---|---|---|
| **Correlation Search** | `Type: CorrelationSearch` | Creates notable event in Splunk ES on every match | < 10 notables/day | High-confidence; binary activity; validated in SavedSearch first |
| **Saved Search** | `Type: SavedSearch` | Scheduled report; analyst reviews results | Unlimited during tuning | New rules in probation; noisy signals; RBA contributor rules |
| **RBA Contributor** | `Type: CorrelationSearch` + RBA block | Adds risk score to entity; no direct notable | Unlimited | Signals that are weak alone but corroborating with others |

**RBA (Risk-Based Alerting) in Splunk ES** accumulates risk scores on entities
(user, host, IP) across multiple contributing rules. A single `risk_notable`
fires only when the entity's cumulative score crosses a threshold. Use this
pattern for any rule that fires > 10 times/day — it reduces notable event volume
while preserving signal fidelity.

---

#### Promotion path (both platforms)

```
1. Write as HuntingQuery (KQL) or SavedSearch (SPL)
2. Run for 2 weeks in production
3. Review daily result volume and TP rate:
      < 10 rows/day  AND  > 80% TP rate → promote to AnalyticRule / CorrelationSearch
      > 10 rows/day  OR   < 80% TP rate → tune exclusions / raise thresholds, repeat
4. After promotion, set suppression to prevent re-alerting on the same entity
   within a reasonable window (2h–4h for most identity/endpoint rules)
```

Never deploy a new rule directly to `AnalyticRule` / `CorrelationSearch` without
a hunting / SavedSearch validation period **unless** the technique has zero
legitimate use in any environment (e.g. DCSync from a user account, impossible
travel in < 10 minutes with elevated risk score, wiper chain with 4+ TTPs).

---

#### Rule type decision guide (applies to both platforms)

```
Does this activity have ANY legitimate use in your environment?
  NO  → AnalyticRule / CorrelationSearch immediately
  YES → HuntingQuery / SavedSearch first, then evaluate

Would a single match always require analyst action?
  YES → AnalyticRule / CorrelationSearch
  NO  → HuntingQuery / SavedSearch

Does the rule fire on volume thresholds (> N events)?
  YES → HuntingQuery / SavedSearch until threshold validated in production
  NO  → AnalyticRule / CorrelationSearch candidate

Is this a new index / table / data source not monitored before?
  YES → HuntingQuery / SavedSearch for 30 days minimum
  NO  → proceed with normal 2-week probation

Is the signal weak alone but meaningful when combined with other signals?
  YES (KQL)  → use risk scoring block in the KQL template
  YES (SPL)  → use RBA contributor pattern; feed risk_index not notable_index
```

---

### KQL rule template

The template below is the canonical form for all KQL rules. Fill every header
field — blank fields are deployment blockers.

```kql
// ============================================================
// Use case ID:  <prefix>-{NNN}_{description}
// Rule:         {NNN}_{description}.kql
// ATT&CK:       T1XXX.YYY — <technique name>
// Severity:     low | medium | high | critical
// Author:       <author>
// Date:         YYYY-MM-DD
//
// Type:         AnalyticRule | HuntingQuery
//   AnalyticRule  → auto-creates incident on every match; < 10 alerts/day expected
//   HuntingQuery  → analyst-reviewed; use until < 10 rows/day confirmed in production
//
// Target:       Sentinel | DefenderXDR | Both
//   • Sentinel    → TimeGenerated; Sentinel-only tables (SigninLogs, SecurityEvent, etc.)
//   • DefenderXDR → Timestamp; XDR Advanced Hunting tables (Device*, Identity*)
//   • Both        → TimeGenerated; avoid tables absent from one console
//
// Schedule:     every <Xm|Xh>        (AnalyticRule only)
// Lookback:     <Xh|Xd>              (must be ≥ Schedule interval)
// Suppress:     none | <field>:<Xh>  (e.g. AccountName:4h)
//
// Prerequisite: <data connector that must be enabled>
//
// Watchlist exclusions applied:
//   [ ] VPN-Egress-IPs       (IP-based rules)
//   [ ] Service-Accounts     (identity/sign-in rules)
//   [ ] Admin-Workstations   (endpoint/lateral movement rules)
//   [ ] Sanctioned-Tools     (process-based rules)
//   [ ] High-Value-Assets    (severity graduation)
//   Unchecked = not applicable for this rule type; document why if unexpected.
//
// False positives:
//   - <concrete scenario 1> → mitigated by <watchlist or filter>
//   - <concrete scenario 2> → mitigated by <watchlist or filter>
// ============================================================

// ── Watchlist exclusions (remove blocks that don't apply to this rule) ────────
let ExcludedVPNIPs = toscalar(
    _GetWatchlist('VPN-Egress-IPs')
    | summarize make_set(SearchKey));
let ExcludedServiceAccounts = toscalar(
    _GetWatchlist('Service-Accounts')
    | summarize make_set(tolower(SearchKey)));
let ExcludedAdminHosts = toscalar(
    _GetWatchlist('Admin-Workstations')
    | summarize make_set(tolower(SearchKey)));
let SanctionedTools = toscalar(
    _GetWatchlist('Sanctioned-Tools')
    | summarize make_set(tolower(SearchKey)));
let HighValueAssets = toscalar(
    _GetWatchlist('High-Value-Assets')
    | summarize make_set(tolower(SearchKey)));

// ── Base query ────────────────────────────────────────────────────────────────
<LogSource>
| where TimeGenerated > ago(<Lookback>)   // swap to Timestamp for DefenderXDR target
// --- core behavior ---
| where <field> <operator> <value>
// --- watchlist exclusions ---
| where IPAddress !in (ExcludedVPNIPs)
| where tolower(UserPrincipalName) !in (ExcludedServiceAccounts)
| where tolower(DeviceName) !in (ExcludedAdminHosts)
| where tolower(InitiatingProcessFileName) !in (SanctionedTools)
// --- structural exclusions (invariants — hardcode acceptable) ---
| where not(AccountName endswith "$")           // machine accounts
| where AccountDomain !in~ ("NT AUTHORITY", "WINDOW MANAGER", "Font Driver Host")

// ── [OPTIONAL] Entity enrichment — uncomment when IdentityInfo is available ──
// | join kind=leftouter (
//     IdentityInfo
//     | where TimeGenerated > ago(7d)
//     | summarize arg_max(TimeGenerated, *) by AccountObjectId
//     | project AccountObjectId, JobTitle, Department,
//               Manager = ManagerDisplayName, IsMFARegistered,
//               AssignedRoles, IsAccountEnabled
// ) on AccountObjectId

// ── [OPTIONAL] Baseline comparison — uncomment for anomaly-based rules ────────
// Compares current event count against a 30-day rolling baseline for the same entity.
// IsFirstOccurrence = true is a strong high-confidence signal.
// | join kind=leftouter (
//     <LogSource>
//     | where TimeGenerated between (ago(30d) .. ago(1h))
//     | where <same_core_behavior_filter>
//     | summarize BaselineCount = count() by <entity_field>
// ) on <entity_field>
// | extend IsFirstOccurrence = isempty(BaselineCount) or BaselineCount == 0

// ── [OPTIONAL] Risk scoring — uncomment to replace binary threshold with score ─
// Add one point per corroborating signal. Alert only when score ≥ threshold.
// | extend
//     Score_AfterHours  = iff(hourofday(TimeGenerated) !between (7 .. 19), 2, 0),
//     Score_Weekend     = iff(dayofweek(TimeGenerated) in (0d, 6d), 1, 0),
//     Score_HighRisk    = iff(RiskLevelDuringSignIn in ("high","medium"), 3, 0),
//     Score_NewSource   = iff(IsFirstOccurrence == true, 3, 0),
//     Score_CritAsset   = iff(tolower(DeviceName) in (HighValueAssets), 2, 0)
// | extend TotalScore = Score_AfterHours + Score_Weekend + Score_HighRisk
//                     + Score_NewSource + Score_CritAsset
// | where TotalScore >= 4   // tune threshold; raise to reduce FPs
// | extend Severity = case(TotalScore >= 7, "Critical",
//                          TotalScore >= 4, "High", "Medium")

// ── Severity graduation: high-value asset amplifier ──────────────────────────
| extend IsCriticalAsset = tolower(DeviceName) in (HighValueAssets)
| extend Severity = case(
    IsCriticalAsset, "Critical",
    "<other_condition>", "High",
    "<level>"
)

// ── Rule metadata ─────────────────────────────────────────────────────────────
| extend
    ATT_CK  = "T1XXX.YYY",
    RuleID  = "<prefix>-{NNN}_{description}",
    Triage  = strcat(
        "1. Confirm <entity> is not excluded by watchlist. ",
        "2. <investigation step>. ",
        "3. <escalation step>."
    )

// ── Entity fields ─────────────────────────────────────────────────────────────
// Account entity: AccountName + AccountDomain (Sentinel) | AccountObjectId (XDR)
// Host entity:    Computer or DeviceName
// IP entity:      IPAddress
| extend
    AccountName   = tostring(split(<upn_or_account_field>, "@")[0]),
    AccountDomain = tostring(split(<upn_or_account_field>, "@")[1])

// ── Deduplication — one alert row per entity, not one row per raw event ───────
// Always summarize before the final project. One account/host generating 50 events
// must produce ONE alert row. Use arg_max to surface the most recent event's fields.
| summarize
    FirstSeen    = min(TimeGenerated),
    LastSeen     = max(TimeGenerated),
    EventCount   = count(),
    arg_max(TimeGenerated, *)          // pulls all columns from the most recent event
    by AccountName, AccountDomain      // group key = the alerting entity

// ── Output ────────────────────────────────────────────────────────────────────
| project
    Severity,
    // --- identity ---
    AccountName,
    AccountDomain,
    // --- host ---
    Computer,           // or DeviceName for MDE tables
    // --- network ---
    IPAddress,
    // --- timing ---
    FirstSeen,
    LastSeen,
    EventCount,
    // --- evidence ---
    <key_fields>,
    // --- enrichment (uncomment when joins are active) ---
    // JobTitle, Department, Manager, IsMFARegistered, AssignedRoles,
    // IsFirstOccurrence, BaselineCount,
    IsCriticalAsset,
    // --- rule metadata ---
    ATT_CK,
    RuleID,
    Triage
| sort by Severity asc, LastSeen desc
```

#### Entity field mapping cheat-sheet

| Alert type | Sentinel entity type | Required columns | Defender XDR required column |
|---|---|---|---|
| User account alert | Account | `AccountName` + `AccountDomain` (or `AccountUPN`) | `AccountObjectId` or `AccountSid` |
| Host / endpoint alert | Host | `Computer` or `HostName` | `DeviceName` or `DeviceId` |
| IP-based alert | IP | `IPAddress` | `IPAddress` (for enrichment only) |
| URL / domain alert | URL | `Url` | `Url` |
| MDE process/file alert | Host + Process | `DeviceName` + `FileName` + `ProcessCommandLine` | `ReportId` + `DeviceName` |
| Email alert | Mailbox + Account | `RecipientEmailAddress` | `NetworkMessageId` |

**Sentinel entity mapping rule:** After writing the query, open the Analytics Rule wizard → "Set rule logic" → "Alert enrichment" → "Entity mapping". Map each `extend`-ed column to its entity type. Without this step the alert creates no entities and SOC analysts cannot click-pivot from the incident.

**Defender XDR custom detection rule:** The query result **must** include `Timestamp`, `ReportId` (for MDE rules), and at least one of `DeviceName` / `AccountObjectId`. Rules that fail this schema check are rejected by the portal with no alert generated.

---

## Microsoft Sentinel — Table and Connector Reference

Use this section to identify the correct KQL table before writing any Sentinel rule.
Source: https://learn.microsoft.com/en-us/azure/sentinel/sentinel-tables-connectors-reference

### Azure AD / Entra ID (Identity)

| Table | What it captures | Connector |
|---|---|---|
| `SigninLogs` | Interactive user sign-ins | Microsoft Entra ID |
| `AADNonInteractiveUserSignInLogs` | Non-interactive sign-ins (app token refreshes, background auth) | Microsoft Entra ID |
| `AADServicePrincipalSignInLogs` | Service principal and managed identity sign-ins | Microsoft Entra ID |
| `AADManagedIdentitySignInLogs` | Managed identity sign-ins | Microsoft Entra ID |
| `ADFSSignInLogs` | AD FS sign-in events | Microsoft Entra ID |
| `AuditLogs` | Azure AD directory changes (user/group/app/role changes) | Microsoft Entra ID |
| `AADProvisioningLogs` | User provisioning and de-provisioning | Microsoft Entra ID |
| `AADRiskyUsers` | Accounts flagged as risky by Identity Protection | Microsoft Entra ID |
| `AADRiskyServicePrincipals` | Service principals flagged as risky | Microsoft Entra ID |
| `AADUserRiskEvents` | Risk detections on user accounts | Microsoft Entra ID |
| `AADServicePrincipalRiskEvents` | Risk detections on service principals | Microsoft Entra ID |
| `NetworkAccessTraffic` | Microsoft Entra Internet Access / Private Access traffic | Microsoft Entra ID |

**When to use which sign-in table:**
- Human login alerts → `SigninLogs`
- App-to-app / daemon auth → `AADServicePrincipalSignInLogs`
- Token refresh / silent auth → `AADNonInteractiveUserSignInLogs`
- On-prem AD FS federation → `ADFSSignInLogs`
- All four combined → `union SigninLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs, AADManagedIdentitySignInLogs`

---

### Windows Host & Security Events

| Table | What it captures | Connector |
|---|---|---|
| `SecurityEvent` | Windows Security Event Log (EID 4xxx, 5xxx) — logon, privilege, account, object access | Windows Security Events via AMA |
| `WindowsEvent` | All Windows event channels forwarded via WEF | Windows Forwarded Events |
| `Event` | Windows events ingested via legacy MMA agent | Windows Events (legacy) |

---

### Microsoft Defender for Endpoint (MDE / XDR)

| Table | What it captures | Connector |
|---|---|---|
| `DeviceProcessEvents` | Process creation and termination on endpoints | Microsoft Defender XDR |
| `DeviceNetworkEvents` | Network connections from endpoints | Microsoft Defender XDR |
| `DeviceFileEvents` | File creation, modification, deletion on endpoints | Microsoft Defender XDR |
| `DeviceRegistryEvents` | Registry key and value changes | Microsoft Defender XDR |
| `DeviceLogonEvents` | Logon events on endpoints | Microsoft Defender XDR |
| `DeviceImageLoadEvents` | DLL/image load events | Microsoft Defender XDR |
| `DeviceEvents` | Miscellaneous endpoint events (WMI, scheduled tasks, raw I/O) | Microsoft Defender XDR |
| `AlertEvidence` | Evidence artifacts linked to Defender alerts | Microsoft Defender XDR |
| `CloudAppEvents` | Cloud app activity (via Defender for Cloud Apps) | Microsoft Defender XDR |
| `EmailEvents` | Email send/receive events (via Defender for Office 365) | Microsoft Defender XDR |
| `IdentityLogonEvents` | Identity logon events (via Defender for Identity) | Microsoft Defender XDR |
| `SecurityAlert` | Alerts from Defender for Endpoint, Defender for Identity, Entra ID Protection, and others | Multiple Defender connectors |
| `SecurityIncident` | Incidents created from correlated alerts | Microsoft Defender XDR |

---

### Defender XDR Identity Tables (Advanced Hunting)

These tables are available in **both** Defender XDR Advanced Hunting and Microsoft Sentinel (when the Defender XDR connector is enabled). They are the primary data source for Active Directory and identity-based detections — use them instead of `SecurityEvent` when the Defender for Identity sensor is deployed.

| Table | What it captures | Key fields | When to use |
|---|---|---|---|
| `IdentityInfo` | Account properties snapshot — SAMAccountName, UPN, department, manager, MFA registration, on-prem sync status, group memberships | `AccountObjectId`, `AccountName`, `AccountDomain`, `IsAccountEnabled`, `IsMFARegistered`, `JobTitle`, `Department` | Enrich alerts with account context; detect high-privilege accounts; hunt for accounts missing MFA |
| `IdentityLogonEvents` | Logon events on endpoints AND domain controllers (broader than `DeviceLogonEvents`) — includes NTLM, Kerberos, LDAP bind | `AccountName`, `AccountDomain`, `DeviceName`, `LogonType`, `Protocol`, `FailureReason`, `IPAddress`, `DestinationPort` | Pass-the-hash, pass-the-ticket, NTLM relay, brute force against DCs |
| `IdentityQueryEvents` | LDAP and Kerberos queries — includes recon queries against AD | `AccountName`, `QueryType`, `QueryTarget`, `Protocol`, `IPAddress`, `DeviceName` | AD reconnaissance (BloodHound-style LDAP queries), SPN enumeration, user/group enumeration |
| `IdentityDirectoryEvents` | Active Directory directory changes — password resets, group changes, account creation/deletion, DCSync, GPO modification | `AccountName`, `ActionType`, `TargetAccountDisplayName`, `TargetDeviceName`, `AdditionalFields` | DCSync detection, privilege escalation via group membership, GPO abuse, account manipulation |

**Key `ActionType` values for `IdentityDirectoryEvents`:**

| ActionType | ATT&CK | What it means |
|---|---|---|
| `DirectoryServicesReplication` | T1003.006 | DCSync — DRSUAPI replication pull from non-DC |
| `SensitiveGroupModification` | T1098 | User added to Domain Admins, Enterprise Admins, etc. |
| `UserAccountModification` | T1098.001 | Password reset, account enable/disable |
| `UserAccountCreation` | T1136.001 | New local or domain account created |
| `PasswordResetAttempt` | T1078 | Password reset (may indicate account takeover) |
| `GroupModification` | T1098 | Non-sensitive group membership change |
| `ServiceAccountModification` | T1098 | Service account attribute changed |

**Key `Protocol` values for `IdentityLogonEvents`:**

| Protocol | What it means | Detection relevance |
|---|---|---|
| `Kerberos` | Kerberos ticket auth | Pass-the-ticket, Kerberoasting (TGS requests) |
| `NTLM` | Challenge-response auth | Pass-the-hash, NTLM relay |
| `Ldap` | LDAP bind authentication | LDAP brute force, anonymous bind abuse |
| `Radius` | RADIUS auth (VPN/Wi-Fi) | VPN credential spray |

**Example — detect DCSync using `IdentityDirectoryEvents`:**
```kql
IdentityDirectoryEvents
| where Timestamp > ago(1d)
| where ActionType == "DirectoryServicesReplication"
| join kind=leftouter (
    IdentityInfo | project AccountObjectId, IsDCAccount = AccountName
) on $left.AccountObjectId == $right.AccountObjectId
| where isempty(IsDCAccount)   // exclude legitimate DC-to-DC replication
| project Timestamp, AccountName, AccountDomain, DeviceName, IPAddress, ActionType
```

**Example — AD user and group enumeration via LDAP (BloodHound/SharpHound recon):**
```kql
IdentityQueryEvents
| where Timestamp > ago(1h)
| where Protocol == "Ldap"
| where QueryType in ("AllUsers", "AllGroups", "AllAdminGroups", "AllComputers", "AllAdminMembers")
| summarize
    QueryCount = count(),
    QueryTypes = make_set(QueryType),
    FirstQuery = min(Timestamp),
    LastQuery  = max(Timestamp)
    by AccountName, AccountDomain, IPAddress, DeviceName
| where QueryCount > 10
| extend ATT_CK = "T1069.002,T1087.002"
```

---

### Azure Platform & Services

| Table | What it captures | Connector |
|---|---|---|
| `AzureActivity` | Azure control-plane operations (resource create/delete/modify, RBAC changes) | Azure Activity |
| `AzureDiagnostics` | Diagnostic logs from many Azure resources (Key Vault, AKS, SQL, App Gateway, etc.) | Multiple Azure resource connectors |
| `AzureMetrics` | Performance metrics from Azure resources | Azure Storage Account |
| `StorageBlobLogs` | Azure Blob Storage read/write/delete operations | Azure Storage Account |
| `StorageFileLogs` | Azure File Storage operations | Azure Storage Account |
| `StorageQueueLogs` | Azure Queue Storage operations | Azure Storage Account |
| `StorageTableLogs` | Azure Table Storage operations | Azure Storage Account |

---

### Azure Firewall

| Table | What it captures | Connector |
|---|---|---|
| `AZFWApplicationRule` | Application (L7) rule matches | Azure Firewall |
| `AZFWNetworkRule` | Network (L3/L4) rule matches | Azure Firewall |
| `AZFWNatRule` | DNAT/SNAT rule hits | Azure Firewall |
| `AZFWThreatIntel` | Threat intelligence-based blocks | Azure Firewall |
| `AZFWIdpsSignature` | IDPS signature matches | Azure Firewall |
| `AZFWDnsQuery` | DNS proxy query logs | Azure Firewall |
| `AZFWFlowTrace` | Full flow trace data | Azure Firewall |

---

### Network & DNS

| Table | What it captures | Connector |
|---|---|---|
| `CommonSecurityLog` | CEF-formatted logs from network/security devices (Cisco ASA/FTD, Palo Alto NGFW, Fortinet, Check Point, Infoblox, etc.) | Syslog/CEF connectors |
| `Syslog` | Plain syslog messages from Linux hosts and network devices | Syslog via AMA |
| `DnsEvents` | DNS query and response events | Windows DNS / Linux DNS |
| `DnsInventory` | DNS zone and record inventory | DNS |
| `ASimDnsActivityLogs` | ASIM-normalized DNS activity across all DNS sources | Windows DNS Events via AMA |
| `ASimNetworkSessionLogs` | ASIM-normalized network sessions | Multiple (Cisco Meraki, etc.) |

---

### Microsoft 365 / Office 365

| Table | What it captures | Connector |
|---|---|---|
| `OfficeActivity` | SharePoint, Exchange, Teams, OneDrive user operations | Microsoft 365 |

---

### Amazon Web Services (AWS)

| Table | What it captures | Connector |
|---|---|---|
| `AWSCloudTrail` | API calls across all AWS services | AWS S3 |
| `AWSGuardDuty` | GuardDuty threat findings | AWS S3 |
| `AWSVPCFlow` | VPC network flow logs | AWS S3 |
| `AWSWAF` | AWS WAF allow/block decisions | AWS S3 |
| `AWSSecurityHubFindings` | Security Hub aggregated findings | AWS Security Hub |
| `AWSNetworkFirewallFlow` | AWS Network Firewall flow logs | AWS Network Firewall |
| `AWSRoute53Resolver` | Route53 DNS resolver logs | AWS S3 DNS Route53 |

---

### Google Cloud Platform (GCP)

| Table | What it captures | Connector |
|---|---|---|
| `GCPAuditLogs` | GCP admin activity and data access audit logs | GCP Pub/Sub |
| `GCPVPCFlow` | VPC network flow logs | GCP Pub/Sub |
| `GKEAudit` | Google Kubernetes Engine audit logs | Google Kubernetes Engine |
| `GoogleCloudSCC` | Security Command Center findings | Google SCC |
| `GoogleWorkspaceReports` | Gmail, Drive, Admin, Login activity | Google Workspace |
| `GCPDNS` | Cloud DNS query logs | GCP |
| `GCPIAM` | IAM policy change logs | GCP |

---

### Threat Intelligence

| Table | What it captures | Connector |
|---|---|---|
| `ThreatIntelligenceIndicator` | IOCs from TAXII feeds, MISP, Microsoft Defender TI, GreyNoise | Multiple TI connectors |
| `ThreatIntelIndicators` | Threat indicators from CrowdStrike Falcon | CrowdStrike Falcon Adversary Intelligence |

---

### Third-Party Identity Providers (IdP)

| Table | What it captures | Connector |
|---|---|---|
| `Okta_CL` / `OktaV2_CL` | Okta SSO and MFA logs | Okta Single Sign-On |
| `Auth0Logs_CL` | Auth0 authentication and user events | Auth0 |
| `OneLoginEventsV2_CL` | OneLogin IAM events | OneLogin IAM Platform |
| `CyberArk_AuditEvents_CL` | CyberArk PAM audit trail | CyberArk Audit |
| `SailPointIDN_Events_CL` | SailPoint IdentityNow events | SailPoint IdentityNow |

---

### Custom Tables (`_CL`)

Custom Log tables are environment-specific and not publicly documented. Before
writing any rule against a `_CL` table, a schema reference file **must** exist in
`references/custom-tables/`. Without it, field names are guesses and rules will
silently return no results.

#### How to add a new custom table (process)

1. **Extract schema** from the live workspace:
   ```kql
   YourTable_CL | getschema
   YourTable_CL | take 10
   ```
2. **Determine category and routing** using the category routing table above.
3. **Create a schema reference file** at
   `references/custom-tables/<tablename_lower>.md` using the skeleton template
   (see `thycotic_cl.md` as the canonical example).
4. **Add the table** to the appropriate section in this file and to the
   Quick-Reference table below.
5. **Fill in** the field reference, EventType values, and at least two detection
   patterns in the reference file before writing the first rule.

#### Registered custom tables

| Table | What it captures | Category | Schema reference |
|---|---|---|---|
| `Thycotic_CL` | Thycotic/Delinea Secret Server — privileged credential checkouts, secret access, PAM session launches, admin activity | `identity/` | [`references/custom-tables/thycotic_cl.md`](references/custom-tables/thycotic_cl.md) |
| <!-- YourTable_CL --> | <!-- description --> | <!-- category --> | <!-- references/custom-tables/yourtable_cl.md --> |

---

### Third-Party Endpoint Security

| Table | What it captures | Connector |
|---|---|---|
| `CrowdStrikeAlerts` | CrowdStrike Falcon alerts | CrowdStrike API |
| `SentinelOneAlerts_CL` | SentinelOne threat detections | SentinelOne |
| `CarbonBlackEvents_CL` | VMware Carbon Black endpoint events | VMware Carbon Black Cloud |

---

### Cloud Security Posture (CSPM)

| Table | What it captures | Connector |
|---|---|---|
| `PaloAltoPrismaCloudAlertV2_CL` | Prisma Cloud misconfigurations and threats | Palo Alto Prisma Cloud CSPM |
| `WizIssues_CL` / `WizIssuesV2_CL` | Wiz security issues | Wiz |
| `WizAuditLogs_CL` / `WizAuditLogsV2_CL` | Wiz audit logs | Wiz |
| `OrcaAlerts_CL` | Orca Security cloud risk alerts | Orca Security |

---

### Microsoft Power Platform & Business Apps

| Table | What it captures | Connector |
|---|---|---|
| `PowerPlatformAdminActivity` | Power Platform admin operations | Microsoft Power Platform Admin Activity |
| `PowerAutomateActivity` | Power Automate flow runs | Microsoft Power Automate |
| `PowerBIActivity` | Power BI workspace activity | Microsoft PowerBI |
| `Dynamics365Activity` | Dynamics 365 CRM/ERP activity | Dynamics365 |
| `DataverseActivity` | Microsoft Dataverse API calls | Microsoft Dataverse |

---

### ASIM (Advanced SIEM Information Model) Normalized Tables

ASIM tables normalize events across different source vendors into a common schema. Prefer ASIM tables when writing rules that must work across multiple data sources.

| ASIM Table | Covers |
|---|---|
| `ASimAuditEventLogs` | Audit events from any source |
| `ASimAuthenticationEventLogs` | Authentication events from any source |
| `ASimDnsActivityLogs` | DNS queries from any DNS source |
| `ASimNetworkSessionLogs` | Network sessions from any source |
| `ASimProcessEventLogs` | Process creation from any endpoint source |
| `ASimFileEventLogs` | File events from any source |
| `ASimRegistryEventLogs` | Registry changes from any source |
| `ASimWebSessionLogs` | Web sessions from proxies and WAFs |

**ASIM union pattern** — query all sources at once:
```kql
ASimAuthenticationEventLogs
| where TimeGenerated > ago(1d)
| where EventResult == "Failure"
```

---

### Table Selection Quick-Reference

| Scenario | Table(s) |
|---|---|
| Azure AD user sign-in anomaly | `SigninLogs` |
| App/service principal abuse | `AADServicePrincipalSignInLogs` |
| Azure resource change (RBAC, policy, delete) | `AzureActivity` |
| Key Vault secret access | `AzureDiagnostics` (where ResourceType == "VAULTS") |
| Windows privilege escalation / logon | `SecurityEvent` |
| Endpoint process / file / registry / network | `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceNetworkEvents` |
| Network device allow/deny (Cisco, Palo, Fortinet) | `CommonSecurityLog` |
| Linux syslog (SSH, cron, auth) | `Syslog` |
| DNS abuse / tunneling | `DnsEvents` or `ASimDnsActivityLogs` |
| AWS API abuse | `AWSCloudTrail` |
| GCP admin activity | `GCPAuditLogs` |
| Microsoft 365 data exfiltration | `OfficeActivity` |
| Okta MFA fatigue / account takeover | `Okta_CL` or `OktaV2_CL` |
| Threat intel IOC matching | `ThreatIntelligenceIndicator` |
| Impossible travel / risky user | `SigninLogs` + `AADRiskyUsers` |
| Email phishing / BEC | `EmailEvents` (via Defender for Office 365) |
| Cloud app shadow IT / anomaly | `CloudAppEvents` |
| PAM privileged credential access / session (KQL) | `Thycotic_CL` — see `references/custom-tables/thycotic_cl.md` for schema |
| PAM privileged credential access / session (SPL) | `index="*-pam"` sourcetype `thycotic:secretserver` — see `references/custom-indexes/thycotic_pam.md` for schema |

---

## References

When writing rules, consult:
- `references/example-rules/` - Well-formatted examples to follow
- `references/severity-guide.md` - Severity level guidance
- `references/false-positive-patterns.md` - Common FP documentation
- `references/custom-tables/` - KQL `_CL` table schemas (environment-specific)
- `references/custom-indexes/` - Splunk custom index schemas (environment-specific)
  - `references/custom-indexes/_template.md` - blank template for new indexes
  - `references/custom-indexes/thycotic_pam.md` - Thycotic Secret Server (`*-pam`)
- SigmaHQ category reference: https://github.com/SigmaHQ/sigma/tree/master/rules
- Microsoft Sentinel tables reference: https://learn.microsoft.com/en-us/azure/sentinel/sentinel-tables-connectors-reference
