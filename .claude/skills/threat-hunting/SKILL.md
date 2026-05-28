---
name: threat-hunting
description: |
  Threat hunting methodology and query development. Activate when
  forming hunt hypotheses, developing hunting queries (KQL, SPL, Sigma),
  analyzing data for attacker TTPs, or converting hunt findings into
  detection rules.
---

# Threat Hunting Methodology

## Trigger

Use this skill when:
- Forming or validating a hunt hypothesis against ATT&CK techniques
- Developing hunting queries in KQL, SPL, EQL, or Sigma
- Analyzing log data for attacker TTPs without a prior alert
- Identifying detection coverage gaps through proactive hunting
- Converting confirmed hunt findings into production detection rules
- Planning or scoping a hunting campaign

---

## Hunting Principles

1. **Hypothesis first, data second** — Never start querying without a written
   hypothesis. "Let me look at process creation logs" is not a hunt; it is log browsing.

2. **ATT&CK technique drives the hypothesis** — Every hunt targets a specific
   technique or sub-technique. Tactic-level hunts are too broad to be actionable.

3. **Define true/false positive criteria before querying** — Know what a hit looks
   like and what benign activity will generate noise before you run the query.

4. **Absence of evidence is not evidence of absence** — A clean hunt result means
   either the technique is not present or your data sources do not cover it. Distinguish
   these cases explicitly.

5. **Every confirmed finding becomes a detection rule** — A hunt that produces
   a true positive but no rule is an incomplete hunt.

---

## Hunt Lifecycle

```
Hypothesis → Data Source Mapping → Query Development → Analysis → Findings → Rule Creation
```

---

## Phase 1 — Hypothesis Formation

**A valid hunt hypothesis must answer all four questions:**

1. **What technique?** — ATT&CK technique ID and name (e.g., T1059.001 — PowerShell)
2. **What behavior?** — Specific observable action (e.g., base64-encoded commands in PowerShell ScriptBlock logs)
3. **What data source?** — Log source and field names (e.g., Windows Event ID 4104, ScriptBlockText)
4. **What is the expected attacker pattern vs. benign pattern?** — Concrete distinguishing criteria

**Hypothesis template:**
```
Technique:     T1XXX.YYY — <name>
Behavior:      <specific action the attacker takes>
Data source:   <log source, event ID, field names>
Attacker IOB:  <what a malicious hit looks like>
Benign noise:  <what legitimate activity looks like — how to distinguish>
Hunt period:   <time range to query>
```

**Reject a hypothesis if:**
- It targets a tactic, not a technique
- The data source does not exist or is not ingested
- You cannot articulate the difference between a hit and benign noise

---

## Phase 2 — Data Source Mapping

Before writing a query, confirm the data source is available and covers the technique.

**ATT&CK data source → log source mapping:**

| ATT&CK data source | Windows log source | Field examples |
|---|---|---|
| Process creation | Sysmon EID 1 / Security EID 4688 | Image, CommandLine, ParentImage |
| Network connections | Sysmon EID 3 / Firewall | DestinationIp, DestinationPort |
| File creation | Sysmon EID 11 | TargetFilename |
| Registry modification | Sysmon EID 12/13 | TargetObject, Details |
| Process access | Sysmon EID 10 | TargetImage, GrantedAccess, CallTrace |
| DNS queries | Sysmon EID 22 | QueryName, QueryResults |
| Scheduled task | Security EID 4698 | TaskName, TaskContent |
| Script block logging | PowerShell EID 4104 | ScriptBlockText |
| Authentication | Security EID 4624/4625 | LogonType, SubjectUserName |
| LDAP queries | AD EID 1644 / Sysmon | QueryFilter |

**Coverage check:** If the required log source is not available, document the gap
and stop. Do not hunt with a substitute data source without updating the hypothesis.

---

## Phase 3 — Query Development

### Query quality standards

- **Specificity over sensitivity** — A query returning 10 true positives and 5 FPs
  is better than one returning 100 hits with 95 FPs.
- **Bounded time ranges** — Always scope queries to a specific hunt period.
- **Field-level precision** — Filter on specific fields, not full-text search where possible.
- **Comment your logic** — Every filter clause should have a comment explaining why.

### Query structure template (KQL)

```kql
// Hypothesis: <technique ID> — <behavior>
// Expected hit: <what a TP looks like>
// Expected noise: <what FPs look like and how they are filtered>
<LogSource>
| where TimeGenerated between (datetime(YYYY-MM-DD) .. datetime(YYYY-MM-DD))
// --- Technique-specific filters ---
| where <field> <operator> <value>          // core behavior
| where <field> !in~ (<benign_values>)     // noise reduction
// --- Enrichment ---
| extend ATT_CK = "T1XXX.YYY"
| project TimeGenerated, Computer, AccountName, <key_fields>, ATT_CK
| sort by TimeGenerated asc
```

### Query structure template (SPL)

```spl
`comment("Hypothesis: T1XXX.YYY — <behavior>")`
index=<index> sourcetype=<sourcetype>
    earliest=-30d latest=now
    <field>=<value>                        `comment("core behavior")`
NOT (<field> IN (<benign_values>))         `comment("noise reduction")`
| eval attck_technique="T1XXX.YYY"
| table _time, host, user, <key_fields>, attck_technique
| sort _time
```

### Converting hunting queries to Sigma

When a hunt query produces confirmed true positives, convert it to a Sigma rule
following detection-engineering standards before closing the hunt.

Sigma conversion steps:
1. Map the query's log source to a Sigma `logsource` category/product
2. Translate filter logic to Sigma `detection` blocks
3. Apply all five detection-engineering standards (see SKILL.md)
4. Validate with `scripts/validate-rule.py`

---

## Phase 4 — Analysis

**For each hit, answer:**

1. Is this a true positive, false positive, or requires more context?
2. If TP: what ATT&CK technique does it confirm?
3. If FP: should this be filtered in the detection rule or is it environment-specific?
4. Does this hit pivot to additional hunting leads (new IPs, accounts, hashes)?

**Triage categories:**

| Category | Definition | Action |
|---|---|---|
| Confirmed TP | Attacker behavior, no benign explanation | Escalate to IR, create detection rule |
| Suspected TP | Behavior consistent with attack, needs more evidence | Pivot hunt, collect more context |
| Benign | Known-good activity, documented reason | Add to exclusion list with justification |
| Inconclusive | Insufficient data to determine | Document data gap, revisit with richer source |

**Pivot fields** — when you find a TP, immediately pivot on:
- Host name → other activity from the same host
- Account name → other activity by the same account
- Hash / command line → other hosts running the same binary
- C2 IP/domain → other hosts communicating with the same infrastructure
- Parent process → full process tree

---

## Phase 5 — Findings Documentation

Every completed hunt must produce a hunt report, even if the result is "nothing found."

**Hunt report sections:**

```markdown
## Hunt Report: <Technique ID> — <Short Title>

**Hypothesis:** <one sentence>
**Period:** <start> to <end> UTC
**Analyst:** <name>
**Data sources queried:** <list>

### Results
- Hits reviewed: N
- True positives: N
- False positives: N
- Inconclusive: N

### True Positive Details
<for each TP: timestamp, host, user, observed behavior, ATT&CK technique>

### Detection Gap Assessment
- Rule created: yes/no — <rule filename>
- Coverage before hunt: <existing rules that should have caught this>
- Coverage after hunt: <new rules created>

### Recommended Follow-On Hunts
<pivots or related techniques worth investigating>
```

---

## Phase 6 — Rule Creation

**A hunt is not complete until:**
- [ ] Every confirmed TP has a corresponding Sigma or YARA rule
- [ ] Rules validated with `scripts/validate-rule.py`
- [ ] `mappings/` updated with new technique-to-rule entries
- [ ] ATT&CK Navigator layer updated to reflect new coverage

**Coverage gap categories:**

| Gap type | Example | Action |
|---|---|---|
| No rule exists | Novel TTP found in hunt | Write new rule, reference hunt report in `references` field |
| Rule exists but missed | Existing rule filtered out the TP | Update filter, add test case for the FP scenario |
| Rule exists, data source missing | Sigma rule for Sysmon but Sysmon not deployed | File infrastructure gap ticket, not a rule gap |

---

## Hunt Backlog Management

Maintain hunt ideas as backlog items tied to ATT&CK techniques.
Prioritize by:

1. **Techniques with zero detection coverage** in `mappings/`
2. **High-impact techniques** in the current threat intel context
3. **Techniques exploited in recent IR cases** within the organization
4. **ATT&CK techniques marked as "common"** by current threat actor profiles

---

## Integration with Detection Engineering and IR

- **Before hunting:** Check `mappings/` to identify techniques with no rules — those are the highest-value hunt targets.
- **After a TP:** Open an IR ticket if active. Open a detection gap ticket regardless.
- **Rule creation:** Follow `.claude/skills/detection-engineering/SKILL.md` standards.
- **Post-IR hunt:** After every IR engagement, run targeted hunts for related techniques the attacker may have used but not been detected using.
