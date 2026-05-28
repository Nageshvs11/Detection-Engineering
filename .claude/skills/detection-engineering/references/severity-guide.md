# Severity Level Guide

Use this guide to choose and justify the `level` field on every rule.
The inline comment above `level:` must explain the choice using these criteria.

---

## Decision Framework

Work through these questions in order:

1. **Does this activity have any legitimate use in a production environment?**
   - No legitimate use → start at `high`, consider `critical`
   - Rare legitimate use → `high`
   - Common legitimate use → `medium` or `low`

2. **What is the impact if this is a true positive?**
   - Direct path to domain compromise, credential theft, ransomware deployment → `critical` or `high`
   - Significant lateral movement or persistence capability → `high` or `medium`
   - Reconnaissance or information disclosure only → `medium` or `low`

3. **What is the expected false positive rate after filters are applied?**
   - Near-zero FPs → keep at the impact-driven level
   - Moderate FPs (known tools, admin workflows) → drop one level
   - High FPs (very common activity) → `low`, use for hunting/correlation only

---

## Levels

### `critical`

**Use when:** The activity is almost always malicious AND represents an immediate,
severe compromise with little or no time to respond.

Criteria:
- No legitimate use case exists in any production environment
- Confirms active exploitation or exfiltration already in progress
- Single event is sufficient to page on-call without further triage

Examples:
- Domain controller NTDS.dit file read by a non-DC process
- Golden ticket forging (TGT with abnormal lifetime)
- Ransomware kill-chain indicator (shadow copy deletion + mass encryption)

```yaml
# critical: NTDS.dit access outside ntdsutil/VSS has no legitimate use;
# confirms credential dumping of the entire domain is in progress.
level: critical
```

---

### `high`

**Use when:** The activity is almost always malicious but either has a narrow
legitimate use case (filtered out) or requires brief triage to confirm.

Criteria:
- Legitimate use is limited to specific tools or accounts (filterable)
- Direct path to credential theft, privilege escalation, or persistence
- After filters, FP rate should be very low (< 1 in 100 alerts)

Examples:
- LSASS memory access with dump-grade access rights (filtered for WER/EDR)
- Mimikatz or Rubeus command-line strings
- Pass-the-Hash / Pass-the-Ticket activity in Security logs
- Scheduled task creation by a non-admin user in a sensitive path

```yaml
# high: GrantedAccess masks targeting LSASS cover the minimum rights needed
# to dump credentials; filtered for WER and EDR, so FP rate is very low.
level: high
```

---

### `medium`

**Use when:** The activity is suspicious but has enough legitimate overlap
that automated escalation without triage would generate excessive noise.

Criteria:
- Legitimate use exists (admin tools, security scanners, developer workflows)
- Activity is a meaningful indicator when combined with other signals
- Requires analyst judgment to determine whether context is malicious

Examples:
- SPN enumeration via setspn.exe (admins do this legitimately)
- RC4 Kerberos ticket requests (legacy apps still use RC4)
- PowerShell encoded command execution (pentest tools AND legitimate automation)
- LDAP queries for sensitive attributes from a non-service account

```yaml
# medium: SPN enumeration overlaps with legitimate AD admin inventory scripts;
# high FP rate without additional context keeps this below high.
# Correlate with subsequent EventID 4769 RC4 requests to escalate.
level: medium
```

---

### `low`

**Use when:** The activity is commonly benign but worth recording for
correlation, hunting, or building a timeline around other higher-severity events.

Criteria:
- High FP rate even after tuning — most hits are benign
- Useful as a supporting signal, not a standalone alert
- Should rarely or never trigger an on-call page by itself

Examples:
- DNS queries to newly registered domains (high volume, mostly benign)
- User enumeration commands (net user, whoami) — normal developer activity
- Browser spawning a child process (occasional legitimate use)
- LSASS handle open with low-privilege access mask

```yaml
# low: whoami and net user are standard developer and helpdesk activity;
# high FP rate makes this a hunting/correlation signal only, not a standalone alert.
level: low
```

---

## Quick-Reference Table

| Level | Legitimate use? | FP rate (post-filter) | Impact | Page on-call? |
|---|---|---|---|---|
| `critical` | None | Near zero | Domain/system compromise confirmed | Immediately |
| `high` | Rare / filtered | Very low | Direct path to major impact | After brief triage |
| `medium` | Common | Moderate | Significant with context | After correlation |
| `low` | Very common | High | Minimal alone | No — hunting only |

---

## Common Mistakes

**Assigning `high` because the technique sounds scary:**
Severity reflects *this rule's* expected signal quality, not the technique's
theoretical impact. A noisy rule for a critical technique should still be `medium`
until tuned.

**Assigning `medium` as a safe default:**
`medium` is not the safe middle ground — it means "needs analyst triage on every
hit." If the FP rate is genuinely low, use `high`. If the FP rate is high, use `low`.

**Not adjusting level after adding filters:**
If filters reduce the FP rate significantly, consider bumping the level up.
The justification comment should reflect the post-filter expected FP rate.
