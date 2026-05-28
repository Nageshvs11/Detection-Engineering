---
name: incident-response
description: |
  Incident Response procedures and playbooks. Activate when triaging
  alerts, investigating incidents, collecting evidence, containing
  threats, or producing IR reports.
---

# Incident Response Procedures

## Trigger

Use this skill when:
- Triaging a security alert or investigating a potential incident
- Collecting or preserving digital evidence
- Containing or eradicating a threat from an environment
- Mapping observed attacker activity to ATT&CK techniques
- Building or reviewing incident timelines
- Writing incident reports or post-incident reviews
- Coordinating handoff between triage, investigation, and remediation

---

## IR Lifecycle

```
Detection → Triage → Scoping → Containment → Eradication → Recovery → Post-Incident Review
```

Each phase has required outputs before the next phase begins. Do not skip phases
or combine containment and eradication without explicit sign-off.

---

## Phase 1 — Triage

**Goal:** Determine if an alert is a true positive and estimate initial severity.

**Required outputs before advancing:**
- [ ] Alert triaged as TP / FP / Benign
- [ ] Initial ATT&CK technique(s) identified
- [ ] Severity assigned: P1 (critical) / P2 (high) / P3 (medium) / P4 (low)
- [ ] Incident ticket opened with initial findings

**Triage questions:**
1. What is the data source and detection rule that fired?
2. What host/user/process is involved?
3. Is this activity expected for this asset at this time?
4. What is the earliest related event in the logs?
5. Is there evidence of lateral movement or additional hosts involved?

**ATT&CK mapping at triage:**
Map every observed behavior to at least one ATT&CK technique before escalating.
Use the format `Tactic: TA00XX / Technique: T1XXX.YYY` in ticket notes.

---

## Phase 2 — Scoping

**Goal:** Determine the full blast radius — all affected hosts, accounts, and data.

**Required outputs before advancing:**
- [ ] Affected host list with first/last seen timestamps
- [ ] Affected account list with privilege level
- [ ] Initial attacker timeline (UTC, chronological)
- [ ] Data at risk identified (credentials, PII, IP, regulated data)
- [ ] C2 infrastructure identified (IPs, domains, JA3/JARM hashes)

**Scoping queries to run:**

| Question | Log source | Key fields |
|---|---|---|
| Which hosts communicated with C2? | Firewall / Proxy | dst_ip, dst_domain, bytes_out |
| Which accounts were used? | AD / SIEM | SubjectUserName, LogonType, SourceAddress |
| What was staged or exfiltrated? | DLP / Proxy | file_name, bytes_out, dst_domain |
| Which hosts have the implant? | EDR | file_hash, process_name, parent_process |
| What persistence mechanisms exist? | EDR / Registry | RegistryKey, ServiceName, ScheduledTask |

**Minimum timeline fields:**
```
[UTC timestamp] | [Host] | [User] | [Process] | [Event] | [ATT&CK technique]
```

---

## Phase 3 — Containment

**Goal:** Stop ongoing attacker activity without destroying evidence.

**Required outputs before advancing:**
- [ ] Containment strategy approved by IR lead
- [ ] Evidence preserved (memory dumps, disk images, log exports) BEFORE isolation
- [ ] Network isolation or firewall blocks applied
- [ ] Affected accounts disabled or password-reset
- [ ] C2 domains/IPs blocked at perimeter

**Containment decision matrix:**

| Scenario | Preferred containment | Avoid |
|---|---|---|
| Active exfiltration | Block C2 at firewall immediately | Pulling the host offline (loses network state) |
| Credential compromise | Reset password + revoke sessions | Disabling account before evidence is copied |
| Ransomware staging | Isolate host from network | Rebooting (may trigger detonation) |
| Persistence via scheduled task | Disable task, preserve original entry | Deleting before imaging |
| Lateral movement in progress | Isolate pivot host | Blocking until all hops are mapped |

**Evidence to preserve before containment actions:**
- Running processes (memory dump or EDR telemetry snapshot)
- Active network connections (`netstat -anob`, EDR network events)
- Scheduled tasks, services, registry run keys
- Prefetch, event logs, PowerShell history

---

## Phase 4 — Eradication

**Goal:** Remove all attacker footholds from the environment.

**Required outputs before advancing:**
- [ ] All implants and persistence mechanisms removed
- [ ] All compromised credentials rotated
- [ ] Affected hosts rebuilt or verified clean
- [ ] Patch or configuration gap that enabled initial access remediated
- [ ] Detection rules created or updated to catch this TTP

**Eradication checklist by persistence type:**

| Persistence type | Eradication action | Verification |
|---|---|---|
| Scheduled task | Delete task, check for re-creation | `schtasks /query` post-clean |
| Registry run key | Remove key, check HKLM + HKCU | Autoruns diff before/after |
| Service | Stop + delete service, remove binary | `sc query` + hash verification |
| WMI subscription | Remove subscription/consumer/filter | `Get-WMIObject` check |
| Boot/logon autostart | Remove entry, verify MBR/VBR | Autoruns + hash baseline |
| Credential persistence | Rotate all creds touched by attacker | Verify with `klist purge` |

---

## Phase 5 — Recovery

**Goal:** Restore normal operations with confidence the threat is eliminated.

**Required outputs:**
- [ ] Hosts rebuilt or validated clean with current patches
- [ ] Monitoring enhanced for reinfection indicators
- [ ] Business stakeholders notified of restoration
- [ ] Temporary containment controls (firewall blocks, disabled accounts) reviewed

---

## Phase 6 — Post-Incident Review

**Goal:** Capture lessons learned and improve defenses before the report is closed.

**Required outputs:**
- [ ] Incident report drafted (see template below)
- [ ] Detection gaps identified and filed as backlog items
- [ ] New/updated Sigma or YARA rules created for observed TTPs
- [ ] ATT&CK Navigator layer updated with confirmed techniques
- [ ] Tabletop or purple-team exercise scheduled if gap was critical

**Incident report sections (minimum):**
1. Executive summary (2-3 sentences: what happened, impact, status)
2. Timeline (UTC, full attacker activity from first evidence to eradication)
3. ATT&CK technique matrix (confirmed techniques with evidence references)
4. Root cause (initial access vector and contributing factors)
5. Impact assessment (data, systems, users affected)
6. Containment and eradication actions taken
7. Recommendations (detection, hardening, process improvements)

---

## Severity Definitions

| Priority | Definition | SLA |
|---|---|---|
| P1 Critical | Active exfiltration, ransomware detonation, domain compromise | 15 min response, continuous until contained |
| P2 High | Confirmed breach, C2 active, credential theft, lateral movement | 1 hr response, 4 hr containment target |
| P3 Medium | Suspicious activity requiring investigation, single-host compromise | 4 hr response, 24 hr investigation |
| P4 Low | Low-confidence alerts, policy violations, no evidence of impact | 24 hr response, 72 hr investigation |

---

## ATT&CK Tagging Standard

Every IR ticket and timeline entry must include ATT&CK tags for each observed behavior.
Use the same `attack.tXXXX.YYY` format as detection rules to enable cross-referencing.

**Required tags per incident:**
- Initial access technique (how did attacker get in?)
- Execution technique (how did they run code?)
- Persistence technique (how did they maintain access?)
- Any credential access, lateral movement, or exfiltration techniques observed

---

## Integration with Detection Engineering

When IR confirms a novel TTP not covered by existing rules:
1. File a detection gap ticket referencing the incident ID
2. Write or update a Sigma rule following detection-engineering standards
3. Validate with `scripts/validate-rule.py` before closing the gap ticket
4. Update `mappings/` with the new technique-to-rule mapping

Cross-reference: see `.claude/skills/detection-engineering/SKILL.md`
