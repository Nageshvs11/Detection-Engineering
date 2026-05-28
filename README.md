# Detection Engineering

A detection engineering knowledge base combining Sigma rules, KQL (Microsoft Sentinel / Defender XDR), SPL (Splunk), and YARA rules — with an MCP server that exposes the knowledge base to Claude for AI-assisted detection authoring.

---

## Repository Structure

```
Detection-Engineering/
├── kql/                        # KQL rules — Microsoft Sentinel / Defender XDR
│   ├── cloud/
│   ├── identity/
│   ├── windows/
│   ├── linux/  network/  web/  application/  macos/
│
├── splunk/                     # SPL rules — Splunk Enterprise Security
│   ├── identity/  windows/  cloud/
│   ├── linux/  network/  web/  application/  macos/
│
├── rules/                      # Sigma rules (platform-agnostic YAML)
├── yara/                       # YARA detection rules
├── mappings/                   # ATT&CK technique → rule ID index
├── server.py                   # MCP server (Claude Code integration)
└── .claude/skills/             # Detection engineering skill definitions
```

---

## Detection Coverage

### KQL Rules

| File | Use Case ID | ATT&CK | Platform | Severity |
|---|---|---|---|---|
| `kql/identity/001_dcsync_non_dc.kql` | OS-DET-AD-001 | T1003.006 — DCSync | Sentinel / Defender XDR | Critical |
| `kql/identity/002_mfa_fatigue_adfs_push_bombing.kql` | Identity-DET-Azure-002 | T1621 — MFA Request Generation | Sentinel | High / Critical |
| `kql/windows/001_pass_the_hash_ntlm_lateral_movement.kql` | OS-DET-WIN-001 | T1550.002 — Pass the Hash | Sentinel / Defender XDR | High / Critical |
| `kql/windows/002_handala_wiper_chain.kql` | OS-DET-WIN-002 | T1485 — Data Destruction | Sentinel / Defender XDR | Critical |
| `kql/cloud/001_impossible_travel_login.kql` | Cloud-DET-Azure-001 | T1078 — Valid Accounts | Sentinel | High |

### Sigma Rules (`rules/`)

| Category | Rules |
|---|---|
| Credential Access — LSASS | `proc_access_win_lsass_memdump.yml`, `proc_access_win_lsass_minidump_api.yml`, `proc_access_win_lsass_dump_comsvcs_dll.yml`, `proc_access_win_lsass_susp_access_flag.yml`, `proc_access_win_hktl_handlekatz_lsass_access.yml` |
| Credential Access — Dumping tools | `proc_creation_win_lsass_dump_procdump.yml`, `proc_creation_win_sysinternals_procdump_lsass.yml`, `proc_creation_win_rundll32_process_dump_via_comsvcs.yml`, `rules/win_security_susp_lsass_dump_generic.yml` |
| Credential Access — Mimikatz | `proc_creation_win_hktl_mimikatz_command_line.yml` |
| Credential Access — Kerberos | `win_security_kerberoasting_activity.yml`, `win_security_kerberoasting_rc4.yml`, `win_security_susp_rc4_kerberos.yml`, `posh_ps_spn_enumeration_kerberoasting.yml`, `posh_ps_request_kerberos_ticket.yml`, `proc_creation_win_setspn_spn_enumeration.yml` |
| Lateral Movement | `win_security_pass_the_hash.yml`, `win_security_pass_the_hash_2.yml`, `win_security_overpass_the_hash.yml`, `win_susp_ntlm_auth.yml` |
| Privilege Escalation | `win_security_golden_ticket.yml` |
| Active Directory | `win_security_dcsync.yml`, `win_security_ad_replication_non_machine_account.yml` |
| Offensive Tools | `posh_ps_hktl_rubeus.yml`, `proc_creation_win_hktl_rubeus.yml`, `pipe_created_hktl_generic_cred_dump_tools_pipes.yml`, `file_event_win_lsass_default_dump_file_names.yml` |

### YARA Rules (`yara/`)

| File | Target | Description |
|---|---|---|
| `MAL_Win_CobaltStrike_Beacon_May26.yar` | Windows PE | CobaltStrike Beacon detection |

---

## KQL Rule Design

Each KQL rule follows a standard structure:

- **Dual console support** — rules declare `// Target: Sentinel`, `// Target: DefenderXDR`, or `// Target: Both` and use the correct timestamp field (`TimeGenerated` vs `Timestamp`)
- **Watchlist exclusions** — five standard Sentinel Watchlists (`VPN-Egress-IPs`, `Service-Accounts`, `Admin-Workstations`, `Sanctioned-Tools`, `High-Value-Assets`) are applied for FP suppression
- **Severity graduation** — alerts escalate to `Critical` when the targeted account or asset appears in `High-Value-Assets`
- **Rule type** — every rule declares `AnalyticRule` (auto-creates incident) or `HuntingQuery` (analyst-reviewed) in the header
- **Deduplication** — `summarize + arg_max(TimeGenerated, *)` ensures one row per entity per alert window
- **Triage guidance** — every rule includes a `Triage` field with step-by-step analyst instructions

---

## SPL Rule Design

SPL rules (added to `splunk/` as they are written) follow the same principles adapted for Splunk ES:

- **Index routing** — rules target the correct index pattern (`*-os-win`, `*-os-linux`, `*-network`, `*-edr`, `*-azure`, `*-pam`, etc.)
- **Lookup exclusions** — five standard lookup CSVs mirror the Sentinel Watchlists (`vpn_egress_ips.csv`, `service_accounts.csv`, `admin_workstations.csv`, `sanctioned_tools.csv`, `high_value_assets.csv`)
- **Rule type** — `CorrelationSearch` (creates notable event) or `SavedSearch` (analyst-reviewed report)
- **RBA support** — high-volume signals use the Risk-Based Alerting pattern (`risk_object`, `risk_score`, `risk_index`) instead of direct notable events

---

## Claude Code Integration (MCP Server)

`server.py` is an [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server that exposes this knowledge base to Claude Code. When registered, Claude can:

- Browse and query Sigma rules by ATT&CK technique
- Check detection coverage gaps across `mappings/attack_techniques.json`
- Cross-reference Hayabusa scan hits against rule IDs

**Register in `~/.claude/settings.json`:**

```json
{
  "mcpServers": {
    "detection-kb": {
      "command": "python",
      "args": ["/path/to/Detection-Engineering/server.py"]
    }
  }
}
```

**Run standalone:**

```bash
python server.py
```

### Detection Engineering Skill

`.claude/skills/detection-engineering/SKILL.md` is a Claude Code skill that enforces detection quality standards when writing or reviewing rules. It covers:

- ATT&CK technique tag requirements
- Severity level justification
- False positive documentation
- Test case generation
- File naming and sequence numbering
- KQL watchlist and SPL lookup exclusion patterns
- Rule type classification and promotion path

Custom data source schemas are stored under `.claude/skills/detection-engineering/references/`:

| Directory | Purpose |
|---|---|
| `references/custom-tables/` | KQL `_CL` table schemas (e.g. `thycotic_cl.md`) |
| `references/custom-indexes/` | Splunk custom index schemas (e.g. `thycotic_pam.md`) |

---

## Adding a New Rule

### KQL

1. Determine the category and run `next-seq.py` to get the sequence number:
   ```bash
   python .claude/skills/detection-engineering/scripts/next-seq.py kql/windows
   # → 003
   ```
2. Create `kql/<category>/NNN_description.kql` using the template in `SKILL.md`
3. Add the technique mapping to `mappings/attack_techniques.json`

### Sigma

1. Create `rules/<lowercase_filename>.yml` following SigmaHQ naming conventions
2. Validate: `python .claude/skills/detection-engineering/scripts/validate-rule.py rules/<file>.yml`
3. Add to `mappings/attack_techniques.json`

### SPL

1. Run `next-seq.py` against the target splunk category directory
2. Create `splunk/<category>/NNN_description.spl` using the SPL template in `SKILL.md`
3. Ensure the correct index pattern and lookup exclusions are declared in the header

---

## ATT&CK Technique Index

`mappings/attack_techniques.json` maps ATT&CK technique IDs to rule IDs. Currently covered:

| Technique | Name | Rules |
|---|---|---|
| T1003.006 | DCSync | `OS-DET-AD-001_dcsync_non_dc` |
| T1550.002 | Pass the Hash | `OS-DET-WIN-001_pass_the_hash_ntlm_lateral_movement` |
| T1621 | MFA Request Generation | `Identity-DET-Azure-002_mfa_fatigue_adfs_push_bombing` |

---

## Prerequisites

| Component | Requirement |
|---|---|
| KQL rules | Microsoft Sentinel workspace with relevant data connectors enabled |
| Defender XDR rules | Microsoft Defender XDR Advanced Hunting access |
| SPL rules | Splunk Enterprise Security with lookup CSVs deployed |
| MCP server | Python 3.9+, `mcp` package |
| Sigma validation | `pyyaml` package |
