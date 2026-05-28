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

## KQL Rule Design

Each KQL rule follows a standard structure:

- **Dual console support** — rules declare `// Target: Sentinel`, `// Target: DefenderXDR`, or `// Target: Both` and use the correct timestamp field (`TimeGenerated` vs `Timestamp`)
- **Context-aware watchlist exclusions** — seven standard Sentinel Watchlists applied based on the rule's focus area (see Exclusion Matrix below)
- **Severity graduation** — alerts escalate to `Critical` when the targeted account or asset appears in `High-Value-Assets`
- **Rule type** — every rule declares `AnalyticRule` (auto-creates incident) or `HuntingQuery` (analyst-reviewed) in the header
- **Deduplication** — `summarize + arg_max(TimeGenerated, *)` ensures one row per entity per alert window
- **Triage guidance** — every rule includes a `Triage` field with step-by-step analyst instructions

---

## SPL Rule Design

SPL rules (added to `splunk/` as they are written) follow the same principles adapted for Splunk ES:

- **Index routing** — rules target the correct index pattern (`*-os-win`, `*-os-linux`, `*-network`, `*-edr`, `*-azure`, `*-pam`, etc.)
- **Context-aware lookup exclusions** — seven standard lookup CSVs mirror the Sentinel Watchlists and are applied based on the rule's focus area (see Exclusion Matrix below)
- **Rule type** — `CorrelationSearch` (creates notable event) or `SavedSearch` (analyst-reviewed report)
- **RBA support** — high-volume signals use the Risk-Based Alerting pattern (`risk_object`, `risk_score`, `risk_index`) instead of direct notable events

---

## Exclusion Matrix

Every rule applies exclusions based on its focus area. The matrix below determines which watchlists and lookup CSVs are required for each rule type.

| Rule focus | Required exclusions | Why |
|---|---|---|
| **Network** (firewall, proxy, DNS, IDS/IPS) | VPN IPs · Scanner IPs · BAS IPs | Scanners and BAS tools generate high-volume authorized traffic that matches network detection patterns |
| **Identity / Authentication** (sign-in, MFA, LDAP, Kerberos) | Service accounts · VPN IPs · Scanner IPs · BAS IPs | Scanner/BAS auth attempts look identical to credential spray; service accounts authenticate at high frequency |
| **Process Execution** (process creation, script execution) | Service accounts · Admin workstations · Sanctioned tools | Admins and approved tooling run the same binaries attackers abuse |
| **Credential Access** (LSASS, SAM, DPAPI) | Service accounts · Admin workstations · Sanctioned tools · Scanner IPs · BAS IPs | Scanners and BAS tools probe credential stores as part of authorized assessments |
| **Lateral Movement** (PsExec, WMI, SMB, RDP) | Service accounts · Admin workstations · Scanner IPs · BAS IPs | Scanners enumerate SMB/RDP; admins use the same remote management tools |
| **Cloud** (Azure/AWS/GCP API, resource change) | Service accounts · VPN IPs · Scanner IPs · BAS IPs | Cloud assessment tools and automation accounts generate high-volume authorized API calls |
| **Endpoint / EDR** (file, registry, injection) | Service accounts · Admin workstations · Sanctioned tools · BAS IPs | BAS agents run directly on endpoints and execute the same artifacts as real attackers |
| **PAM / Privileged Access** | Service accounts · Scanner IPs · BAS IPs | Password rotation scripts and BAS credential-testing modules interact directly with PAM APIs |
| **All rules** | High-Value-Assets | Severity graduation — always applied, never used as exclusion |

**Quick decision rule:**
- Rule has a source IP field → always add VPN + scanner + BAS IPs
- Rule has a user/account field → always add service accounts
- Rule targets process execution or endpoint activity → always add admin workstations + sanctioned tools

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
