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

All rules are authored as `.yml` files following the Sigma YAML schema. KQL rules embed the Sentinel/XDR query in a `kql_query:` block; SPL rules use a `spl_query:` block. This provides a single industry-standard format with consistent metadata across all platforms.

| File | Use Case ID | ATT&CK | Platform | Severity |
|---|---|---|---|---|
| `kql/identity/001_dcsync_non_dc.yml` | OS-DET-AD-001 | T1003.006 — DCSync | Sentinel / Defender XDR | Critical |
| `kql/identity/002_mfa_fatigue_adfs_push_bombing.yml` | Identity-DET-Azure-002 | T1621 — MFA Request Generation | Sentinel | High / Critical |
| `kql/identity/003_password_spray.yml` | Identity-DET-Azure-003 | T1110.003 — Password Spray | Sentinel | High / Critical |
| `kql/identity/004_attack_chain_credential_access.yml` | Identity-DET-Azure-004 | T1110.003 · T1621 · T1078.004 — Correlated chain | Sentinel | High / Critical |
| `kql/identity/005_kerberoasting_spn_request.yml` | OS-DET-AD-002 | T1558.003 — Kerberoasting | Sentinel | High / Critical |
| `kql/windows/001_pass_the_hash_ntlm_lateral_movement.yml` | OS-DET-WIN-001 | T1550.002 — Pass the Hash | Sentinel / Defender XDR | High / Critical |
| `kql/windows/002_handala_wiper_chain.yml` | OS-DET-WIN-002 | T1485 — Data Destruction | Sentinel / Defender XDR | Critical |
| `kql/cloud/001_impossible_travel_login.yml` | Cloud-DET-Azure-001 | T1078.004 — Cloud Accounts | Sentinel | High / Critical |

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
- **Context-aware watchlist exclusions** — seven standard Sentinel Watchlists applied based on the rule's focus area (see Exclusion Matrix below)
- **Severity graduation** — alerts escalate to `Critical` when the targeted account or asset appears in `High-Value-Assets`
- **Rule type** — every rule declares `AnalyticRule` (auto-creates incident) or `HuntingQuery` (analyst-reviewed) in the header
- **Deduplication** — `summarize + arg_max(TimeGenerated, *)` ensures one row per entity per alert window
- **Triage guidance** — every rule includes a `Triage` field with step-by-step analyst instructions

### Sentinel Watchlists

| Watchlist | Purpose | Rules that use it |
|---|---|---|
| `VPN-Egress-IPs` | Corporate VPN gateway and ZTNA egress IPs | Network, identity, cloud rules |
| `Vuln-Scanner-IPs` | Nessus, Qualys, Rapid7, OpenVAS scanner IPs | Any rule with a source IP field |
| `BAS-IPs` | SafeBreach, AttackIQ, Cymulate, XM Cyber agent and controller IPs | Any rule with a source IP field |
| `Service-Accounts` | Non-human accounts — service, automation, sync accounts | Every identity, sign-in, and process rule |
| `Admin-Workstations` | PAW machines, jump hosts, bastion servers | Endpoint, lateral movement, credential access rules |
| `Sanctioned-Tools` | Approved security and admin tool process names | Process creation, execution, defense evasion rules |
| `Sanctioned-Apps` | Approved app names (AppDisplayName) — backup agents, sync tools, SIEM connectors | Identity, cloud, MFA rules |
| `High-Value-Assets` | Domain controllers, CA servers, PAM servers, crown-jewel assets | All rules — severity graduation |

---

## SPL Rule Design

SPL rules (added to `splunk/` as they are written) follow the same principles adapted for Splunk ES:

- **Index routing** — rules target the correct index pattern (`*-os-win`, `*-os-linux`, `*-network`, `*-edr`, `*-azure`, `*-pam`, etc.)
- **Context-aware lookup exclusions** — seven standard lookup CSVs mirror the Sentinel Watchlists and are applied based on the rule's focus area (see Exclusion Matrix below)
- **Rule type** — `CorrelationSearch` (creates notable event) or `SavedSearch` (analyst-reviewed report)
- **RBA support** — high-volume signals use the Risk-Based Alerting pattern (`risk_object`, `risk_score`, `risk_index`) instead of direct notable events

### Splunk Lookup CSVs

| CSV file | Purpose | Rules that use it |
|---|---|---|
| `vpn_egress_ips.csv` | Corporate VPN gateway and ZTNA egress IPs | Network, identity, cloud rules |
| `vuln_scanner_ips.csv` | Nessus, Qualys, Rapid7, OpenVAS scanner IPs | Any rule with a `src_ip` or `dest_ip` field |
| `bas_ips.csv` | SafeBreach, AttackIQ, Cymulate, XM Cyber agent and controller IPs | Any rule with a `src_ip` or `dest_ip` field |
| `service_accounts.csv` | Non-human accounts — service, automation, sync accounts | Every identity, sign-in, and process rule |
| `admin_workstations.csv` | PAW machines, jump hosts, bastion servers | Endpoint, lateral movement, credential access rules |
| `sanctioned_tools.csv` | Approved security and admin tool process names | Process creation, execution, defense evasion rules |
| `high_value_assets.csv` | Domain controllers, CA servers, PAM servers, crown-jewel assets | All rules — severity graduation |

---

## Exclusion Matrix

Every rule applies exclusions based on its focus area. The matrix below determines which watchlists and lookup CSVs are required for each rule type.

| Rule focus | Required exclusions | Why |
|---|---|---|
| **Network** (firewall, proxy, DNS, IDS/IPS) | VPN IPs · Scanner IPs · BAS IPs | Scanners and BAS tools generate high-volume authorized traffic that matches network detection patterns |
| **Identity / Authentication** (sign-in, MFA, LDAP, Kerberos) | Service accounts · VPN IPs · Scanner IPs · BAS IPs · Sanctioned apps | Scanner/BAS auth attempts look identical to credential spray; approved apps (backup, sync) legitimately authenticate across many accounts |
| **Process Execution** (process creation, script execution) | Service accounts · Admin workstations · Sanctioned tools | Admins and approved tooling run the same binaries attackers abuse |
| **Credential Access** (LSASS, SAM, DPAPI) | Service accounts · Admin workstations · Sanctioned tools · Scanner IPs · BAS IPs | Scanners and BAS tools probe credential stores as part of authorized assessments |
| **Lateral Movement** (PsExec, WMI, SMB, RDP) | Service accounts · Admin workstations · Scanner IPs · BAS IPs | Scanners enumerate SMB/RDP; admins use the same remote management tools |
| **Cloud** (Azure/AWS/GCP API, resource change) | Service accounts · VPN IPs · Scanner IPs · BAS IPs · Sanctioned apps | Cloud assessment tools, automation accounts, and approved cloud-connector apps generate high-volume authorized API calls |
| **Endpoint / EDR** (file, registry, injection) | Service accounts · Admin workstations · Sanctioned tools · BAS IPs | BAS agents run directly on endpoints and execute the same artifacts as real attackers |
| **PAM / Privileged Access** | Service accounts · Scanner IPs · BAS IPs | Password rotation scripts and BAS credential-testing modules interact directly with PAM APIs |
| **All rules** | High-Value-Assets | Severity graduation — always applied, never used as exclusion |

**Quick decision rule:**
- Rule has a source IP field → always add VPN + scanner + BAS IPs
- Rule has a user/account field → always add service accounts
- Rule targets process execution or endpoint activity → always add admin workstations + sanctioned tools
- Rule targets sign-in, MFA, or cloud API activity → always add sanctioned apps

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

All rules — KQL, SPL, and Sigma — are authored as `.yml` files following the Sigma YAML schema.

### KQL (Sentinel / Defender XDR)

1. Get the next sequence number:
   ```bash
   python .claude/skills/detection-engineering/scripts/next-seq.py kql/windows
   # → 003
   ```
2. Create `kql/<category>/NNN_description.yml` using the KQL YAML template in `SKILL.md`
3. Embed the full KQL query in the `kql_query:` block scalar
4. Add the technique mapping to `mappings/attack_techniques.json`

### SPL (Splunk ES)

1. Get the next sequence number:
   ```bash
   python .claude/skills/detection-engineering/scripts/next-seq.py splunk/windows
   # → 001
   ```
2. Create `splunk/<category>/NNN_description.yml` using the SPL YAML template in `SKILL.md`
3. Embed the full SPL query in the `spl_query:` block scalar
4. Add the technique mapping to `mappings/attack_techniques.json`

### Sigma (platform-agnostic)

1. Create `rules/<lowercase_filename>.yml` following SigmaHQ naming conventions
2. Validate: `python .claude/skills/detection-engineering/scripts/validate-rule.py rules/<file>.yml`
3. Convert to KQL or SPL using sigma-cli if needed:
   ```bash
   sigma convert -t microsoft365defender rules/<file>.yml
   sigma convert -t splunk rules/<file>.yml
   ```
4. Add to `mappings/attack_techniques.json`

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
