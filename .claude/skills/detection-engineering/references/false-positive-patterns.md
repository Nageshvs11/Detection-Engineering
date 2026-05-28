# False Positive Patterns

A reference of common FP categories and how to document them correctly.
Use this when filling the `falsepositives` field or deciding whether to add a filter.

The goal is always the same: give a responder enough information to rule out a
benign hit in under 60 seconds without escalating to Tier 2.

---

## Category 1 — Windows Built-in Processes

Processes shipped with Windows that legitimately perform actions that resemble attacks.

| Process | Common FP scenario |
|---|---|
| `WerFault.exe` / `WerFaultSecure.exe` | Creates memory dumps of crashed processes, including LSASS |
| `taskmgr.exe` | Users and admins open LSASS handle for process inspection |
| `lsass.exe` (self) | LSASS occasionally accesses itself |
| `svchost.exe` | Hosts many services that touch sensitive registry keys or network |
| `msiexec.exe` | Installs software, touches registry run keys and scheduled tasks |
| `wscript.exe` / `cscript.exe` | Legitimate VBScript/JScript automation in enterprise environments |

**How to document:**
```yaml
falsepositives:
    - Windows Error Reporting (WerFault.exe) collecting process crash diagnostics
      — filtered by default; alert fires only if binary is renamed or run from
      an unexpected path outside C:\Windows\System32\
```

**When to filter vs document:**
- Filter if the process path is predictable and the behavior is always benign.
- Document (don't filter) if the legitimate use is conditional — e.g., taskmgr
  opened by a non-admin is suspicious; opened by an admin during incident response
  is not.

---

## Category 2 — EDR, AV, and Security Tooling

Security products routinely perform actions that look identical to attacker TTPs.

| Vendor / Product | Binary examples | Common FP |
|---|---|---|
| Microsoft Defender | `MsMpEng.exe`, `SenseIR.exe`, `SenseCncProxy.exe` | LSASS memory reads, process injection for monitoring |
| CrowdStrike Falcon | `CSFalconService.exe`, `CSFalconContainer.exe` | Network scanning, registry reads, kernel driver loads |
| SentinelOne | `SentinelAgent.exe`, `SentinelServiceHost.exe` | Behavioural monitoring, memory inspection |
| Carbon Black | `cb.exe`, `CbDefense.exe` | Process and file monitoring hooks |
| Sysmon itself | `Sysmon.exe`, `Sysmon64.exe` | May appear in its own event logs |
| Vulnerability scanners | `nessus.exe`, `qualys_scan_util.exe` | Port scans, SMB enumeration, credential testing |

**How to document:**
```yaml
falsepositives:
    - EDR and AV engines (Defender MsMpEng.exe, CrowdStrike CSFalconService.exe)
      performing live memory inspection — add vendor-specific binaries to the
      filter block if they generate alerts in your environment
```

**Tip:** Never hard-code all EDR vendors into a filter. Document the pattern and
let the deploying team add their specific binary paths.

---

## Category 3 — IT Administration Workflows

Legitimate administrative tasks that overlap with attacker reconnaissance or
persistence techniques.

| Admin action | Technique overlap |
|---|---|
| AD inventory (Get-ADUser, ldifde) | T1087 Account Discovery, T1558 SPN enumeration |
| GPO deployment scripts | T1059 Script execution, T1112 Registry modification |
| Remote management (PSRemoting, WinRM) | T1021.006 Remote Services |
| Scheduled maintenance tasks | T1053 Scheduled Task |
| Software deployment (SCCM, Intune) | T1072 Software Deployment Tools |
| Password reset tooling | T1098 Account Manipulation |
| SPN registration/cleanup | T1558.003 Kerberoasting recon |

**How to document:**
```yaml
falsepositives:
    - AD administrators running SPN inventory or cleanup scripts using
      Get-ADUser / setspn.exe — baseline expected scripts and establish a
      known-good schedule; alerts outside that window are higher fidelity
```

**Tip:** If an admin workflow is predictable (same account, same schedule,
same source host), document the pattern so analysts can confirm or suppress
quickly. Don't filter it out entirely — admin credential abuse is a real threat.

---

## Category 4 — Monitoring, Backup, and Automation Agents

Third-party agents that run with elevated privileges and touch sensitive
resources as part of their normal operation.

| Agent type | Examples | Common FP |
|---|---|---|
| Backup agents | Veeam, Commvault, Backup Exec | VSS snapshot creation, registry reads, file system enumeration |
| RMM tools | ConnectWise, Kaseya, NinjaRMM | Remote script execution, registry writes, lateral tool transfer |
| Configuration management | Ansible, Chef, Puppet, Salt | Script execution, file writes to system paths |
| Cloud agents | AWS SSM Agent, Azure Monitor Agent | Command execution, credential access for managed identity |
| ITSM agents | ServiceNow MID Server | Network scanning, WMI queries |

**How to document:**
```yaml
falsepositives:
    - Backup agents (Veeam, Commvault) creating VSS snapshots — distinguish by
      known service account names and scheduled execution windows; ad-hoc
      execution outside backup windows is higher fidelity
    - RMM tools (ConnectWise, Kaseya) executing remote scripts for patch
      management — verify SourceImage matches known agent binary path
```

---

## Category 5 — Developer and Testing Environments

Development workflows that intentionally exercise dangerous capabilities.

| Scenario | Common FP |
|---|---|
| Penetration test / red team engagement | Any offensive technique |
| Security research workstations | Malware analysis, tool testing |
| CI/CD pipelines | Automated test runners executing scripts, reading credentials from env |
| Load/stress testing | High-volume network connections, resource exhaustion patterns |
| Debugging sessions | Process memory reads, debugger attachment |

**How to document:**
```yaml
falsepositives:
    - Authorized penetration testing or red team exercises — coordinate with
      the security team to establish test windows and source IP ranges for
      suppression during engagements
    - Security research workstations running malware analysis — isolate on
      dedicated hosts and exclude those host names from production alerting
```

---

## Category 6 — Legacy Applications

Older software that uses deprecated or insecure patterns still common in
enterprise environments.

| Legacy pattern | Detection overlap |
|---|---|
| RC4 Kerberos tickets | T1558.003 Kerberoasting detection |
| NTLM authentication | Pass-the-Hash, NTLM relay detection |
| Unencrypted protocols (FTP, Telnet, HTTP) | Cleartext credential detection |
| Old TLS versions (1.0/1.1) | Weak cipher detection |
| SAM/LSA registry reads | T1003.002 SAM database access |

**How to document:**
```yaml
falsepositives:
    - Legacy applications that only support RC4 Kerberos encryption and cannot
      be updated — identify the specific service accounts and SPNs, document
      them, and consider adding targeted suppression by ServiceName
```

---

## When FPs Are Genuinely Unknown

`Unknown` alone is never acceptable. If you cannot identify a concrete FP scenario,
use the following form and revisit after the rule has been in production for two weeks:

```yaml
falsepositives:
    - No false positives have been identified during testing in a standard
      enterprise Windows environment. Monitor for tuning opportunities in
      environments with non-standard tooling, legacy software, or third-party
      security agents not accounted for above.
```

This is better than `Unknown` because it tells the responder:
1. The author looked for FPs and found none in the tested environment.
2. The most likely sources of noise to investigate (non-standard tooling, legacy software).
3. That the rule may need tuning after initial deployment.
