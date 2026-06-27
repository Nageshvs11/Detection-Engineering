# Splunk lookup tables — exclusion infrastructure

These seven CSVs back the SPL exclusion blocks in every rule (see the `detection-engineering`
skill → *Splunk Lookup Table Infrastructure* and the *Exclusion Application Matrix*). Until they
exist **and are populated** in Splunk, the `inputlookup` exclusions silently pass all events
through — the rules still run, but with no noise suppression.

## ⚠️ These are SEEDS — replace the EXAMPLE rows before production
Every file ships with **one clearly-marked `EXAMPLE` row** (using documentation IP ranges
RFC 5737 / RFC 1918, or placeholder names) purely to demonstrate the schema. They are inert —
documentation IPs never appear in real traffic — but you **must** replace them with real values,
or the exclusion does nothing. The only real seed is `high_value_assets.csv` → `ADDC.RANA.local`
(the lab DC).

## Upload to Splunk
`Settings → Lookups → Lookup table files → New` (or `| outputlookup`), then define a
lookup definition of the same name under `Lookup definitions`.

| File | Key field | What to put in it |
|---|---|---|
| `vpn_egress_ips.csv` | `ip` | VPN/ZTNA/proxy egress IPs |
| `vuln_scanner_ips.csv` | `ip` | Nessus/Qualys/Rapid7/OpenVAS scanner IPs + scan subnets |
| `bas_ips.csv` | `ip` | SafeBreach/AttackIQ/Cymulate/XM Cyber/Picus agent + controller IPs |
| `service_accounts.csv` | `account` | service / automation / sync accounts |
| `admin_workstations.csv` | `hostname` | PAWs, jump hosts, bastions |
| `sanctioned_tools.csv` | `process_name` | approved admin/security tool process names (lowercase) |
| `high_value_assets.csv` | `hostname` | DCs, CA servers, PAM servers, crown-jewel app servers |

## Verify a lookup is populated before relying on it
```spl
| inputlookup vpn_egress_ips.csv | stats count
| inputlookup high_value_assets.csv | stats count
```

> **Do not exclude `bas_ips.csv` during active BAS/simulation exercises** — you want the rules to
> fire then. The BAS exclusion is for *always-on* scanning noise. Suppress simulation windows by
> time/tag instead. (See the skill's note under *BAS-IPs*.)

> Keep CSVs clean: header row + data rows only. Do **not** add `#` comment lines — Splunk would
> ingest them as bogus lookup entries.
