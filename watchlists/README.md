# Sentinel watchlists — exclusion infrastructure

These eight CSVs back the KQL `_GetWatchlist()` exclusion joins in every rule (see the
`detection-engineering` skill → *Watchlist Infrastructure* and the *Exclusion Application Matrix*).
Until each watchlist exists **and has entries** in Sentinel, the joins return empty sets and the
exclusions do nothing — the rules still run, just without noise suppression.

## ⚠️ These are SEEDS — replace the EXAMPLE rows before production
Each file has **one `EXAMPLE` row** to show the schema (documentation IP ranges / placeholder
names — inert). Replace them with real values. The only real seed is `High-Value-Assets.csv` →
`ADDC.RANA.local` (the lab DC).

## Upload to Sentinel
`Microsoft Sentinel → Configuration → Watchlists → New`, or via ARM template. The **alias** must
match the name referenced in the rules (the filename without `.csv`), and **`SearchKey`** is the
column the KQL joins on.

| Watchlist (alias) | SearchKey holds | What to put in it |
|---|---|---|
| `VPN-Egress-IPs` | IP (exact/CIDR) | VPN/ZTNA/proxy egress IPs |
| `Vuln-Scanner-IPs` | IP | scanner IPs + scan subnets |
| `BAS-IPs` | IP | BAS agent + controller IPs |
| `Service-Accounts` | UPN / sAMAccountName | service / automation / sync accounts (MSOL_*, AADConnect) |
| `Admin-Workstations` | hostname / IP | PAWs, jump hosts, bastions |
| `Sanctioned-Tools` | process name (lowercase) | approved admin/security tools |
| `Sanctioned-Apps` | AppDisplayName (lowercase) | approved apps that auth across many accounts |
| `High-Value-Assets` | hostname / FQDN | DCs, CA servers, PAM servers, crown-jewel apps |

## Verify a watchlist has entries before relying on it
```kql
_GetWatchlist('VPN-Egress-IPs') | summarize EntryCount = count()
// EntryCount = 0 → missing/empty; do not deploy a rule that depends on it
```

> Required columns when creating: `SearchKey`, `Description`, `LastUpdated` (these seeds include
> all three). Add more columns as your environment needs.
