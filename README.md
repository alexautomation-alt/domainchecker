# Domain Checker

PowerShell tool that checks a domain's email, web and infrastructure security and produces a branded HTML report with a risk rating, findings and recommendations.

> **Internal tool - ACC London.** Run by hand from a technician's machine. Not for client distribution.

## Features

- **Email:** SPF (including the 10-lookup limit), DMARC policy parsing, DKIM key discovery and strength, MTA-STS, TLS-RPT
- **Web:** certificate validity / hostname / chain / TLS version, HTTP to HTTPS redirect, security headers, server version disclosure
- **Infrastructure:** name servers, DNSSEC, CAA, MX, wildcard DNS, sensitive subdomain exposure, subdomain takeover (dangling CNAMEs)
- Weighted score (Pass = 1, Warn = 0.5, Fail = 0) with a Low / Medium / High risk rating
- Findings grouped by category, worst first, with remediation text for every issue
- Responsive HTML report with light/dark mode and a print-friendly layout
- Optional JSON export for tracking scores over time

## Installation

### Requirements

- Windows 10 / 11 or Windows Server (uses `Resolve-DnsName`)
- Windows PowerShell 5.1 or PowerShell 7+
- Outbound DNS (UDP/TCP 53), HTTP (80) and HTTPS (443)

### Folder structure

```
domainchecker/
├── Invoke-DomainCheck.ps1
├── README.md
├── Modules/
│   ├── Common.ps1                 # Shared helpers (dot-sourced by each module)
│   ├── EmailChecks.psm1
│   ├── WebChecks.psm1
│   └── InfrastructureChecks.psm1
└── Reports/                       # Created automatically on first run
```

### Setup

```powershell
git clone https://github.com/<your-org>/domainchecker.git
cd domainchecker
Get-ChildItem -Recurse | Unblock-File
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Usage

Run the whole script (not F8 / Run Selection) from the repo folder.

```powershell
# Basic scan - saves to .\Reports and opens the report
.\Invoke-DomainCheck.ps1 -Domain example.co.uk

# Use public DNS instead of the office resolver
.\Invoke-DomainCheck.ps1 -Domain example.co.uk -DnsServer 1.1.1.1

# Save HTML + JSON to a client folder without opening the browser
.\Invoke-DomainCheck.ps1 -Domain example.co.uk -OutputPath "C:\Reports\Clients" -ExportJson -NoOpen

# Several domains with a summary table
"client1.co.uk","client2.com" | ForEach-Object {
    .\Invoke-DomainCheck.ps1 -Domain $_ -NoOpen -PassThru
} | Format-Table Domain, Score, Risk, Fail, Warn
```

URLs are accepted and cleaned up, so `-Domain https://www.example.co.uk/contact` works.

### Parameters

| Parameter     | Required | Default             | Description |
|---------------|----------|---------------------|-------------|
| `-Domain`     | Yes      | -                   | Domain to assess |
| `-OutputPath` | No       | `Reports` next to the script | Folder for the report |
| `-DnsServer`  | No       | System resolver     | DNS server for all lookups, e.g. `1.1.1.1` |
| `-ExportJson` | No       | Off                 | Also save results as JSON |
| `-LogoPath`   | No       | Website logo URL    | Local logo file to embed in the report |
| `-NoOpen`     | No       | Off                 | Don't open the report when finished |
| `-PassThru`   | No       | Off                 | Return a summary object (domain, score, risk, paths) |

Full help: `Get-Help .\Invoke-DomainCheck.ps1 -Full`

### Output

```
SecurityAssessment_<domain>_<yyyyMMdd_HHmmss>.html
SecurityAssessment_<domain>_<yyyyMMdd_HHmmss>.json   # with -ExportJson
```

### Scoring

| Status | Points | Meaning |
|--------|--------|---------|
| Pass   | 1      | Configured correctly |
| Warn   | 0.5    | Works, but should be improved |
| Fail   | 0      | Missing or broken - fix this |
| Info   | -      | Shown for context, not scored (e.g. breach check, skipped checks) |

| Score  | Risk rating |
|--------|-------------|
| 85%+   | Low         |
| 60-84% | Medium      |
| < 60%  | High        |

### Things to know

- **DKIM "not found" is a Warn, not a Fail.** DNS can't list DKIM selectors, so the tool tries common ones. Check a sent email's `DKIM-Signature: s=` value if unsure.
- **Microsoft 365 DKIM keys don't upgrade themselves.** A 1024-bit warning needs `Rotate-DkimSigningConfig -KeySize 2048` run twice, waiting for the first rotation to complete.
- **Wildcard DNS** is detected, and subdomains that only resolve because of it are ignored.
- **Office DNS can differ from public DNS.** If results look wrong, re-run with `-DnsServer 1.1.1.1`.
- **Run time** is roughly 30 seconds to a couple of minutes per domain (around 70 DNS lookups).
- **The Data Breach Check** is a placeholder and shows as Info until an API is wired in.

## Contributing

1. Create a branch: `git checkout -b feature/new-check`
2. Add the check to the matching module. Use the helpers in `Modules\Common.ps1` rather than writing new DNS lookup code.
3. Every check must return this shape (use `New-CheckResult`):
   ```powershell
   New-CheckResult -Category 'Email' -Check 'Check Name' -Status 'Pass' `
       -Details 'What was found' -Remediation 'What to do (blank if Pass)'
   ```
   `Status` must be `Pass`, `Fail`, `Warn` or `Info`. Treat DNS **errors** as `Warn`, never as "not found".
4. Keep `Details` and `Remediation` plain English - they go straight into the report.
5. Update the version and changelog in the `.NOTES` block of every file you change.
6. Test against at least:
   - a well-configured Microsoft 365 domain
   - a poorly configured domain
   - a domain with wildcard DNS
   - a domain with no website
7. Open a pull request with a screenshot of a sample report.

## Changelog

| Version | Summary |
|---------|---------|
| 2.1.0 | Shared `Common.ps1` helpers, `-DnsServer` passed to all modules, error/exit fix |
| 2.0.x | Rewrite: weighted scoring, remediation, grouped findings, new email/web/infrastructure checks, `-NoOpen` / `-ExportJson` / `-LogoPath` / `-PassThru` |
| 1.0.0 | Initial release |

Full details are in the `.NOTES` block of each file.

## License

Copyright © ACC London. All rights reserved.

Internal use by ACC London staff only. Do not redistribute or publish without written permission. Reports produced by this tool are confidential and for the intended recipients only.
