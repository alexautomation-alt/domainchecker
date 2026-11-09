# Domain Checker

A PowerShell tool that runs a security assessment against a domain and produces a branded HTML report. It checks **email security**, **web security** and **infrastructure**, scores the results, gives an overall risk rating (Low / Medium / High) and lists recommendations for anything that failed or raised a warning.

## Features

- Email, web and infrastructure checks, each in its own module
- Overall security score (% of checks passed) with a Low / Medium / High risk rating
- Findings table with Pass / Fail / Warn badges
- Recommendations generated automatically from failed and warning checks
- Responsive HTML report with ACC London branding, a light/dark mode toggle and a print-friendly layout
- Timestamped report files, so earlier reports aren't overwritten

## Installation

### Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Internet access for DNS and web lookups (the report also loads the Inter font from Google Fonts)
- An execution policy that allows local scripts to run

### Folder structure

```
Domain-Checker/
├── Invoke-DomainCheck.ps1
├── Modules/
│   ├── EmailChecks.psm1
│   ├── WebChecks.psm1
│   └── InfrastructureChecks.psm1
└── Reports/              # Created automatically on first run
```

### Setup

1. Clone or download the repository:
   ```powershell
   git clone https://github.com/<your-org>/Domain-Checker.git
   cd Domain-Checker
   ```
2. If you downloaded the files from the internet, unblock them:
   ```powershell
   Get-ChildItem -Recurse | Unblock-File
   ```
3. If needed, allow local scripts for the current session:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```

## Usage

### Basic scan

```powershell
.\Invoke-DomainCheck.ps1 -Domain example.co.uk
```

This saves the report to `.\Reports\` and opens it in your default browser.

### Custom output location

```powershell
.\Invoke-DomainCheck.ps1 -Domain example.co.uk -OutputPath "C:\Reports\Clients"
```

### Parameters

| Parameter     | Required | Default      | Description                          |
|---------------|----------|--------------|--------------------------------------|
| `-Domain`     | Yes      | —            | The domain to assess                 |
| `-OutputPath` | No       | `.\Reports`  | Folder where the HTML report is saved |

### Output

Reports are named like this:

```
SecurityAssessment_<domain>_<yyyyMMdd_HHmmss>.html
```

### Scoring

| Score   | Risk rating |
|---------|-------------|
| 85%+    | Low         |
| 60–84%  | Medium      |
| < 60%   | High        |

The score is the number of checks passed divided by the total number of checks. Warnings count against the score.

### Notes

- The **Data Breach Check** is a placeholder for now. It always shows a warning until an API key is set up, which lowers the score slightly.
- The script ends with `Start-Process`, which opens the report automatically. When running headless (for example from an RMM tool), remove or comment out that line.

## Contributing

1. Fork the repository and create a feature branch:
   ```powershell
   git checkout -b feature/new-check
   ```
2. New checks should go in the matching module (`EmailChecks`, `WebChecks` or `InfrastructureChecks`) and return objects in this format:
   ```powershell
   [PSCustomObject]@{
       Check   = "Check Name"
       Status  = "Pass"   # Pass | Fail | Warn
       Details = "What was found / what to do"
   }
   ```
3. Test against at least one known-good domain and one known-bad domain before submitting.
4. Keep `Details` text client-friendly, because it appears directly in the report and recommendations.
5. Open a pull request describing the change and include a sample report if the layout changed.

## License

Copyright © ACC London. All rights reserved.

This tool is for internal use by ACC London and its authorised clients. Do not redistribute, modify for external use, or publish it without written permission. Reports produced by the tool are confidential and only for the intended recipients.
