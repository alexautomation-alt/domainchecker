#Requires -Version 5.1
<#
.SYNOPSIS
    Generates a security assessment report for a specified domain.

.DESCRIPTION
    Domain Checker runs email, web and infrastructure security checks against a
    domain, scores the results and produces a branded HTML report (ACC London)
    with a risk rating, grouped findings and recommendations.

    Checks are provided by three modules in the .\Modules folder:
        EmailChecks.psm1           -> Test-EmailSecurity
        WebChecks.psm1             -> Test-WebSecurity
        InfrastructureChecks.psm1  -> Test-Infrastructure

    Each check should return objects in this format:
        [PSCustomObject]@{
            Category    = "Email"            # Optional - defaults to the module's category
            Check       = "SPF Record"
            Status      = "Pass"             # Pass | Fail | Warn | Info
            Details     = "What was found"
            Remediation = "What to do"       # Optional - used in Recommendations
        }

    Scoring:
        Pass = 1 point, Warn = 0.5 points, Fail = 0 points.
        Info / skipped checks are shown in the report but NOT scored.
        Score % = points / scored checks.  85%+ = Low, 60-84% = Medium, <60% = High.

    Exit codes (for N-able RMM / scheduled tasks):
        0 = Report generated
        1 = Report could not be generated (fatal error)

.PARAMETER Domain
    The domain to assess, e.g. example.co.uk. URLs such as https://www.example.co.uk/
    are accepted and cleaned up automatically.

.PARAMETER OutputPath
    Folder to save the report in. Defaults to a "Reports" folder next to the script.

.PARAMETER NoOpen
    Do not open the report in the browser when finished. Use this when running
    headless (RMM, scheduled task, remote session).

.PARAMETER ExportJson
    Also save the raw results and summary as a JSON file next to the HTML report.
    Useful for tracking scores over time.

.PARAMETER LogoPath
    Optional path to a local logo image (png/jpg/svg). If supplied, the logo is
    embedded in the report so it displays offline and in email clients that block
    remote images. If not supplied, the ACC London website logo URL is used.

.PARAMETER PassThru
    Return a summary object (domain, score, risk, report path) to the pipeline.

.EXAMPLE
    .\Invoke-DomainCheck.ps1 -Domain example.co.uk

    Runs the assessment, saves the report to .\Reports and opens it.

.EXAMPLE
    .\Invoke-DomainCheck.ps1 -Domain example.co.uk -NoOpen -ExportJson -OutputPath "C:\Reports\Clients"

    Headless run for RMM, saving HTML and JSON to a custom folder.

.EXAMPLE
    "client1.co.uk","client2.com" | ForEach-Object {
        .\Invoke-DomainCheck.ps1 -Domain $_ -NoOpen -PassThru
    } | Format-Table Domain, Score, Risk

    Bulk run across several client domains with a summary table.

.NOTES
    Name    : Invoke-DomainCheck.ps1
    Version : 2.0.0
    Author  : Alex Wilson - ACC London

    ===========================================================================
    CHANGELOG
    ===========================================================================
    2.0.0
      Fixed
        - Results are now wrapped in @() before combining, so a module returning a
          single object no longer throws an op_Addition error.
        - All check text is HTML-encoded before it goes into the report, so
          records containing < > & no longer break the layout or inject markup.
        - High risk icon was blank. Risk icons now use HTML entities instead of
          raw emoji, so they survive PowerShell 5.1 file encoding.
        - Unknown statuses (e.g. "Error", "Skipped") no longer produce an empty
          badge. They are normalised to Info and shown as "Not scored".
        - Removed the overwrite of the automatic $PSScriptRoot variable and the
          Set-Location call that changed the caller's working directory. Paths
          are now built with Join-Path $PSScriptRoot.
        - Counts use @(...).Count so they are always correct (including 0 and 1).
        - Ring offset is formatted with invariant culture so the SVG renders on
          machines using a comma decimal separator.
      Added
        - [CmdletBinding()], #Requires and $ErrorActionPreference = 'Stop'.
        - Each module is imported and run in its own try/catch. If one fails, a
          Fail result is recorded for it and the rest of the report still builds.
        - Domain input is cleaned (scheme, path, www. kept, trailing dot removed)
          and validated before any checks run.
        - -NoOpen switch for headless/RMM runs.
        - -ExportJson switch to save results and summary as JSON.
        - -LogoPath to embed a local logo as base64.
        - -PassThru to return a summary object for pipelines and bulk runs.
        - Optional Remediation property per check, used in Recommendations.
        - Findings are grouped by category and sorted Fail > Warn > Info > Pass.
        - "Not scored" stat card and Info badge style.
        - RMM-friendly STATUS line and exit codes.
        - Full comment-based help (Get-Help .\Invoke-DomainCheck.ps1 -Full).
      Changed
        - Weighted scoring: Pass = 1, Warn = 0.5, Fail = 0. Info/skipped checks are
          excluded, so the maximum achievable score is genuinely 100%.
        - Data Breach Check placeholder is now Info (not scored) instead of Warn,
          so it no longer drags the score down.
        - Google Fonts removed in favour of a system font stack. The report works
          offline and does not send the recipient's IP address to Google.
        - Report is written as UTF-8 via .NET so output is consistent between
          PowerShell 5.1 and 7.
        - Removed leftover "FIX:" comments.

    1.0.0
        - Initial release: email, web and infrastructure checks, pass-rate score,
          risk rating and branded HTML report with dark mode.
    ===========================================================================
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Domain,

    [string]$OutputPath = (Join-Path $PSScriptRoot 'Reports'),

    [switch]$NoOpen,

    [switch]$ExportJson,

    [string]$LogoPath,

    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '2.0.0'

# =============================================================================
# Helper functions
# =============================================================================

function ConvertTo-HtmlSafe {
    # Encodes text so it can be safely placed inside HTML.
    param([AllowNull()][object]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function ConvertTo-CheckResult {
    # Normalises any object returned by a module into a consistent shape:
    # Category, Check, Status (Pass/Fail/Warn/Info), Details, Remediation.
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [Parameter(Mandatory)][string]$DefaultCategory
    )

    $props = $InputObject.PSObject.Properties

    $category = if ($props['Category'] -and $InputObject.Category) { [string]$InputObject.Category } else { $DefaultCategory }
    $check    = if ($props['Check'])   { [string]$InputObject.Check }   else { 'Unnamed check' }
    $details  = if ($props['Details']) { [string]$InputObject.Details } else { '' }
    $remedy   = if ($props['Remediation']) { [string]$InputObject.Remediation } else { '' }
    $rawState = if ($props['Status'])  { [string]$InputObject.Status }  else { '' }

    # switch is case-insensitive by default; anything unrecognised becomes Info.
    $status = switch -Regex ($rawState.Trim()) {
        '^pass(ed)?$'               { 'Pass'; break }
        '^fail(ed)?$'               { 'Fail'; break }
        '^warn(ing)?$'              { 'Warn'; break }
        default                     { 'Info' }
    }

    [PSCustomObject]@{
        Category    = $category
        Check       = $check
        Status      = $status
        Details     = $details
        Remediation = $remedy
    }
}

function Invoke-CheckModule {
    # Imports a check module and runs its test function in isolation.
    # If anything fails, a single Fail result is returned instead of stopping the script.
    param(
        [Parameter(Mandatory)][string]$ModuleFile,
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Domain
    )

    $modulePath = Join-Path (Join-Path $PSScriptRoot 'Modules') $ModuleFile

    try {
        if (-not (Test-Path -LiteralPath $modulePath)) {
            throw "Module file not found: $modulePath"
        }

        Import-Module $modulePath -Force -ErrorAction Stop

        if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
            throw "Command '$Command' was not exported by $ModuleFile"
        }

        Write-Verbose "Running $Command against $Domain"
        $raw = @(& $Command -Domain $Domain)

        if ($raw.Count -eq 0) {
            return @([PSCustomObject]@{
                Category    = $Category
                Check       = "$Category checks"
                Status      = 'Info'
                Details     = "No results were returned by $Command."
                Remediation = ''
            })
        }

        return @($raw | Where-Object { $null -ne $_ } | ForEach-Object {
            ConvertTo-CheckResult -InputObject $_ -DefaultCategory $Category
        })
    }
    catch {
        Write-Warning "$Category checks failed: $($_.Exception.Message)"
        return @([PSCustomObject]@{
            Category    = $Category
            Check       = "$Category checks"
            Status      = 'Fail'
            Details     = "Checks could not be completed: $($_.Exception.Message)"
            Remediation = "Re-run the assessment. If the problem persists, check $ModuleFile and network/DNS access from this machine."
        })
    }
}

# =============================================================================
# Main
# =============================================================================

try {
    # -------------------------------------------------------------------------
    # Clean and validate the domain
    # Accepts input like "https://www.example.co.uk/path" -> "www.example.co.uk"
    # -------------------------------------------------------------------------
    $Domain = $Domain.Trim().ToLowerInvariant()
    $Domain = $Domain -replace '^[a-z]+://', ''   # strip scheme
    $Domain = ($Domain -split '[/?#:]')[0]         # strip path, query, port
    $Domain = $Domain.TrimEnd('.')                  # strip trailing dot

    $domainPattern = '^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
    if ($Domain -notmatch $domainPattern) {
        throw "'$Domain' is not a valid domain name."
    }

    Write-Host ""
    Write-Host "  Domain Checker v$ScriptVersion" -ForegroundColor Cyan
    Write-Host "  Assessing: $Domain" -ForegroundColor Cyan
    Write-Host ""

    # -------------------------------------------------------------------------
    # Prepare output folder
    # -------------------------------------------------------------------------
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # -------------------------------------------------------------------------
    # Run checks (each module isolated so one failure doesn't stop the report)
    # -------------------------------------------------------------------------
    $emailResults = Invoke-CheckModule -ModuleFile 'EmailChecks.psm1'          -Command 'Test-EmailSecurity'  -Category 'Email'          -Domain $Domain
    $webResults   = Invoke-CheckModule -ModuleFile 'WebChecks.psm1'            -Command 'Test-WebSecurity'    -Category 'Web'            -Domain $Domain
    $infraResults = Invoke-CheckModule -ModuleFile 'InfrastructureChecks.psm1' -Command 'Test-Infrastructure' -Category 'Infrastructure' -Domain $Domain

    # Placeholder until a breach API key is configured. Info = shown, not scored.
    $breachResults = @([PSCustomObject]@{
        Category    = 'Threat Intelligence'
        Check       = 'Data Breach Check'
        Status      = 'Info'
        Details     = 'Not run - API key required.'
        Remediation = ''
    })

    $allResults = @($emailResults) + @($webResults) + @($infraResults) + @($breachResults)

    # -------------------------------------------------------------------------
    # Summary stats and weighted score
    # -------------------------------------------------------------------------
    $counts = [ordered]@{
        Pass = @($allResults | Where-Object Status -eq 'Pass').Count
        Fail = @($allResults | Where-Object Status -eq 'Fail').Count
        Warn = @($allResults | Where-Object Status -eq 'Warn').Count
        Info = @($allResults | Where-Object Status -eq 'Info').Count
    }

    $total       = $allResults.Count
    $scoredTotal = $counts.Pass + $counts.Fail + $counts.Warn
    $points      = $counts.Pass + ($counts.Warn * 0.5)

    $scorePercent = if ($scoredTotal -gt 0) {
        [int][math]::Round(($points / $scoredTotal) * 100, 0)
    } else { 0 }

    $riskRating = if ($scorePercent -ge 85) { 'Low' } elseif ($scorePercent -ge 60) { 'Medium' } else { 'High' }

    $riskWord = @{ Low = 'minimal'; Medium = 'moderate'; High = 'significant' }[$riskRating]

    # HTML entities avoid emoji encoding issues in PowerShell 5.1
    $riskIcon = @{
        Low    = '&#x2705;'          # green tick
        Medium = '&#x26A0;&#xFE0F;'  # warning sign
        High   = '&#x1F534;'         # red circle
    }[$riskRating]

    $ringStroke = @{ Low = 'var(--ring-pass)'; Medium = 'var(--ring-warn)'; High = 'var(--ring-fail)' }[$riskRating]

    $ringOffset = [math]::Round(314.16 - (314.16 * $scorePercent / 100), 2).ToString([System.Globalization.CultureInfo]::InvariantCulture)

    # -------------------------------------------------------------------------
    # Build findings table - grouped by category, worst status first
    # -------------------------------------------------------------------------
    $severityOrder = @{ Fail = 0; Warn = 1; Info = 2; Pass = 3 }
    $categoryOrder = @{ 'Email' = 0; 'Web' = 1; 'Infrastructure' = 2; 'Threat Intelligence' = 3 }
    $badgeClass    = @{ Pass = 'pass'; Fail = 'fail'; Warn = 'warn'; Info = 'info' }

    $sortedResults = $allResults | Sort-Object `
        @{ Expression = { if ($categoryOrder.ContainsKey($_.Category)) { $categoryOrder[$_.Category] } else { 99 } } },
        @{ Expression = { $_.Category } },
        @{ Expression = { $severityOrder[$_.Status] } },
        @{ Expression = { $_.Check } }

    $rowBuilder   = New-Object System.Text.StringBuilder
    $lastCategory = $null

    foreach ($r in $sortedResults) {
        if ($r.Category -ne $lastCategory) {
            [void]$rowBuilder.AppendLine("<tr class=`"group-row`"><td colspan=`"3`">$(ConvertTo-HtmlSafe $r.Category)</td></tr>")
            $lastCategory = $r.Category
        }
        $cls   = $badgeClass[$r.Status]
        $badge = "<span class=`"badge $cls`">$($r.Status)</span>"
        [void]$rowBuilder.AppendLine("<tr><td>$(ConvertTo-HtmlSafe $r.Check)</td><td>$badge</td><td>$(ConvertTo-HtmlSafe $r.Details)</td></tr>")
    }
    $findingsRows = $rowBuilder.ToString()

    # -------------------------------------------------------------------------
    # Recommendations - Fails first, then Warns. Uses Remediation if provided.
    # -------------------------------------------------------------------------
    $recResults = @($allResults |
        Where-Object { $_.Status -in 'Fail', 'Warn' } |
        Sort-Object @{ Expression = { $severityOrder[$_.Status] } }, Category, Check)

    $recItems = ($recResults | ForEach-Object {
        $tag  = if ($_.Status -eq 'Fail') { '<span class="badge fail">Fail</span>' } else { '<span class="badge warn">Warn</span>' }
        $text = if ([string]::IsNullOrWhiteSpace($_.Remediation)) { $_.Details } else { $_.Remediation }
        "<li class=`"rec-$($_.Status.ToLower())`">$tag <strong>$(ConvertTo-HtmlSafe $_.Check):</strong> $(ConvertTo-HtmlSafe $text)</li>"
    }) -join "`n"

    if ([string]::IsNullOrWhiteSpace($recItems)) {
        $recItems = '<li class="rec-pass"><span class="badge pass">OK</span> No significant issues identified.</li>'
    }

    # -------------------------------------------------------------------------
    # Logo - embed local file if supplied, otherwise use the website URL
    # -------------------------------------------------------------------------
    $logoSrc = 'https://www.accldn.com/wp-content/uploads/2024/01/ACC-logo-2-200x73.png'
    if ($LogoPath) {
        if (Test-Path -LiteralPath $LogoPath) {
            $ext  = [System.IO.Path]::GetExtension($LogoPath).TrimStart('.').ToLowerInvariant()
            $mime = switch ($ext) { 'svg' { 'image/svg+xml' } 'jpg' { 'image/jpeg' } 'jpeg' { 'image/jpeg' } default { "image/$ext" } }
            $logoSrc = "data:$mime;base64," + [Convert]::ToBase64String([System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $LogoPath)))
        } else {
            Write-Warning "Logo not found at '$LogoPath'. Using website logo instead."
        }
    }

    $generated = (Get-Date).ToUniversalTime().ToString("dd MMM yyyy HH:mm 'UTC'")

    # -------------------------------------------------------------------------
    # HTML report
    # -------------------------------------------------------------------------
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Assessment - $Domain</title>
<style>
:root{
--bg:#f0f2f5;--surface:#fff;--surface-alt:#f8f9fb;--border:#e2e5ea;
--text:#1a1a2e;--text-muted:#5c6370;--accent:#2563eb;--accent-light:#dbeafe;
--header-bg:#0f172a;--header-text:#fff;
--pass-bg:#ecfdf5;--pass-fg:#065f46;--pass-bdr:#6ee7b7;
--fail-bg:#fef2f2;--fail-fg:#991b1b;--fail-bdr:#fca5a5;
--warn-bg:#fffbeb;--warn-fg:#92400e;--warn-bdr:#fcd34d;
--info-bg:#eff6ff;--info-fg:#1e40af;--info-bdr:#93c5fd;
--ring-pass:#22c55e;--ring-fail:#ef4444;--ring-warn:#f59e0b;--ring-info:#3b82f6;--ring-track:#e5e7eb;
--shadow:0 1px 3px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);
--shadow-lg:0 10px 25px rgba(0,0,0,.07);
}
[data-theme="dark"]{
--bg:#0f172a;--surface:#1e293b;--surface-alt:#1a2436;--border:#334155;
--text:#e2e8f0;--text-muted:#94a3b8;--accent:#60a5fa;--accent-light:#1e3a5f;
--header-bg:#020617;--header-text:#f1f5f9;
--pass-bg:#052e16;--pass-fg:#86efac;--pass-bdr:#166534;
--fail-bg:#450a0a;--fail-fg:#fca5a5;--fail-bdr:#7f1d1d;
--warn-bg:#451a03;--warn-fg:#fcd34d;--warn-bdr:#78350f;
--info-bg:#172554;--info-fg:#93c5fd;--info-bdr:#1e40af;
--ring-pass:#4ade80;--ring-fail:#f87171;--ring-warn:#fbbf24;--ring-info:#60a5fa;--ring-track:#334155;
--shadow:0 1px 3px rgba(0,0,0,.3);--shadow-lg:0 10px 25px rgba(0,0,0,.4);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:'Segoe UI',system-ui,-apple-system,Roboto,'Helvetica Neue',Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;transition:background .3s,color .3s}
.header{background:var(--header-bg);color:var(--header-text);padding:16px 24px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;position:sticky;top:0;z-index:100;box-shadow:0 2px 8px rgba(0,0,0,.25)}
.header-left{display:flex;align-items:center;gap:16px}
.header img{height:40px}
.header .title{font-size:clamp(1rem,2.5vw,1.35rem);font-weight:700;letter-spacing:-.02em}
.header .domain-chip{font-size:.8rem;background:rgba(255,255,255,.12);padding:4px 12px;border-radius:20px;font-weight:500}
.theme-toggle{background:none;border:2px solid rgba(255,255,255,.25);color:var(--header-text);border-radius:8px;padding:6px 12px;font-size:.85rem;cursor:pointer;transition:border-color .2s;font-family:inherit}
.theme-toggle:hover{border-color:rgba(255,255,255,.6)}
.wrapper{max-width:1100px;margin:0 auto;padding:24px 16px 60px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:28px;margin-bottom:24px;box-shadow:var(--shadow);transition:background .3s,border-color .3s}
.card h2{font-size:1.25rem;margin-bottom:18px;display:flex;align-items:center;gap:8px}
.dashboard{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:18px;margin-bottom:24px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:24px;text-align:center;box-shadow:var(--shadow);transition:transform .2s,box-shadow .2s,background .3s}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow-lg)}
.stat-card .stat-value{font-size:2.2rem;font-weight:700}
.stat-card .stat-label{font-size:.85rem;color:var(--text-muted);margin-top:4px}
.ring-wrap{position:relative;width:120px;height:120px;margin:0 auto 8px}
.ring-wrap svg{transform:rotate(-90deg)}
.ring-track{fill:none;stroke:var(--ring-track);stroke-width:10}
.ring-fill{fill:none;stroke-width:10;stroke-linecap:round;transition:stroke-dashoffset .8s ease}
.ring-label{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;font-weight:700;font-size:1.5rem}
.ring-label small{font-size:.7rem;font-weight:500;color:var(--text-muted)}
.c-pass{color:var(--ring-pass)}.c-fail{color:var(--ring-fail)}.c-warn{color:var(--ring-warn)}.c-info{color:var(--ring-info)}
.risk-badge{display:inline-flex;align-items:center;gap:6px;padding:6px 16px;border-radius:8px;font-weight:600;font-size:.95rem}
.risk-low{background:var(--pass-bg);color:var(--pass-fg);border:1px solid var(--pass-bdr)}
.risk-medium{background:var(--warn-bg);color:var(--warn-fg);border:1px solid var(--warn-bdr)}
.risk-high{background:var(--fail-bg);color:var(--fail-fg);border:1px solid var(--fail-bdr)}
.table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{padding:12px 14px;text-align:left;border-bottom:1px solid var(--border);vertical-align:top}
td{word-break:break-word}
th{background:var(--header-bg);color:var(--header-text);font-weight:600;position:sticky;top:0}
th:first-child{border-radius:8px 0 0 0}th:last-child{border-radius:0 8px 0 0}
tr{transition:background .15s}tr:hover{background:var(--accent-light)}
.group-row td{background:var(--surface-alt);font-weight:700;font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted)}
.group-row:hover{background:none}
.badge{display:inline-block;padding:3px 12px;border-radius:20px;font-size:.78rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.badge.pass{background:var(--pass-bg);color:var(--pass-fg);border:1px solid var(--pass-bdr)}
.badge.fail{background:var(--fail-bg);color:var(--fail-fg);border:1px solid var(--fail-bdr)}
.badge.warn{background:var(--warn-bg);color:var(--warn-fg);border:1px solid var(--warn-bdr)}
.badge.info{background:var(--info-bg);color:var(--info-fg);border:1px solid var(--info-bdr)}
.rec-list{list-style:none;padding:0}
.rec-list li{padding:12px 16px;border-left:4px solid var(--border);margin-bottom:10px;background:var(--surface-alt);border-radius:0 8px 8px 0;font-size:.92rem;transition:background .3s}
.rec-list li.rec-fail{border-left-color:var(--ring-fail)}
.rec-list li.rec-warn{border-left-color:var(--ring-warn)}
.rec-list li.rec-pass{border-left-color:var(--ring-pass)}
.footer{background:var(--header-bg);color:var(--header-text);padding:28px 24px;text-align:center;font-size:.82rem;line-height:1.8;border-top:3px solid var(--accent)}
.footer a{color:var(--accent);text-decoration:none}.footer a:hover{text-decoration:underline}
@media(max-width:600px){.header{padding:12px 14px}.card{padding:18px 14px}.wrapper{padding:14px 8px 40px}th,td{padding:10px 8px;font-size:.82rem}}
@media print{body{background:#fff}.header,.footer{position:static}.theme-toggle{display:none}.stat-card:hover{transform:none}}
</style>
</head>
<body>
<div class="header">
<div class="header-left">
<img src="$logoSrc" alt="ACC London">
<div>
<div class="title">Security Assessment Report</div>
<span class="domain-chip">$Domain</span>
</div>
</div>
<button class="theme-toggle" id="themeBtn" aria-label="Toggle dark mode">Dark Mode</button>
</div>
<div class="wrapper">
<div class="dashboard">
<div class="stat-card">
<div class="ring-wrap">
<svg viewBox="0 0 120 120" width="120" height="120">
<circle class="ring-track" cx="60" cy="60" r="50"/>
<circle class="ring-fill" cx="60" cy="60" r="50" stroke="$ringStroke" stroke-dasharray="314.16" stroke-dashoffset="$ringOffset"/>
</svg>
<div class="ring-label">${scorePercent}%<small>SCORE</small></div>
</div>
<div class="stat-label">Overall Security Score</div>
</div>
<div class="stat-card"><div class="stat-value c-pass">$($counts.Pass)</div><div class="stat-label">Passed</div></div>
<div class="stat-card"><div class="stat-value c-fail">$($counts.Fail)</div><div class="stat-label">Failed</div></div>
<div class="stat-card"><div class="stat-value c-warn">$($counts.Warn)</div><div class="stat-label">Warnings</div></div>
<div class="stat-card"><div class="stat-value c-info">$($counts.Info)</div><div class="stat-label">Not Scored</div></div>
</div>
<div class="card">
<h2>Executive Summary</h2>
<p>This report provides a high-level security assessment for <strong>$Domain</strong>, covering <strong>email</strong>, <strong>web</strong>, and <strong>infrastructure</strong> controls.</p>
<p style="margin-top:12px;"><strong>Risk Rating:</strong> <span class="risk-badge risk-$($riskRating.ToLower())">$riskIcon $riskRating Risk</span></p>
<p style="margin-top:12px;color:var(--text-muted);font-size:.9rem;">The organisation has <strong>$riskWord</strong> exposure to common attack vectors such as phishing, misconfiguration, and service enumeration. <strong>$($counts.Pass)</strong> of <strong>$scoredTotal</strong> scored checks passed, with <strong>$($counts.Warn)</strong> warning(s) and <strong>$($counts.Fail)</strong> failure(s).</p>
</div>
<div class="card">
<h2>Findings</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Check</th><th>Status</th><th>Details</th></tr></thead>
<tbody>
$findingsRows
</tbody>
</table>
</div>
</div>
<div class="card">
<h2>Recommendations</h2>
<ul class="rec-list">
$recItems
</ul>
</div>
<div class="card" style="font-size:.82rem;color:var(--text-muted);">
<h2>Report Metadata</h2>
<p><strong>Domain:</strong> $Domain</p>
<p><strong>Generated:</strong> $generated</p>
<p><strong>Checks run:</strong> $total ($scoredTotal scored, $($counts.Info) not scored)</p>
<p><strong>Scoring:</strong> Pass = 1, Warning = 0.5, Fail = 0. Informational checks are not scored.</p>
<p><strong>Tool version:</strong> Domain Checker v$ScriptVersion</p>
</div>
</div>
<div class="footer">
<p><strong>ACC London</strong></p>
<p>59 George Ln, London E18 1JJ | 020 8518 8353</p>
<p><a href="mailto:helpdesk@accldn.com">helpdesk@accldn.com</a> | <a href="https://www.accldn.com" target="_blank" rel="noopener">www.accldn.com</a></p>
<p style="margin-top:8px;opacity:.6;">Confidential - for intended recipients only.</p>
</div>
<script>
(function(){
var btn=document.getElementById('themeBtn');
var root=document.documentElement;
var PREF='acc-theme';
var saved=null;
try{saved=localStorage.getItem(PREF);}catch(e){}
if(saved){root.setAttribute('data-theme',saved)}
else if(window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches){root.setAttribute('data-theme','dark')}
updateBtn();
btn.addEventListener('click',function(){
var next=root.getAttribute('data-theme')==='dark'?'light':'dark';
root.setAttribute('data-theme',next);
try{localStorage.setItem(PREF,next);}catch(e){}
updateBtn();
});
function updateBtn(){
var dark=root.getAttribute('data-theme')==='dark';
btn.textContent=dark?'Light Mode':'Dark Mode';
}
})();
</script>
</body>
</html>
"@

    # -------------------------------------------------------------------------
    # Save report (UTF-8 via .NET for consistent output on PS 5.1 and 7)
    # -------------------------------------------------------------------------
    $stamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
    $baseName   = "SecurityAssessment_${Domain}_$stamp"
    $resolvedOut = (Resolve-Path -LiteralPath $OutputPath).Path
    $reportFile = Join-Path $resolvedOut "$baseName.html"

    [System.IO.File]::WriteAllText($reportFile, $html, (New-Object System.Text.UTF8Encoding($false)))

    # -------------------------------------------------------------------------
    # Optional JSON export
    # -------------------------------------------------------------------------
    $jsonFile = $null
    if ($ExportJson) {
        $jsonFile = Join-Path $resolvedOut "$baseName.json"
        $export = [ordered]@{
            Domain        = $Domain
            Generated     = $generated
            ToolVersion   = $ScriptVersion
            Score         = $scorePercent
            Risk          = $riskRating
            Counts        = $counts
            Results       = $allResults
        }
        $export | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonFile -Encoding UTF8
    }

    # -------------------------------------------------------------------------
    # Console / RMM output
    # -------------------------------------------------------------------------
    $statusColour = @{ Low = 'Green'; Medium = 'Yellow'; High = 'Red' }[$riskRating]

    Write-Host "  STATUS: OK | Domain: $Domain | Score: $scorePercent% | Risk: $riskRating | Pass: $($counts.Pass) Warn: $($counts.Warn) Fail: $($counts.Fail) Info: $($counts.Info)" -ForegroundColor $statusColour
    Write-Host "  Report saved: $reportFile" -ForegroundColor Green
    if ($jsonFile) { Write-Host "  JSON saved:   $jsonFile" -ForegroundColor Green }
    Write-Host ""

    if (-not $NoOpen) {
        try { Start-Process -FilePath $reportFile }
        catch { Write-Warning "Could not open the report automatically: $($_.Exception.Message)" }
    }

    if ($PassThru) {
        [PSCustomObject]@{
            Domain     = $Domain
            Score      = $scorePercent
            Risk       = $riskRating
            Pass       = $counts.Pass
            Warn       = $counts.Warn
            Fail       = $counts.Fail
            Info       = $counts.Info
            ReportPath = $reportFile
            JsonPath   = $jsonFile
        }
    }
}
catch {
    Write-Host "  STATUS: ERROR | Domain: $Domain | $($_.Exception.Message)" -ForegroundColor Red
    Write-Error $_
    exit 1
}
