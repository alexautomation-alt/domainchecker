<#
.SYNOPSIS
    Generates a comprehensive security assessment report for a specified domain.
#>

param(
    [Parameter(Mandatory = $true)][string]$Domain,
    [string]$OutputPath = ".\Reports"
)

# =========================
# FIX: Always run from script directory
# =========================
if ($PSScriptRoot) {
    Set-Location $PSScriptRoot
} else {
    $PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    Set-Location $PSScriptRoot
}

# =========================
# Initialize output directory
# =========================
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

# =========================
# FIX: Correct module paths using $PSScriptRoot
# =========================
Import-Module "$PSScriptRoot\Modules\EmailChecks.psm1" -Force
Import-Module "$PSScriptRoot\Modules\WebChecks.psm1" -Force
Import-Module "$PSScriptRoot\Modules\InfrastructureChecks.psm1" -Force

# =========================
# Execute security checks
# =========================
$emailResults = Test-EmailSecurity   -Domain $Domain
$webResults   = Test-WebSecurity     -Domain $Domain
$infraResults = Test-Infrastructure  -Domain $Domain

# Placeholder for breach checks
$breachResults = @([PSCustomObject]@{
    Check   = "Data Breach Check"
    Status  = "Warn"
    Details = "Disabled - API key required"
})

# =========================
# Combine results
# =========================
$allResults = $emailResults + $webResults + $infraResults + $breachResults

# =========================
# Summary stats
# =========================
$counts = @{
    Pass = ($allResults | Where-Object Status -eq "Pass").Count
    Fail = ($allResults | Where-Object Status -eq "Fail").Count
    Warn = ($allResults | Where-Object Status -eq "Warn").Count
}

$total = $allResults.Count
$scorePercent = if ($total -gt 0) {
    [math]::Round(($counts.Pass / $total) * 100, 0)
} else {
    0
}

# Risk rating
$riskRating = switch ($scorePercent) {
    { $_ -ge 85 } { "Low"; break }
    { $_ -ge 60 } { "Medium"; break }
    default { "High" }
}

$riskWord = switch ($riskRating) {
    "Low" { "minimal" }
    "Medium" { "moderate" }
    "High" { "significant" }
}

# =========================
# Build findings table
# =========================
$findingsRows = ($allResults | ForEach-Object {
    $badge = switch ($_.Status) {
        "Pass" { '<span class="badge pass">Pass</span>' }
        "Fail" { '<span class="badge fail">Fail</span>' }
        "Warn" { '<span class="badge warn">Warn</span>' }
    }
    "<tr><td>$($_.Check)</td><td>$badge</td><td>$($_.Details)</td></tr>"
}) -join "`n"

# Recommendations
$recItems = ($allResults | Where-Object Status -ne "Pass" | ForEach-Object {
    $icon = if ($_.Status -eq "Fail") { "[FAIL]" } else { "[WARN]" }
    "<li>$icon <strong>$($_.Check):</strong> $($_.Details)</li>"
}) -join "`n"

if ([string]::IsNullOrWhiteSpace($recItems)) {
    $recItems = "<li>[OK] No significant issues identified.</li>"
}

# Timestamp
$generated = (Get-Date).ToUniversalTime().ToString("dd MMM yyyy HH:mm 'UTC'")

# Risk visuals
$riskIcon = switch ($riskRating) {
    "Low" { "&#9989;" }
    "Medium" { "&#9888;&#65039;" }
    "High" { "&#128308;" }
}

$ringStroke = switch ($riskRating) {
    "Low" { "var(--ring-pass)" }
    "Medium" { "var(--ring-warn)" }
    default { "var(--ring-fail)" }
}

$ringOffset = 314.16 - (314.16 * $scorePercent / 100)

# =========================
# HTML REPORT (UNCHANGED BELOW THIS POINT)
# =========================
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Assessment - $Domain</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
--bg:#f0f2f5;--surface:#fff;--surface-alt:#f8f9fb;--border:#e2e5ea;
--text:#1a1a2e;--text-muted:#5c6370;--accent:#2563eb;--accent-light:#dbeafe;
--header-bg:#0f172a;--header-text:#fff;
--pass-bg:#ecfdf5;--pass-fg:#065f46;--pass-bdr:#6ee7b7;
--fail-bg:#fef2f2;--fail-fg:#991b1b;--fail-bdr:#fca5a5;
--warn-bg:#fffbeb;--warn-fg:#92400e;--warn-bdr:#fcd34d;
--ring-pass:#22c55e;--ring-fail:#ef4444;--ring-warn:#f59e0b;--ring-track:#e5e7eb;
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
--ring-pass:#4ade80;--ring-fail:#f87171;--ring-warn:#fbbf24;--ring-track:#334155;
--shadow:0 1px 3px rgba(0,0,0,.3);--shadow-lg:0 10px 25px rgba(0,0,0,.4);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;transition:background .3s,color .3s}
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
.dashboard{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:18px;margin-bottom:24px}
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
.c-pass{color:var(--ring-pass)}.c-fail{color:var(--ring-fail)}.c-warn{color:var(--ring-warn)}
.risk-badge{display:inline-flex;align-items:center;gap:6px;padding:6px 16px;border-radius:8px;font-weight:600;font-size:.95rem}
.risk-low{background:var(--pass-bg);color:var(--pass-fg);border:1px solid var(--pass-bdr)}
.risk-medium{background:var(--warn-bg);color:var(--warn-fg);border:1px solid var(--warn-bdr)}
.risk-high{background:var(--fail-bg);color:var(--fail-fg);border:1px solid var(--fail-bdr)}
.table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{padding:12px 14px;text-align:left;border-bottom:1px solid var(--border)}
th{background:var(--header-bg);color:var(--header-text);font-weight:600;position:sticky;top:0}
th:first-child{border-radius:8px 0 0 0}th:last-child{border-radius:0 8px 0 0}
tr{transition:background .15s}tr:hover{background:var(--accent-light)}
.badge{display:inline-block;padding:3px 12px;border-radius:20px;font-size:.78rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.badge.pass{background:var(--pass-bg);color:var(--pass-fg);border:1px solid var(--pass-bdr)}
.badge.fail{background:var(--fail-bg);color:var(--fail-fg);border:1px solid var(--fail-bdr)}
.badge.warn{background:var(--warn-bg);color:var(--warn-fg);border:1px solid var(--warn-bdr)}
.rec-list{list-style:none;padding:0}
.rec-list li{padding:12px 16px;border-left:4px solid var(--border);margin-bottom:10px;background:var(--surface-alt);border-radius:0 8px 8px 0;font-size:.92rem;transition:background .3s}
.footer{background:var(--header-bg);color:var(--header-text);padding:28px 24px;text-align:center;font-size:.82rem;line-height:1.8;border-top:3px solid var(--accent)}
.footer a{color:var(--accent);text-decoration:none}.footer a:hover{text-decoration:underline}
@media(max-width:600px){.header{padding:12px 14px}.card{padding:18px 14px}.wrapper{padding:14px 8px 40px}th,td{padding:10px 8px;font-size:.82rem}}
@media print{body{background:#fff}.header,.footer{position:static}.theme-toggle{display:none}.stat-card:hover{transform:none}}
</style>
</head>
<body>
<div class="header">
<div class="header-left">
<img src="https://www.accldn.com/wp-content/uploads/2024/01/ACC-logo-2-200x73.png" alt="ACC London">
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
<div class="stat-card">
<div class="stat-value c-pass">$($counts.Pass)</div>
<div class="stat-label">Passed</div>
</div>
<div class="stat-card">
<div class="stat-value c-fail">$($counts.Fail)</div>
<div class="stat-label">Failed</div>
</div>
<div class="stat-card">
<div class="stat-value c-warn">$($counts.Warn)</div>
<div class="stat-label">Warnings</div>
</div>
</div>
<div class="card">
<h2>Executive Summary</h2>
<p>This report provides a high-level security assessment for <strong>$Domain</strong>, covering <strong>email</strong>, <strong>web</strong>, and <strong>infrastructure</strong> controls.</p>
<p style="margin-top:12px;"><strong>Risk Rating:</strong> <span class="risk-badge risk-$($riskRating.ToLower())">$riskIcon $riskRating Risk</span></p>
<p style="margin-top:12px;color:var(--text-muted);font-size:.9rem;">The organisation has <strong>$riskWord</strong> exposure to common attack vectors such as phishing, misconfiguration, and service enumeration. <strong>$($counts.Pass)</strong> of <strong>$total</strong> checks passed.</p>
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
<p><strong>Checks run:</strong> $total</p>
</div>
</div>
<div class="footer">
<p><strong>ACC London</strong></p>
<p>59 George Ln, London E18 1JJ | 020 8518 8353</p>
<p><a href="mailto:helpdesk@accldn.com">helpdesk@accldn.com</a> | <a href="https://www.accldn.com" target="_blank">www.accldn.com</a></p>
<p style="margin-top:8px;opacity:.6;">Confidential - for intended recipients only.</p>
</div>
<script>
(function(){
var btn=document.getElementById('themeBtn');
var root=document.documentElement;
var PREF='acc-theme';
var saved=localStorage.getItem(PREF);
if(saved){root.setAttribute('data-theme',saved)}
else if(window.matchMedia('(prefers-color-scheme:dark)').matches){root.setAttribute('data-theme','dark')}
updateBtn();
btn.addEventListener('click',function(){
var next=root.getAttribute('data-theme')==='dark'?'light':'dark';
root.setAttribute('data-theme',next);
localStorage.setItem(PREF,next);
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

# =========================
# Save report
# =========================
$reportFile = Join-Path $OutputPath "SecurityAssessment_${Domain}_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
$html | Out-File $reportFile -Encoding UTF8

Write-Host ""
Write-Host "  Report saved: $reportFile" -ForegroundColor Green
Write-Host ""

Start-Process $reportFile