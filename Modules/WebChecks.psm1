<#
.SYNOPSIS
    Web and mail transport checks for Domain Checker.

.DESCRIPTION
    Exposes Test-WebSecurity, which returns one result object per check in the
    format expected by Invoke-DomainCheck.ps1:

        Category    = "Web" or "Email"
        Check       = "SSL Certificate"
        Status      = "Pass" | "Fail" | "Warn" | "Info"
        Details     = What was found
        Remediation = What to do about it (blank when nothing to do)

    Web checks (Category = Web):
        SSL Certificate        - validity, hostname match, trusted chain, expiry, TLS version
        HTTPS Redirect         - http:// redirects to https://
        HSTS Header            - present with a sensible max-age
        CSP Header             - Content-Security-Policy present (enforced, not report-only)
        Clickjacking Header    - X-Frame-Options or CSP frame-ancestors
        MIME Sniffing Header   - X-Content-Type-Options: nosniff
        Referrer Header        - Referrer-Policy present and not unsafe-url
        Server Disclosure      - Server / X-Powered-By leaking software versions

    Mail transport checks (Category = Email):
        MTA-STS DNS Record     - _mta-sts TXT record (v=STSv1; id=...)
        MTA-STS Policy         - policy file, mode, max_age, MX hosts match real MX
        TLS-RPT Record         - _smtp._tls TXT record for TLS failure reports

.NOTES
    Module  : WebChecks.psm1
    Version : 2.0.0
    Author  : Alex Wilson - ACC London
    Requires: Windows (Resolve-DnsName / DnsClient module)

    ===========================================================================
    CHANGELOG
    ===========================================================================
    2.0.0
      Fixed
        - Windows PowerShell 5.1 can default to TLS 1.0, so HTTPS checks failed
          against modern sites ("Could not create SSL/TLS secure channel").
          TLS 1.2 is now enabled for the session.
        - Certificate expiry was parsed from a culture-specific date string
          (GetExpirationDateString), which could misread dd/MM vs MM/dd. Now uses
          the certificate's NotAfter date directly.
        - SSL check used HEAD and failed the certificate if the site returned an
          error (e.g. 405 Method Not Allowed), even when the certificate was fine.
          The certificate is now read directly from the TLS handshake.
        - Cached ServicePoint certificates could be reported instead of the live one.
        - Header check used HEAD with no timeout, so it could hang, and a 403/405
          lost all header results. Now uses GET with a timeout and still reads
          headers from error responses.
        - Header check only tried https://<domain>. If the bare domain has no
          website, www.<domain> is now tried for all web checks.
        - X-Frame-Options was failed even when CSP frame-ancestors covered it.
        - "X-Content-Type-Options" was passed for any value, not just "nosniff".
        - MTA-STS DNS lookups that timed out were reported as "No TXT record".
        - MTA-STS policy check failed when skipped, counting the same problem
          twice. A skipped policy check is now Info (not scored).
      Added
        - Certificate hostname mismatch and untrusted chain (self-signed /
          missing intermediate) detection, issuer and negotiated TLS version.
        - HTTPS Redirect check.
        - HSTS max-age check, CSP report-only detection, Referrer-Policy value check.
        - Server Disclosure check (version numbers in Server / X-Powered-By).
        - MTA-STS: multiple records, missing id=, redirect on policy URL,
          Content-Type, max_age upper limit, and policy MX entries compared
          against the domain's real MX records.
        - TLS-RPT check.
        - -DnsServer to query a specific resolver (e.g. 1.1.1.1).
        - Remediation text and Category on every result.
      Changed
        - MTA-STS / TLS-RPT results are now Category "Email" so they group
          with SPF, DMARC and DKIM in the report.
        - Missing CSP, Clickjacking, MIME Sniffing and Referrer headers are now
          Warn instead of Fail. Missing HSTS stays a Fail.
        - MTA-STS not configured is now Warn instead of Fail (optional control).

    1.0.0
        - Initial SSL certificate, security header and MTA-STS checks.
    ===========================================================================
#>

# =============================================================================
# Helpers (not exported)
# =============================================================================

function Initialize-TlsProtocol {
    # Windows PowerShell 5.1 / .NET Framework may not offer TLS 1.2 by default.
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch {}
}

function New-CheckResult {
    param([string]$Category, [string]$Check, [string]$Status, [string]$Details, [string]$Remediation = '')
    [PSCustomObject]@{
        Category    = $Category
        Check       = $Check
        Status      = $Status
        Details     = $Details
        Remediation = $Remediation
    }
}

function Get-WorstStatus {
    # Returns the more serious of two statuses: Fail > Warn > Pass.
    param([string]$Current, [string]$New)
    $rank = @{ Pass = 0; Warn = 1; Fail = 2 }
    if ($rank[$New] -gt $rank[$Current]) { return $New }
    return $Current
}

function Get-InnerMessage {
    # Returns the most useful error message from a (possibly wrapped) exception.
    param($Exception)
    $ex = $Exception
    while ($ex.InnerException) { $ex = $ex.InnerException }
    return $ex.Message
}

function Get-DnsTxt {
    # Status = Found | NotFound | Error; Records = TXT strings (chunks joined)
    param([Parameter(Mandatory)][string]$Name, [string]$Server)

    $params = @{ Name = $Name; Type = 'TXT'; DnsOnly = $true; ErrorAction = 'Stop' }
    if ($Server) { $params.Server = $Server }

    try {
        $answers = @(Resolve-DnsName @params | Where-Object { $_.QueryType -eq 'TXT' })
        $records = @($answers | ForEach-Object { ($_.Strings -join '') })
        if ($records.Count -gt 0) { return [PSCustomObject]@{ Status = 'Found'; Records = $records; Message = '' } }
        return [PSCustomObject]@{ Status = 'NotFound'; Records = @(); Message = '' }
    }
    catch {
        if ($_.FullyQualifiedErrorId -match 'DNS_ERROR_RCODE_NAME_ERROR|DNS_INFO_NO_RECORDS|9003|9501') {
            return [PSCustomObject]@{ Status = 'NotFound'; Records = @(); Message = '' }
        }
        return [PSCustomObject]@{ Status = 'Error'; Records = @(); Message = $_.Exception.Message }
    }
}

function Get-MxHosts {
    param([string]$Domain, [string]$Server)
    $params = @{ Name = $Domain; Type = 'MX'; DnsOnly = $true; ErrorAction = 'Stop' }
    if ($Server) { $params.Server = $Server }
    try {
        @(Resolve-DnsName @params |
            Where-Object { $_.QueryType -eq 'MX' -and $_.NameExchange } |
            ForEach-Object { $_.NameExchange.TrimEnd('.').ToLowerInvariant() } |
            Sort-Object -Unique)
    } catch { @() }
}

function Get-TlsInfo {
    # Connects to host:443 and performs a TLS handshake, capturing the live
    # certificate, any validation errors and the negotiated protocol.
    param([Parameter(Mandatory)][string]$HostName, [int]$Port = 443, [int]$TimeoutMs = 10000)

    $state = @{ Errors = $null; Cert = $null }

    # Accept the certificate so we can inspect it, but record any errors.
    $callback = {
        param($s, $certificate, $chain, $sslPolicyErrors)
        $state.Errors = $sslPolicyErrors
        if ($certificate) {
            $state.Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $certificate
        }
        return $true
    }.GetNewClosure()

    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $connect = $tcp.ConnectAsync($HostName, $Port)
        if (-not $connect.Wait($TimeoutMs)) { throw "Connection to ${HostName}:$Port timed out." }

        $tcp.ReceiveTimeout = $TimeoutMs
        $tcp.SendTimeout    = $TimeoutMs

        $ssl = New-Object System.Net.Security.SslStream -ArgumentList $tcp.GetStream(), $false, ([System.Net.Security.RemoteCertificateValidationCallback]$callback)
        try {
            $ssl.AuthenticateAsClient($HostName)
            return [PSCustomObject]@{
                Success  = $true
                HostName = $HostName
                Cert     = $state.Cert
                Errors   = $state.Errors
                Protocol = [string]$ssl.SslProtocol
                Message  = ''
            }
        }
        finally { $ssl.Dispose() }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false; HostName = $HostName; Cert = $null; Errors = $null; Protocol = ''
            Message = (Get-InnerMessage $_.Exception)
        }
    }
    finally { $tcp.Dispose() }
}

function Get-HttpResponse {
    # GET a URL and return status, headers and (optionally) body.
    # Headers are still returned for 4xx/5xx responses.
    param(
        [Parameter(Mandatory)][string]$Url,
        [bool]$FollowRedirects = $true,
        [switch]$ReadBody,
        [int]$TimeoutMs = 10000
    )

    $resp = $null
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method            = 'GET'
        $req.Timeout           = $TimeoutMs
        $req.ReadWriteTimeout  = $TimeoutMs
        $req.AllowAutoRedirect = $FollowRedirects
        $req.UserAgent         = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ACC-DomainChecker/2.0'

        try { $resp = $req.GetResponse() }
        catch {
            # Unwrap to the WebException - it carries the response for HTTP errors
            $ex = $_.Exception
            while ($ex -and -not ($ex -is [System.Net.WebException])) { $ex = $ex.InnerException }
            if ($ex -and $ex.Response) { $resp = $ex.Response }
            else { throw }
        }

        $body = ''
        if ($ReadBody) {
            $reader = New-Object System.IO.StreamReader -ArgumentList $resp.GetResponseStream()
            try { $body = $reader.ReadToEnd() } finally { $reader.Dispose() }
        }

        return [PSCustomObject]@{
            Success     = $true
            StatusCode  = [int]$resp.StatusCode
            Headers     = $resp.Headers            # WebHeaderCollection - case-insensitive
            ResponseUri = [string]$resp.ResponseUri
            ContentType = [string]$resp.ContentType
            Body        = $body
            Message     = ''
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false; StatusCode = 0; Headers = $null; ResponseUri = ''; ContentType = ''; Body = ''
            Message = (Get-InnerMessage $_.Exception)
        }
    }
    finally { if ($resp) { $resp.Close() } }
}

# =============================================================================
# SSL certificate
# =============================================================================

function Test-Certificate {
    param($Tls)

    $check = 'SSL Certificate'
    $cert  = $Tls.Cert

    if (-not $cert) {
        return New-CheckResult 'Web' $check 'Fail' "No certificate returned by $($Tls.HostName)." `
            'Install a valid certificate on the web server.'
    }

    $nameType = [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName
    $subject  = $cert.GetNameInfo($nameType, $false)
    $issuer   = $cert.GetNameInfo($nameType, $true)
    $days     = [int][math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)
    $expiry   = $cert.NotAfter.ToString('dd MMM yyyy')
    $errors   = [System.Net.Security.SslPolicyErrors]$Tls.Errors

    $details = "Host: $($Tls.HostName) | Subject: $subject | Issuer: $issuer | Expires: $expiry ($days days) | Protocol: $($Tls.Protocol)"

    $nameMismatch = ($errors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch) -ne 0
    $chainError   = ($errors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors) -ne 0

    if ($days -lt 0) {
        return New-CheckResult 'Web' $check 'Fail' "$details | Certificate EXPIRED" `
            'Renew the certificate now - browsers are showing a security warning to visitors.'
    }
    if ($nameMismatch) {
        return New-CheckResult 'Web' $check 'Fail' "$details | Certificate does not match the hostname" `
            "Issue a certificate that covers $($Tls.HostName) (and www / the bare domain if both are used)."
    }
    if ($chainError) {
        return New-CheckResult 'Web' $check 'Fail' "$details | Certificate chain not trusted (self-signed, unknown CA or missing intermediate)" `
            'Use a certificate from a public CA and make sure the server sends the full chain, including intermediate certificates.'
    }
    if ($Tls.Protocol -match '^(Ssl\d|Tls|Tls11)$') {
        return New-CheckResult 'Web' $check 'Warn' "$details | Outdated TLS version negotiated" `
            'Enable TLS 1.2 or 1.3 on the web server and disable TLS 1.0 / 1.1.'
    }
    if ($days -le 30) {
        return New-CheckResult 'Web' $check 'Warn' "$details | Expires within 30 days" `
            'Renew the certificate. If it should auto-renew (e.g. Let''s Encrypt), check why renewal has not happened yet.'
    }

    New-CheckResult 'Web' $check 'Pass' $details
}

# =============================================================================
# HTTPS redirect
# =============================================================================

function Test-HttpsRedirect {
    param([string]$HostName)

    $check = 'HTTPS Redirect'
    $r = Get-HttpResponse -Url "http://$HostName/" -FollowRedirects $false

    if (-not $r.Success) {
        return New-CheckResult 'Web' $check 'Pass' "HTTP (port 80) not served on $HostName - HTTPS only."
    }

    $location = if ($r.Headers) { [string]$r.Headers['Location'] } else { '' }

    if ($r.StatusCode -in 301, 302, 303, 307, 308) {
        if ($location -match '^https://') {
            return New-CheckResult 'Web' $check 'Pass' "http://$HostName redirects ($($r.StatusCode)) to $location"
        }
        return New-CheckResult 'Web' $check 'Warn' "http://$HostName redirects ($($r.StatusCode)) to a non-HTTPS URL: $location" `
            'Redirect HTTP straight to the HTTPS version of the site.'
    }

    New-CheckResult 'Web' $check 'Fail' "http://$HostName is served over plain HTTP (status $($r.StatusCode)) without redirecting to HTTPS." `
        'Add a permanent (301) redirect from HTTP to HTTPS on the web server or hosting control panel.'
}

# =============================================================================
# Security headers
# =============================================================================

function Test-SecurityHeaders {
    param([string]$HostName)

    $r = Get-HttpResponse -Url "https://$HostName/"

    if (-not $r.Success) {
        return @(New-CheckResult 'Web' 'Security Headers' 'Warn' "Could not fetch https://$HostName/ : $($r.Message)" `
            'Re-run the check. If the certificate check failed, fix that first.')
    }

    $h       = $r.Headers
    $source  = "from $($r.ResponseUri) (HTTP $($r.StatusCode))"
    $results = New-Object System.Collections.Generic.List[object]

    # --- HSTS ----------------------------------------------------------------
    $hsts = [string]$h['Strict-Transport-Security']
    if (-not $hsts) {
        $results.Add((New-CheckResult 'Web' 'HSTS Header' 'Fail' "Missing $source" `
            'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" so browsers always use HTTPS.'))
    }
    else {
        $maxAge = if ($hsts -match 'max-age\s*=\s*"?(\d+)') { [long]$Matches[1] } else { 0 }
        if ($maxAge -lt 15552000) {
            $results.Add((New-CheckResult 'Web' 'HSTS Header' 'Warn' "$hsts | max-age below 180 days" `
                'Increase HSTS max-age to at least 15552000 (180 days); 31536000 (1 year) is recommended.'))
        } else {
            $results.Add((New-CheckResult 'Web' 'HSTS Header' 'Pass' $hsts))
        }
    }

    # --- CSP -----------------------------------------------------------------
    $csp       = [string]$h['Content-Security-Policy']
    $cspReport = [string]$h['Content-Security-Policy-Report-Only']
    if ($csp) {
        $shown = if ($csp.Length -gt 200) { $csp.Substring(0, 200) + '...' } else { $csp }
        $results.Add((New-CheckResult 'Web' 'CSP Header' 'Pass' "Present: $shown"))
    }
    elseif ($cspReport) {
        $results.Add((New-CheckResult 'Web' 'CSP Header' 'Warn' 'Report-only CSP - violations are logged but not blocked.' `
            'Once the report-only policy is clean, switch it to Content-Security-Policy to enforce it.'))
    }
    else {
        $results.Add((New-CheckResult 'Web' 'CSP Header' 'Warn' "Missing $source" `
            'Add a Content-Security-Policy to limit which scripts and content the site can load (start with report-only to test).'))
    }

    # --- Clickjacking (X-Frame-Options or CSP frame-ancestors) ----------------
    $xfo = [string]$h['X-Frame-Options']
    if ($csp -match 'frame-ancestors') {
        $results.Add((New-CheckResult 'Web' 'Clickjacking Header' 'Pass' 'Protected by CSP frame-ancestors'))
    }
    elseif ($xfo -match '^\s*(DENY|SAMEORIGIN)\s*$') {
        $results.Add((New-CheckResult 'Web' 'Clickjacking Header' 'Pass' "X-Frame-Options: $xfo"))
    }
    else {
        $detail = if ($xfo) { "Invalid X-Frame-Options value: $xfo" } else { "Missing $source" }
        $results.Add((New-CheckResult 'Web' 'Clickjacking Header' 'Warn' $detail `
            'Add "X-Frame-Options: SAMEORIGIN" or a CSP frame-ancestors directive so the site cannot be framed by other sites.'))
    }

    # --- MIME sniffing -------------------------------------------------------
    $xcto = [string]$h['X-Content-Type-Options']
    if ($xcto -match '^\s*nosniff\s*$') {
        $results.Add((New-CheckResult 'Web' 'MIME Sniffing Header' 'Pass' 'X-Content-Type-Options: nosniff'))
    } else {
        $detail = if ($xcto) { "Unexpected value: $xcto" } else { "Missing $source" }
        $results.Add((New-CheckResult 'Web' 'MIME Sniffing Header' 'Warn' $detail `
            'Add "X-Content-Type-Options: nosniff".'))
    }

    # --- Referrer-Policy ------------------------------------------------------
    $ref = [string]$h['Referrer-Policy']
    if (-not $ref) {
        $results.Add((New-CheckResult 'Web' 'Referrer Header' 'Warn' "Missing $source" `
            'Add "Referrer-Policy: strict-origin-when-cross-origin".'))
    }
    elseif ($ref -match 'unsafe-url') {
        $results.Add((New-CheckResult 'Web' 'Referrer Header' 'Warn' "Referrer-Policy: $ref (sends full URLs to other sites)" `
            'Change to "strict-origin-when-cross-origin" or stricter.'))
    }
    else {
        $results.Add((New-CheckResult 'Web' 'Referrer Header' 'Pass' "Referrer-Policy: $ref"))
    }

    # --- Server / technology disclosure ---------------------------------------
    $server  = [string]$h['Server']
    $powered = [string]$h['X-Powered-By']
    $aspnet  = [string]$h['X-AspNet-Version']
    $leaks   = @()
    if ($server -match '\d')  { $leaks += "Server: $server" }
    if ($powered)             { $leaks += "X-Powered-By: $powered" }
    if ($aspnet)              { $leaks += "X-AspNet-Version: $aspnet" }

    if ($leaks.Count -gt 0) {
        $results.Add((New-CheckResult 'Web' 'Server Disclosure' 'Warn' "Software versions exposed: $($leaks -join ' | ')" `
            'Hide version numbers in the Server header and remove X-Powered-By / X-AspNet-Version so attackers cannot easily match known vulnerabilities.'))
    } else {
        $results.Add((New-CheckResult 'Web' 'Server Disclosure' 'Pass' 'No software version numbers exposed in headers.'))
    }

    $results.ToArray()
}

# =============================================================================
# MTA-STS and TLS-RPT (mail transport - reported under Email)
# =============================================================================

function Test-MxPatternMatch {
    # MTA-STS mx patterns: exact host, or "*.example.com" matching ONE extra label.
    param([string]$MxHost, [string]$Pattern)
    $p = $Pattern.Trim().TrimEnd('.').ToLowerInvariant()
    if ($p.StartsWith('*.')) {
        $suffix = $p.Substring(1)   # ".example.com"
        if (-not $MxHost.EndsWith($suffix)) { return $false }
        $label = $MxHost.Substring(0, $MxHost.Length - $suffix.Length)
        return ($label.Length -gt 0 -and $label -notmatch '\.')
    }
    return ($MxHost -eq $p)
}

function Test-MtaSts {
    param([string]$Domain, [string]$Server)

    $results = New-Object System.Collections.Generic.List[object]

    # --- Step 1: DNS record --------------------------------------------------
    $txt = Get-DnsTxt -Name "_mta-sts.$Domain" -Server $Server
    $sts = @($txt.Records | Where-Object { $_ -match '^\s*v=STSv1' })
    $dnsOk = $false

    if ($txt.Status -eq 'Error') {
        $results.Add((New-CheckResult 'Email' 'MTA-STS DNS Record' 'Warn' "Lookup failed: $($txt.Message)" `
            'Re-run the check. If it keeps failing, try -DnsServer 1.1.1.1.'))
    }
    elseif ($sts.Count -eq 0) {
        $results.Add((New-CheckResult 'Email' 'MTA-STS DNS Record' 'Warn' "MTA-STS not configured (no v=STSv1 TXT record at _mta-sts.$Domain)." `
            'Optional but recommended: publish an MTA-STS policy so other mail servers must use encrypted, verified TLS when sending to this domain.'))
    }
    elseif ($sts.Count -gt 1) {
        $results.Add((New-CheckResult 'Email' 'MTA-STS DNS Record' 'Fail' "Multiple MTA-STS records found - senders will ignore MTA-STS. Records: $($sts -join ' || ')" `
            "Keep a single v=STSv1 TXT record at _mta-sts.$Domain."))
    }
    elseif ($sts[0] -notmatch 'id\s*=\s*[A-Za-z0-9]+') {
        $results.Add((New-CheckResult 'Email' 'MTA-STS DNS Record' 'Fail' "$($sts[0]) | Missing or invalid id= tag" `
            'Add an id= value (letters/numbers, e.g. id=20261109) and change it whenever the policy file changes.'))
    }
    else {
        $dnsOk = $true
        $results.Add((New-CheckResult 'Email' 'MTA-STS DNS Record' 'Pass' $sts[0]))
    }

    # --- Step 2: Policy file -------------------------------------------------
    if (-not $dnsOk) {
        $results.Add((New-CheckResult 'Email' 'MTA-STS Policy' 'Info' 'Skipped - no valid MTA-STS DNS record.'))
        return @{ Results = $results.ToArray(); Configured = $false }
    }

    $policyUrl = "https://mta-sts.$Domain/.well-known/mta-sts.txt"
    $r = Get-HttpResponse -Url $policyUrl -FollowRedirects $false -ReadBody

    if (-not $r.Success) {
        $results.Add((New-CheckResult 'Email' 'MTA-STS Policy' 'Fail' "Could not retrieve $policyUrl : $($r.Message)" `
            "The policy must be served over HTTPS with a valid, trusted certificate for mta-sts.$Domain. Check the host and certificate."))
        return @{ Results = $results.ToArray(); Configured = $true }
    }
    if ($r.StatusCode -in 301, 302, 303, 307, 308) {
        $results.Add((New-CheckResult 'Email' 'MTA-STS Policy' 'Fail' "$policyUrl redirects (HTTP $($r.StatusCode)) - redirects are not allowed for MTA-STS policies." `
            'Serve the policy file directly at the URL without any redirect.'))
        return @{ Results = $results.ToArray(); Configured = $true }
    }
    if ($r.StatusCode -ne 200) {
        $results.Add((New-CheckResult 'Email' 'MTA-STS Policy' 'Fail' "Unexpected HTTP $($r.StatusCode) from $policyUrl" `
            'Make sure the policy file exists at /.well-known/mta-sts.txt.'))
        return @{ Results = $results.ToArray(); Configured = $true }
    }

    # Parse "key: value" lines
    $body    = $r.Body
    $version = if ($body -match '(?m)^\s*version:\s*(\S+)')  { $Matches[1].Trim() } else { $null }
    $mode    = if ($body -match '(?m)^\s*mode:\s*(\S+)')     { $Matches[1].Trim().ToLowerInvariant() } else { $null }
    $maxAge  = if ($body -match '(?m)^\s*max_age:\s*(\d+)')  { [long]$Matches[1] } else { $null }
    $mxLines = @([regex]::Matches($body, '(?m)^\s*mx:\s*(\S+)') | ForEach-Object { $_.Groups[1].Value.Trim() })

    $status = 'Pass'
    $notes  = New-Object System.Collections.Generic.List[string]
    $fixes  = New-Object System.Collections.Generic.List[string]

    if ($version -ne 'STSv1') {
        $status = Get-WorstStatus $status 'Fail'
        $notes.Add("Missing or invalid version line ($version)")
        $fixes.Add('The first line of the policy must be "version: STSv1".')
    }

    switch ($mode) {
        'enforce' { $notes.Add('Mode: enforce') }
        'testing' {
            $status = Get-WorstStatus $status 'Warn'
            $notes.Add('Mode: testing (not yet enforcing)')
            $fixes.Add('Once TLS-RPT reports are clean, change mode to enforce.')
        }
        'none' {
            $status = Get-WorstStatus $status 'Fail'
            $notes.Add('Mode: none (policy disabled)')
            $fixes.Add('Set mode to testing, then enforce - or remove MTA-STS completely if it is not wanted.')
        }
        default {
            $status = Get-WorstStatus $status 'Fail'
            $notes.Add('Mode missing or unrecognised')
            $fixes.Add('Add "mode: testing" or "mode: enforce".')
        }
    }

    if ($null -eq $maxAge) {
        $status = Get-WorstStatus $status 'Fail'
        $notes.Add('max_age missing')
        $fixes.Add('Add "max_age: 604800" (1 week) or higher.')
    }
    elseif ($maxAge -lt 86400) {
        $status = Get-WorstStatus $status 'Warn'
        $notes.Add("max_age too low: ${maxAge}s")
        $fixes.Add('Increase max_age to at least 604800 (1 week).')
    }
    elseif ($maxAge -gt 31557600) {
        $status = Get-WorstStatus $status 'Warn'
        $notes.Add("max_age above the 1 year maximum: ${maxAge}s")
        $fixes.Add('Set max_age to 31557600 or lower.')
    }
    else {
        $notes.Add("max_age: $maxAge")
    }

    # Compare policy mx: lines against the real MX records
    $realMx = Get-MxHosts -Domain $Domain -Server $Server
    if ($mxLines.Count -eq 0) {
        $status = Get-WorstStatus $status 'Fail'
        $notes.Add('No mx: lines in policy')
        $fixes.Add('Add an mx: line for each mail server (e.g. "mx: *.mail.protection.outlook.com").')
    }
    else {
        $notes.Add("Policy MX: $($mxLines -join ', ')")
        $uncovered = @($realMx | Where-Object {
            $mxHost = $_
            -not ($mxLines | Where-Object { Test-MxPatternMatch -MxHost $mxHost -Pattern $_ })
        })
        if ($uncovered.Count -gt 0) {
            if ($mode -eq 'enforce') {
                $status = Get-WorstStatus $status 'Fail'
                $notes.Add("MX host(s) NOT covered by policy: $($uncovered -join ', ') - inbound mail to these may be rejected")
            } else {
                $status = Get-WorstStatus $status 'Warn'
                $notes.Add("MX host(s) not covered by policy: $($uncovered -join ', ')")
            }
            $fixes.Add('Update the policy mx: lines to match the current MX records, then change the id= in the DNS record.')
        }
    }

    if ($r.ContentType -and $r.ContentType -notmatch '^text/plain') {
        $status = Get-WorstStatus $status 'Warn'
        $notes.Add("Content-Type is $($r.ContentType) (should be text/plain)")
        $fixes.Add('Serve the policy file with Content-Type: text/plain.')
    }

    $results.Add((New-CheckResult 'Email' 'MTA-STS Policy' $status ($notes -join ' | ') ($fixes -join ' ')))
    return @{ Results = $results.ToArray(); Configured = $true }
}

function Test-TlsRpt {
    param([string]$Domain, [string]$Server, [bool]$MtaStsConfigured)

    $check = 'TLS-RPT Record'
    $txt   = Get-DnsTxt -Name "_smtp._tls.$Domain" -Server $Server

    if ($txt.Status -eq 'Error') {
        return New-CheckResult 'Email' $check 'Warn' "Lookup failed: $($txt.Message)" 'Re-run the check.'
    }

    $rpt = @($txt.Records | Where-Object { $_ -match '^\s*v=TLSRPTv1' })

    if ($rpt.Count -eq 1) {
        return New-CheckResult 'Email' $check 'Pass' $rpt[0]
    }
    if ($rpt.Count -gt 1) {
        return New-CheckResult 'Email' $check 'Fail' "Multiple TLS-RPT records found: $($rpt -join ' || ')" `
            "Keep a single v=TLSRPTv1 TXT record at _smtp._tls.$Domain."
    }
    if ($MtaStsConfigured) {
        return New-CheckResult 'Email' $check 'Warn' 'MTA-STS is configured but there is no TLS-RPT record, so delivery failures will go unnoticed.' `
            "Add a TXT record at _smtp._tls.$Domain : ""v=TLSRPTv1; rua=mailto:tlsrpt@$Domain"""
    }
    New-CheckResult 'Email' $check 'Info' 'No TLS-RPT record (only needed alongside MTA-STS).'
}

# =============================================================================
# Public entry point
# =============================================================================

function Test-WebSecurity {
    <#
    .SYNOPSIS
        Runs web (certificate, redirect, headers) and MTA-STS / TLS-RPT checks.
    .PARAMETER Domain
        Domain to check, e.g. example.co.uk. If the bare domain has no HTTPS
        site, www.<domain> is used for the web checks.
    .PARAMETER DnsServer
        Optional DNS server to query (e.g. 1.1.1.1). Defaults to the system resolver.
    .EXAMPLE
        Test-WebSecurity -Domain example.co.uk
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Domain,
        [string]$DnsServer
    )

    Initialize-TlsProtocol

    $results = New-Object System.Collections.Generic.List[object]

    # --- Pick the web host: bare domain first, then www ------------------------
    $tls = Get-TlsInfo -HostName $Domain
    if (-not $tls.Success -and $Domain -notmatch '^www\.') {
        $wwwTls = Get-TlsInfo -HostName "www.$Domain"
        if ($wwwTls.Success) { $tls = $wwwTls }
    }

    if ($tls.Success) {
        $webHost = $tls.HostName
        $results.Add((Test-Certificate -Tls $tls))
        $results.Add((Test-HttpsRedirect -HostName $webHost))
        foreach ($r in (Test-SecurityHeaders -HostName $webHost)) { $results.Add($r) }
    }
    else {
        $results.Add((New-CheckResult 'Web' 'SSL Certificate' 'Fail' "No HTTPS site reachable on $Domain or www.$Domain : $($tls.Message)" `
            'If the domain has a website, make sure it is served over HTTPS on port 443. If it has no website, this can be ignored.'))
        $results.Add((New-CheckResult 'Web' 'Security Headers' 'Info' 'Skipped - no HTTPS site reachable.'))
    }

    # --- Mail transport ----------------------------------------------------------
    $mta = Test-MtaSts -Domain $Domain -Server $DnsServer
    foreach ($r in $mta.Results) { $results.Add($r) }
    $results.Add((Test-TlsRpt -Domain $Domain -Server $DnsServer -MtaStsConfigured $mta.Configured))

    return $results.ToArray()
}

Export-ModuleMember -Function Test-WebSecurity
