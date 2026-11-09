<#
.SYNOPSIS
    Infrastructure / DNS checks for Domain Checker.

.DESCRIPTION
    Exposes Test-Infrastructure, which returns one result object per check in the
    format expected by Invoke-DomainCheck.ps1:

        Category    = "Infrastructure"
        Check       = "Name Servers"
        Status      = "Pass" | "Fail" | "Warn" | "Info"
        Details     = What was found
        Remediation = What to do about it (blank when nothing to do)

    Checks:
        Name Servers          - at least 2 NS records, provider diversity noted
        DNSSEC                - signed delegation (DS record at the parent)
        CAA Record            - restricts which CAs can issue certificates
        MX Records            - mail routing present / null MX
        Wildcard DNS          - detects *.domain (affects subdomain results)
        Subdomain Exposure    - common subdomains, flags admin/test/dev style names
        Subdomain Takeover    - CNAMEs pointing at cloud services that no longer exist

.NOTES
    Module  : InfrastructureChecks.psm1
    Version : 2.0.0
    Author  : Alex Wilson - ACC London
    Requires: Windows (Resolve-DnsName / DnsClient module)

    ===========================================================================
    CHANGELOG
    ===========================================================================
    2.0.0
      Fixed
        - Subdomain Enumeration logic was inverted: finding subdomains was a
          Pass and finding none was a Fail. Having (or not having) "www" says
          nothing about security. Replaced with Subdomain Exposure, which only
          warns about sensitive names (admin, dev, test, staging, ftp ...).
        - Domains with wildcard DNS (*.domain) reported every subdomain as found.
          Wildcard is now detected and the subdomain results are adjusted.
        - DNS errors/timeouts were silently treated as "not found".
        - Resolve-DnsName could fall back to LLMNR/NetBIOS. Now uses -DnsOnly.
      Added
        - Name Servers, DNSSEC, CAA, MX and Wildcard DNS checks.
        - Subdomain Takeover check for dangling CNAMEs (Azure, AWS, GitHub
          Pages, Heroku etc.).
        - -DnsServer to query a specific resolver (e.g. 1.1.1.1).
        - -Subdomains to add extra names to the subdomain list.
        - Remediation text and Category on every result.

    1.0.0
        - Initial subdomain enumeration check.
    ===========================================================================
#>

# =============================================================================
# Helpers (not exported)
# =============================================================================

function Invoke-DnsQuery {
    # Wrapper around Resolve-DnsName that separates "no record" from "lookup failed".
    #   Status  = Found | NotFound | Error | Unsupported
    #   Answers = answer-section records matching the requested type
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Type,
        [string]$Server
    )

    $params = @{ Name = $Name; Type = $Type; DnsOnly = $true; QuickTimeout = $true; ErrorAction = 'Stop' }
    if ($Server) { $params.Server = $Server }

    try {
        $all     = @(Resolve-DnsName @params)
        $answers = @($all | Where-Object { $_.Section -eq 'Answer' -and [string]$_.QueryType -eq $Type })

        if ($answers.Count -gt 0) {
            return [PSCustomObject]@{ Status = 'Found'; Answers = $answers; All = $all; Message = '' }
        }
        return [PSCustomObject]@{ Status = 'NotFound'; Answers = @(); All = $all; Message = '' }
    }
    catch [System.Management.Automation.ParameterBindingException] {
        # Older Windows builds don't know newer record types (e.g. CAA)
        return [PSCustomObject]@{ Status = 'Unsupported'; Answers = @(); All = @(); Message = $_.Exception.Message }
    }
    catch {
        if ($_.FullyQualifiedErrorId -match 'DNS_ERROR_RCODE_NAME_ERROR|DNS_INFO_NO_RECORDS|9003|9501') {
            return [PSCustomObject]@{ Status = 'NotFound'; Answers = @(); All = @(); Message = '' }
        }
        return [PSCustomObject]@{ Status = 'Error'; Answers = @(); All = @(); Message = $_.Exception.Message }
    }
}

function New-InfraResult {
    param([string]$Check, [string]$Status, [string]$Details, [string]$Remediation = '')
    [PSCustomObject]@{
        Category    = 'Infrastructure'
        Check       = $Check
        Status      = $Status
        Details     = $Details
        Remediation = $Remediation
    }
}

function New-LookupErrorResult {
    param([string]$Check, [string]$Message)
    New-InfraResult -Check $Check -Status 'Warn' `
        -Details "Lookup failed: $Message" `
        -Remediation 'Re-run the check. If it keeps failing, confirm the domain resolves publicly or try -DnsServer 1.1.1.1.'
}

function Get-ParentZone {
    # ns1.example-dns.co.uk -> example-dns.co.uk (rough, good enough for diversity check)
    param([string]$HostName)
    $parts = $HostName.TrimEnd('.').ToLowerInvariant().Split('.')
    if ($parts.Count -ge 3 -and $parts[-2] -match '^(co|org|ac|gov|net|com|ltd|plc|me)$' -and $parts[-1].Length -eq 2) {
        return ($parts[-3..-1] -join '.')
    }
    if ($parts.Count -ge 2) { return ($parts[-2..-1] -join '.') }
    return $HostName
}

# =============================================================================
# Name servers
# =============================================================================

function Test-NameServers {
    param([string]$Domain, [string]$Server)

    $check = 'Name Servers'
    $q = Invoke-DnsQuery -Name $Domain -Type 'NS' -Server $Server

    if ($q.Status -eq 'Error')    { return New-LookupErrorResult $check $q.Message }
    if ($q.Status -ne 'Found') {
        return New-InfraResult $check 'Fail' 'No NS records found for the domain.' `
            'Check the domain registration and that name servers are set at the registrar.'
    }

    $ns        = @($q.Answers | ForEach-Object { $_.NameHost.TrimEnd('.').ToLowerInvariant() } | Sort-Object -Unique)
    $providers = @($ns | ForEach-Object { Get-ParentZone $_ } | Sort-Object -Unique)
    $details   = "$($ns.Count) name server(s): $($ns -join ', ')"

    if ($ns.Count -lt 2) {
        return New-InfraResult $check 'Fail' "$details | Only one name server - no redundancy" `
            'Add at least one more name server so DNS stays up if one fails.'
    }

    $details += " | Provider(s): $($providers -join ', ')"
    New-InfraResult $check 'Pass' $details
}

# =============================================================================
# DNSSEC
# =============================================================================

function Test-Dnssec {
    param([string]$Domain, [string]$Server)

    $check = 'DNSSEC'
    $q = Invoke-DnsQuery -Name $Domain -Type 'DS' -Server $Server

    if ($q.Status -eq 'Unsupported') { return New-InfraResult $check 'Info' 'DS lookups are not supported on this machine.' }
    if ($q.Status -eq 'Error')       { return New-LookupErrorResult $check $q.Message }

    if ($q.Status -eq 'Found') {
        return New-InfraResult $check 'Pass' "DNSSEC enabled - $($q.Answers.Count) DS record(s) published at the parent zone."
    }

    New-InfraResult $check 'Warn' 'DNSSEC not enabled (no DS record at the parent zone). DNS answers can be spoofed or tampered with in transit.' `
        'Enable DNSSEC at the DNS host, then add the DS record at the registrar (many hosts such as Cloudflare do this in a couple of clicks).'
}

# =============================================================================
# CAA
# =============================================================================

function Test-Caa {
    param([string]$Domain, [string]$Server)

    $check = 'CAA Record'
    $q = Invoke-DnsQuery -Name $Domain -Type 'CAA' -Server $Server

    if ($q.Status -eq 'Unsupported') { return New-InfraResult $check 'Info' 'CAA lookups are not supported by Resolve-DnsName on this machine.' }
    if ($q.Status -eq 'Error')       { return New-LookupErrorResult $check $q.Message }

    if ($q.Status -eq 'Found') {
        $values = @($q.Answers | ForEach-Object {
            if ($_.Tag) { "$($_.Tag) $($_.Value)" } else { ($_ | Out-String).Trim() }
        })
        return New-InfraResult $check 'Pass' "CAA restricts certificate issuance: $($values -join '; ')"
    }

    New-InfraResult $check 'Warn' 'No CAA record - any certificate authority can issue certificates for this domain.' `
        "Add CAA records for the CAs actually in use, e.g. '0 issue ""letsencrypt.org""' and '0 issue ""digicert.com""'."
}

# =============================================================================
# MX
# =============================================================================

function Test-Mx {
    param([string]$Domain, [string]$Server)

    $check = 'MX Records'
    $q = Invoke-DnsQuery -Name $Domain -Type 'MX' -Server $Server

    if ($q.Status -eq 'Error') { return New-LookupErrorResult $check $q.Message }

    if ($q.Status -ne 'Found') {
        return New-InfraResult $check 'Warn' 'No MX records - the domain cannot receive email.' `
            'If the domain should receive mail, add MX records. If it should never send or receive mail, publish a null MX ("0 .") plus "v=spf1 -all" and DMARC p=reject.'
    }

    $mx = @($q.Answers | Sort-Object Preference | ForEach-Object { "$($_.Preference) $($_.NameExchange.TrimEnd('.'))" })

    # Null MX (RFC 7505) - domain deliberately does not accept mail
    if ($mx.Count -eq 1 -and $mx[0] -match '^0\s*\.?$') {
        return New-InfraResult $check 'Pass' 'Null MX published - domain explicitly does not accept email.'
    }

    $hosts   = ($mx -join ', ')
    $service = switch -Regex ($hosts) {
        'mail\.protection\.outlook\.com' { 'Microsoft 365'; break }
        'google(mail)?\.com'             { 'Google Workspace'; break }
        'mimecast'                       { 'Mimecast'; break }
        'pphosted|proofpoint'            { 'Proofpoint'; break }
        'messagelabs|symantec'           { 'Symantec / Broadcom'; break }
        default                          { $null }
    }
    $details = "$($mx.Count) MX record(s): $hosts"
    if ($service) { $details += " | Mail service: $service" }

    New-InfraResult $check 'Pass' $details
}

# =============================================================================
# Wildcard DNS
# =============================================================================

function Test-Wildcard {
    # Returns @{ Result = <result object>; IsWildcard = bool; Targets = string[] }
    param([string]$Domain, [string]$Server)

    $check  = 'Wildcard DNS'
    $random = "acc-$([guid]::NewGuid().ToString('N').Substring(0,12)).$Domain"
    $q      = Invoke-DnsQuery -Name $random -Type 'A' -Server $Server

    if ($q.Status -eq 'Error') {
        return @{ Result = (New-LookupErrorResult $check $q.Message); IsWildcard = $false; Targets = @() }
    }

    if ($q.Status -eq 'Found') {
        $ips = @($q.Answers | ForEach-Object { $_.IPAddress } | Sort-Object -Unique)
        $res = New-InfraResult $check 'Info' "Wildcard DNS in use (*.$Domain -> $($ips -join ', ')). Any subdomain resolves, so subdomain results only list names that point somewhere different." `
            'Confirm the wildcard is intentional. Wildcards can hide mistakes and make phishing-style subdomains look legitimate.'
        return @{ Result = $res; IsWildcard = $true; Targets = $ips }
    }

    @{ Result = (New-InfraResult $check 'Pass' 'No wildcard DNS record.'); IsWildcard = $false; Targets = @() }
}

# =============================================================================
# Subdomains: exposure + takeover
# =============================================================================

function Test-Subdomains {
    param(
        [string]$Domain,
        [string]$Server,
        [string[]]$Names,
        [bool]$IsWildcard,
        [string[]]$WildcardTargets
    )

    # Names that usually shouldn't be publicly reachable
    $sensitive = @('admin','test','dev','staging','uat','ftp','beta','old','backup','internal','cpanel','phpmyadmin','jenkins','git')

    # CNAME targets on services where a deleted resource can be re-registered by
    # someone else (subdomain takeover)
    $takeoverPattern = '\.(azurewebsites\.net|cloudapp\.net|cloudapp\.azure\.com|trafficmanager\.net|blob\.core\.windows\.net|azureedge\.net|azurefd\.net|azure-api\.net|azurecontainer\.io|azurestaticapps\.net|s3[.-][a-z0-9-]*\.?amazonaws\.com|s3\.amazonaws\.com|elasticbeanstalk\.com|cloudfront\.net|github\.io|herokuapp\.com|herokudns\.com|myshopify\.com|wpengine\.com|pantheonsite\.io|netlify\.app|ghost\.io|zendesk\.com|helpscoutdocs\.com|surge\.sh|bitbucket\.io|readthedocs\.io|fastly\.net)$'

    $found    = New-Object System.Collections.Generic.List[string]
    $exposed  = New-Object System.Collections.Generic.List[string]
    $dangling = New-Object System.Collections.Generic.List[string]
    $errors   = 0

    foreach ($s in $Names) {
        $fqdn = "$s.$Domain"

        # --- CNAME first (takeover check needs it even if A doesn't resolve) ---
        $cn = Invoke-DnsQuery -Name $fqdn -Type 'CNAME' -Server $Server
        if ($cn.Status -eq 'Error') { $errors++; continue }

        $cnameTarget = $null
        if ($cn.Status -eq 'Found') { $cnameTarget = $cn.Answers[0].NameHost.TrimEnd('.').ToLowerInvariant() }

        if ($cnameTarget -and $cnameTarget -match $takeoverPattern) {
            $t = Invoke-DnsQuery -Name $cnameTarget -Type 'A' -Server $Server
            if ($t.Status -eq 'NotFound') {
                $dangling.Add("$fqdn -> $cnameTarget")
                continue
            }
        }

        # --- Does it resolve? -----------------------------------------------------
        $a = Invoke-DnsQuery -Name $fqdn -Type 'A' -Server $Server
        if ($a.Status -eq 'Error') { $errors++; continue }

        $resolves = ($a.Status -eq 'Found') -or [bool]$cnameTarget
        if (-not $resolves) { continue }

        # Skip names that are only answered by the wildcard
        if ($IsWildcard -and -not $cnameTarget) {
            $ips = @($a.Answers | ForEach-Object { $_.IPAddress } | Sort-Object -Unique)
            if (-not (Compare-Object $ips $WildcardTargets)) { continue }
        }

        $found.Add($fqdn)
        if ($sensitive -contains $s.ToLowerInvariant()) { $exposed.Add($fqdn) }
    }

    $results = New-Object System.Collections.Generic.List[object]

    # --- Subdomain exposure ------------------------------------------------------
    $foundText = if ($found.Count) { $found -join ', ' } else { 'none of the common names' }
    $errText   = if ($errors) { " | $errors lookup(s) failed" } else { '' }

    if ($exposed.Count -gt 0) {
        $results.Add((New-InfraResult 'Subdomain Exposure' 'Warn' `
            "Sensitive subdomain(s) publicly resolvable: $($exposed -join ', ') | All found: $foundText$errText" `
            'Confirm these are still needed. Remove old DNS records, or restrict access (VPN, IP allow-list, Entra app proxy, or authentication).'))
    }
    else {
        $results.Add((New-InfraResult 'Subdomain Exposure' 'Pass' `
            "No sensitive subdomains found. Checked $($Names.Count) common names; resolvable: $foundText$errText"))
    }

    # --- Subdomain takeover ------------------------------------------------------
    if ($dangling.Count -gt 0) {
        $results.Add((New-InfraResult 'Subdomain Takeover' 'Fail' `
            "Dangling CNAME(s) pointing at cloud resources that no longer exist: $($dangling -join '; ')" `
            'Delete these DNS records now, or recreate the cloud resource. Otherwise someone else can claim it and host content on your subdomain.'))
    }
    else {
        $results.Add((New-InfraResult 'Subdomain Takeover' 'Pass' 'No dangling CNAMEs found on the checked subdomains.'))
    }

    $results.ToArray()
}

# =============================================================================
# Public entry point
# =============================================================================

function Test-Infrastructure {
    <#
    .SYNOPSIS
        Runs DNS / infrastructure checks for a domain.
    .PARAMETER Domain
        Domain to check, e.g. example.co.uk.
    .PARAMETER DnsServer
        Optional DNS server to query (e.g. 1.1.1.1). Defaults to the system resolver.
    .PARAMETER Subdomains
        Extra subdomain names to check on top of the built-in list.
    .EXAMPLE
        Test-Infrastructure -Domain example.co.uk -DnsServer 1.1.1.1 -Subdomains 'crm','intranet'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Domain,
        [string]$DnsServer,
        [string[]]$Subdomains
    )

    $names = @(
        'www','mail','webmail','autodiscover','remote','vpn','portal','api','owa','sharepoint',
        'admin','test','dev','staging','uat','ftp','beta','old','backup','internal','cpanel','jenkins','git'
    )
    if ($Subdomains) { $names = @($names + $Subdomains | Select-Object -Unique) }

    $results = New-Object System.Collections.Generic.List[object]

    $results.Add((Test-NameServers -Domain $Domain -Server $DnsServer))
    $results.Add((Test-Dnssec      -Domain $Domain -Server $DnsServer))
    $results.Add((Test-Caa         -Domain $Domain -Server $DnsServer))
    $results.Add((Test-Mx          -Domain $Domain -Server $DnsServer))

    $wild = Test-Wildcard -Domain $Domain -Server $DnsServer
    $results.Add($wild.Result)

    foreach ($r in (Test-Subdomains -Domain $Domain -Server $DnsServer -Names $names `
                        -IsWildcard $wild.IsWildcard -WildcardTargets $wild.Targets)) {
        $results.Add($r)
    }

    return $results.ToArray()
}

Export-ModuleMember -Function Test-Infrastructure
