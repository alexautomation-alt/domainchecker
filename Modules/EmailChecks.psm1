<#
.SYNOPSIS
    Email security checks for Domain Checker (SPF, DMARC, DKIM).

.DESCRIPTION
    Exposes Test-EmailSecurity, which returns one result object per check in the
    format expected by Invoke-DomainCheck.ps1:

        Category    = "Email"
        Check       = "SPF Record"
        Status      = "Pass" | "Fail" | "Warn" | "Info"
        Details     = What was found
        Remediation = What to do about it (blank when nothing to do)

.NOTES
    Module  : EmailChecks.psm1
    Version : 2.0.0
    Author  : Alex Wilson - ACC London
    Requires: Windows (Resolve-DnsName / DnsClient module)

    ===========================================================================
    CHANGELOG
    ===========================================================================
    2.0.0
      Fixed
        - DMARC "p=reject" match also matched "sp=reject", so "p=none; sp=reject"
          was wrongly passed. DMARC tags are now parsed properly.
        - SPF "+all" (anyone can send as you) and a missing "all" were reported
          as Pass. "+all" is now Fail, "?all" / no "all" is Warn.
        - SPF Details became an array (Strings + appended text), which rendered
          oddly. Multi-part TXT records are now joined into one string.
        - DKIM records without the optional "v=DKIM1" tag were missed. Records
          are now detected by their "p=" key tag.
        - DKIM Microsoft 365 selectors (CNAME -> TXT) could merge strings from
          more than one record. Only TXT answers are used now.
        - DNS timeouts / server failures were reported as "No record found".
          Lookup errors now return Warn with the error, not a false Fail.
      Added
        - Multiple SPF or DMARC records detected (both are invalid / permerror).
        - SPF DNS lookup count (approx., follows include/redirect). Over 10 = Fail.
        - SPF "ptr" mechanism flagged (deprecated).
        - DMARC pct < 100 and sp=none (with an enforcing p=) flagged as Warn.
        - DMARC note when no aggregate reporting address (rua) is set.
        - DKIM revoked keys (empty p=) and weak 1024-bit RSA keys flagged.
        - More common DKIM selectors, plus -DkimSelectors to add your own.
        - -DnsServer to query a specific resolver (e.g. 1.1.1.1) instead of
          the local/office DNS, which avoids split-DNS and cached answers.
        - Remediation text on every non-Pass result.
        - Category = "Email" on every result.
      Changed
        - DKIM not found is now Warn instead of Fail. DKIM selectors can't be
          listed from DNS, so "not found among common selectors" doesn't prove
          DKIM is missing.
        - Full DKIM public keys are no longer dumped into the report; the
          selector, key type and approximate key size are shown instead.
        - Consistent indentation and helper functions.

    1.0.0
        - Initial SPF, DMARC and DKIM checks.
    ===========================================================================
#>

# =============================================================================
# Helpers (not exported)
# =============================================================================

function Get-DnsTxt {
    # Looks up TXT records and returns:
    #   Status  = Found | NotFound | Error
    #   Records = string[] (each TXT record with its 255-char chunks joined)
    #   Message = error text when Status is Error
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Server
    )

    $params = @{ Name = $Name; Type = 'TXT'; DnsOnly = $true; ErrorAction = 'Stop' }
    if ($Server) { $params.Server = $Server }

    try {
        # Ignore SOA (authority) and CNAME entries - keep real TXT answers only
        $answers = @(Resolve-DnsName @params | Where-Object { $_.QueryType -eq 'TXT' })
        $records = @($answers | ForEach-Object { ($_.Strings -join '') })

        if ($records.Count -gt 0) {
            return [PSCustomObject]@{ Status = 'Found'; Records = $records; Message = '' }
        }
        return [PSCustomObject]@{ Status = 'NotFound'; Records = @(); Message = '' }
    }
    catch {
        # 9003 = name does not exist (NXDOMAIN), 9501 = no records of this type
        if ($_.FullyQualifiedErrorId -match 'DNS_ERROR_RCODE_NAME_ERROR|DNS_INFO_NO_RECORDS|9003|9501') {
            return [PSCustomObject]@{ Status = 'NotFound'; Records = @(); Message = '' }
        }
        return [PSCustomObject]@{ Status = 'Error'; Records = @(); Message = $_.Exception.Message }
    }
}

function Get-WorstStatus {
    # Returns the more serious of two statuses: Fail > Warn > Pass.
    param([string]$Current, [string]$New)
    $rank = @{ Pass = 0; Warn = 1; Fail = 2 }
    if ($rank[$New] -gt $rank[$Current]) { return $New }
    return $Current
}

function Get-SpfLookupCount {
    # Approximate count of DNS-querying SPF terms (include, redirect, a, mx,
    # ptr, exists), following include/redirect targets. RFC 7208 limit is 10.
    param(
        [Parameter(Mandatory)][string]$Domain,
        [string]$Server,
        [Parameter(Mandatory)]$Visited,
        [int]$Depth = 0
    )

    if ($Depth -gt 10) { return 0 }
    if (-not $Visited.Add($Domain.ToLowerInvariant())) { return 0 }   # loop protection

    $txt = Get-DnsTxt -Name $Domain -Server $Server
    $spf = @($txt.Records | Where-Object { $_ -match '^\s*v=spf1(\s|$)' })
    if ($spf.Count -ne 1) { return 0 }

    $count = 0
    foreach ($term in ($spf[0] -split '\s+')) {
        $t = $term.TrimStart([char[]]'+-~?').ToLowerInvariant()

        if ($t -match '^(include:|redirect=)(.+)$') {
            $target = $Matches[2]          # capture before recursion overwrites $Matches
            $count++
            if ($target -notmatch '%') {   # skip SPF macros - can't resolve statically
                $count += Get-SpfLookupCount -Domain $target -Server $Server -Visited $Visited -Depth ($Depth + 1)
            }
        }
        elseif ($t -match '^(a|mx|ptr|exists)([:/]|$)') {
            $count++
        }
    }
    return $count
}

# =============================================================================
# SPF
# =============================================================================

function Test-Spf {
    param([string]$Domain, [string]$Server)

    $check = 'SPF Record'
    $txt   = Get-DnsTxt -Name $Domain -Server $Server

    if ($txt.Status -eq 'Error') {
        return [PSCustomObject]@{
            Category = 'Email'; Check = $check; Status = 'Warn'
            Details     = "SPF lookup failed: $($txt.Message)"
            Remediation = 'Re-run the check. If it keeps failing, confirm the domain resolves publicly.'
        }
    }

    $spf = @($txt.Records | Where-Object { $_ -match '^\s*v=spf1(\s|$)' })

    if ($spf.Count -eq 0) {
        return [PSCustomObject]@{
            Category = 'Email'; Check = $check; Status = 'Fail'
            Details     = 'No SPF record found.'
            Remediation = 'Publish an SPF TXT record listing every service that sends email for the domain, ending in -all or ~all (e.g. "v=spf1 include:spf.protection.outlook.com -all").'
        }
    }

    if ($spf.Count -gt 1) {
        return [PSCustomObject]@{
            Category = 'Email'; Check = $check; Status = 'Fail'
            Details     = "Multiple SPF records found ($($spf.Count)). Receivers treat this as a permanent error and SPF fails. Records: $($spf -join ' || ')"
            Remediation = 'Merge all SPF records into a single TXT record that starts with v=spf1.'
        }
    }

    $record = $spf[0].Trim()
    $status = 'Pass'
    $notes  = New-Object System.Collections.Generic.List[string]
    $fixes  = New-Object System.Collections.Generic.List[string]

    # --- "all" mechanism -----------------------------------------------------
    if ($record -match '(^|\s)([+\-~?]?)all(\s|$)') {
        switch ($Matches[2]) {
            '-' { $notes.Add('Hard fail -all (Good)') }
            '~' { $notes.Add('Soft fail ~all (OK when DMARC is enforced)') }
            '?' {
                $status = Get-WorstStatus $status 'Warn'
                $notes.Add('Neutral ?all (Poor) - gives no protection')
                $fixes.Add('Change ?all to ~all or -all.')
            }
            default {
                $status = Get-WorstStatus $status 'Fail'
                $notes.Add('+all (Critical) - allows anyone to send as this domain')
                $fixes.Add('Replace +all with -all (or ~all) immediately.')
            }
        }
    }
    elseif ($record -match '(^|\s)redirect=') {
        $notes.Add('Policy set by redirect= target')
    }
    else {
        $status = Get-WorstStatus $status 'Warn'
        $notes.Add('No "all" mechanism (Poor) - unlisted senders are not rejected')
        $fixes.Add('End the SPF record with -all or ~all.')
    }

    # --- Deprecated ptr --------------------------------------------------------
    if ($record -match '(^|\s)[+\-~?]?ptr([:\s]|$)') {
        $status = Get-WorstStatus $status 'Warn'
        $notes.Add('Uses deprecated "ptr" mechanism')
        $fixes.Add('Remove the ptr mechanism - it is slow and ignored by some receivers.')
    }

    # --- 10 DNS lookup limit ---------------------------------------------------
    $visited = New-Object 'System.Collections.Generic.HashSet[string]'
    $lookups = Get-SpfLookupCount -Domain $Domain -Server $Server -Visited $visited

    if ($lookups -gt 10) {
        $status = Get-WorstStatus $status 'Fail'
        $notes.Add("DNS lookups: ~$lookups (over the limit of 10 - SPF will fail)")
        $fixes.Add('Reduce SPF lookups to 10 or fewer: remove unused includes, replace a/mx with ip4/ip6, or use SPF flattening.')
    }
    elseif ($lookups -ge 8) {
        $status = Get-WorstStatus $status 'Warn'
        $notes.Add("DNS lookups: ~$lookups of 10 (close to the limit)")
        $fixes.Add('SPF is close to the 10 lookup limit - review includes before adding any new senders.')
    }
    else {
        $notes.Add("DNS lookups: ~$lookups of 10")
    }

    [PSCustomObject]@{
        Category    = 'Email'
        Check       = $check
        Status      = $status
        Details     = "$record | $($notes -join ' | ')"
        Remediation = ($fixes -join ' ')
    }
}

# =============================================================================
# DMARC
# =============================================================================

function Test-Dmarc {
    param([string]$Domain, [string]$Server)

    $check = 'DMARC Record'
    $txt   = Get-DnsTxt -Name "_dmarc.$Domain" -Server $Server

    if ($txt.Status -eq 'Error') {
        return [PSCustomObject]@{
            Category = 'Email'; Check = $check; Status = 'Warn'
            Details     = "DMARC lookup failed: $($txt.Message)"
            Remediation = 'Re-run the check. If it keeps failing, confirm the domain resolves publicly.'
        }
    }

    $dmarc = @($txt.Records | Where-Object { $_ -match '^\s*v=DMARC1\s*(;|$)' })

    if ($dmarc.Count -eq 0) {
        return [PSCustomObject]@{
            Category = 'Email'; Check = $check; Status = 'Fail'
            Details     = 'No DMARC record found.'
            Remediation = "Publish a TXT record at _dmarc.$Domain, starting with monitoring (e.g. ""v=DMARC1; p=none; rua=mailto:dmarc@$Domain"") and moving to p=quarantine then p=reject."
        }
    }

    if ($dmarc.Count -gt 1) {
        return [PSCustomObject]@{
            Category = 'Email'; Check = $check; Status = 'Fail'
            Details     = "Multiple DMARC records found ($($dmarc.Count)). Receivers ignore DMARC when more than one exists. Records: $($dmarc -join ' || ')"
            Remediation = "Keep a single DMARC TXT record at _dmarc.$Domain."
        }
    }

    $record = $dmarc[0].Trim()

    # Parse tags (p, sp, pct, rua ...) - hashtable keys are case-insensitive
    $tags = @{}
    foreach ($pair in ($record -split ';')) {
        $kv = $pair -split '=', 2
        if ($kv.Count -eq 2) { $tags[$kv[0].Trim()] = $kv[1].Trim().ToLowerInvariant() }
    }

    $policy = $tags['p']
    $status = 'Pass'
    $notes  = New-Object System.Collections.Generic.List[string]
    $fixes  = New-Object System.Collections.Generic.List[string]

    switch ($policy) {
        'reject'     { $notes.Add('Reject policy (Excellent)') }
        'quarantine' { $notes.Add('Quarantine policy (Good)') }
        'none' {
            $status = 'Fail'
            $notes.Add('None policy (Poor) - domain is not enforcing DMARC')
            $fixes.Add('Review DMARC reports, then move the policy to p=quarantine and later p=reject.')
        }
        default {
            $status = 'Fail'
            $notes.Add('Missing or invalid p= tag - record is not valid')
            $fixes.Add('Add a valid policy tag: p=none, p=quarantine or p=reject.')
        }
    }

    if ($policy -in 'reject', 'quarantine') {
        # pct below 100 only applies the policy to part of the mail
        if ($tags.ContainsKey('pct') -and $tags['pct'] -match '^\d+$' -and [int]$tags['pct'] -lt 100) {
            $status = Get-WorstStatus $status 'Warn'
            $notes.Add("Policy only applied to $($tags['pct'])% of failing mail")
            $fixes.Add('Increase pct to 100 (or remove the pct tag).')
        }

        # sp=none leaves subdomains open to spoofing
        if ($tags['sp'] -eq 'none') {
            $status = Get-WorstStatus $status 'Warn'
            $notes.Add('Subdomain policy sp=none - subdomains are not protected')
            $fixes.Add('Set sp=quarantine or sp=reject, or remove sp so subdomains inherit p=.')
        }
    }

    if (-not $tags.ContainsKey('rua')) {
        $notes.Add('No aggregate reporting address (rua) - no visibility of who sends as this domain')
        $fixes.Add('Add rua=mailto:<address> to receive DMARC reports.')
    }

    [PSCustomObject]@{
        Category    = 'Email'
        Check       = $check
        Status      = $status
        Details     = "$record | $($notes -join ' | ')"
        Remediation = ($fixes -join ' ')
    }
}

# =============================================================================
# DKIM
# =============================================================================

function Test-Dkim {
    param([string]$Domain, [string]$Server, [string[]]$Selectors)

    $check  = 'DKIM Selectors'
    $found  = New-Object System.Collections.Generic.List[object]
    $errors = 0

    foreach ($selector in $Selectors) {
        $txt = Get-DnsTxt -Name "$selector._domainkey.$Domain" -Server $Server

        if ($txt.Status -eq 'Error') { $errors++; continue }
        if ($txt.Status -ne 'Found') { continue }

        # v=DKIM1 is optional, so detect DKIM by the p= (public key) tag
        $record = $txt.Records | Where-Object { $_ -match '(^|;)\s*p=' } | Select-Object -First 1
        if (-not $record) { continue }

        $keyType = if ($record -match '(^|;)\s*k=\s*([a-z0-9]+)') { $Matches[2].ToLowerInvariant() } else { 'rsa' }
        $key     = if ($record -match '(^|;)\s*p=\s*([^;]*)') { ($Matches[2] -replace '\s', '') } else { '' }

        # Rough RSA key size from base64 length: ~216 chars = 1024-bit, ~392 = 2048-bit
        $bits = if ($keyType -eq 'rsa' -and $key) {
            if ($key.Length -lt 300) { 1024 } elseif ($key.Length -lt 600) { 2048 } else { 4096 }
        } else { $null }

        $found.Add([PSCustomObject]@{
            Selector = $selector
            KeyType  = $keyType
            Revoked  = [string]::IsNullOrEmpty($key)
            Bits     = $bits
        })
    }

    if ($found.Count -eq 0) {
        if ($errors -eq $Selectors.Count) {
            return [PSCustomObject]@{
                Category = 'Email'; Check = $check; Status = 'Warn'
                Details     = 'DKIM lookups failed for all selectors (DNS error).'
                Remediation = 'Re-run the check. If it keeps failing, confirm the domain resolves publicly.'
            }
        }
        return [PSCustomObject]@{
            Category = 'Email'; Check = $check; Status = 'Warn'
            Details     = "No DKIM key found among $($Selectors.Count) common selectors. DKIM may still be set up with a custom selector."
            Remediation = 'Confirm DKIM signing is enabled for each sending service (e.g. Microsoft 365 Defender > Email authentication > DKIM). Check a sent email header (DKIM-Signature: s=) for the selector name.'
        }
    }

    $status = 'Pass'
    $fixes  = New-Object System.Collections.Generic.List[string]
    $active = @($found | Where-Object { -not $_.Revoked })

    $lines = foreach ($f in $found) {
        if ($f.Revoked) {
            "$($f.Selector): revoked (empty key)"
        }
        elseif ($f.Bits) {
            "$($f.Selector): $($f.KeyType.ToUpper()) ~$($f.Bits)-bit"
        }
        else {
            "$($f.Selector): $($f.KeyType.ToUpper())"
        }
    }

    if ($active.Count -eq 0) {
        $status = 'Warn'
        $fixes.Add('All DKIM keys found are revoked. Enable DKIM signing with a new key.')
    }

    $weak = @($active | Where-Object { $_.Bits -eq 1024 })
    if ($weak.Count -gt 0) {
        $status = Get-WorstStatus $status 'Warn'
        $fixes.Add("Rotate 1024-bit keys to 2048-bit ($(($weak.Selector) -join ', ')).")
    }

    [PSCustomObject]@{
        Category    = 'Email'
        Check       = $check
        Status      = $status
        Details     = ($lines -join ' | ')
        Remediation = ($fixes -join ' ')
    }
}

# =============================================================================
# Public entry point
# =============================================================================

function Test-EmailSecurity {
    <#
    .SYNOPSIS
        Runs SPF, DMARC and DKIM checks for a domain.
    .PARAMETER Domain
        Domain to check, e.g. example.co.uk.
    .PARAMETER DnsServer
        Optional DNS server to query (e.g. 1.1.1.1). Defaults to the system resolver.
    .PARAMETER DkimSelectors
        Extra DKIM selectors to try on top of the built-in list.
    .EXAMPLE
        Test-EmailSecurity -Domain example.co.uk -DnsServer 1.1.1.1 -DkimSelectors 'mycrm1'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Domain,
        [string]$DnsServer,
        [string[]]$DkimSelectors
    )

    # Common selectors: Microsoft 365, Google, Mailchimp, Mandrill, Proton,
    # iCloud, Mimecast/others, and generic names.
    $selectors = @(
        'selector1', 'selector2',              # Microsoft 365
        'google',                              # Google Workspace
        'k1', 'k2', 'k3',                      # Mailchimp / others
        'mandrill', 'mte1', 'mte2',            # Mandrill / Mailchimp Transactional
        'protonmail', 'protonmail2', 'protonmail3',
        'sig1',                                # iCloud
        's1', 's2', 'smtp', 'dkim', 'mail', 'default', 'mxvault', 'everlytic'
    )
    if ($DkimSelectors) { $selectors = @($selectors + $DkimSelectors | Select-Object -Unique) }

    $results = New-Object System.Collections.Generic.List[object]
    $results.Add((Test-Spf   -Domain $Domain -Server $DnsServer))
    $results.Add((Test-Dmarc -Domain $Domain -Server $DnsServer))
    $results.Add((Test-Dkim  -Domain $Domain -Server $DnsServer -Selectors $selectors))

    return $results.ToArray()
}

Export-ModuleMember -Function Test-EmailSecurity
