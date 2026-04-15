function Test-EmailSecurity {
    param([string]$Domain)

    $results = @()

    # SPF Check
    $spf = Resolve-DnsName -Name $Domain -Type TXT -ErrorAction SilentlyContinue |
           Where-Object {$_.Strings -like "*v=spf1*"}

    if ($spf) {
        $status = "Pass"
        $details = $spf.Strings
        if ($spf.Strings -like "*-all") { $details += " | Hard fail (Good)" }
        elseif ($spf.Strings -like "*~all") { $details += " | Soft fail (Moderate)" }
        else { $details += " | No fail mechanism (Poor)" }
    } else {
        $status = "Fail"
        $details = "No SPF record found"
    }

    $results += [PSCustomObject]@{
        Check = "SPF Record"
        Status = $status
        Details = $details
    }


# DMARC Check
$dmarcRaw = Resolve-DnsName -Name "_dmarc.$Domain" -Type TXT -ErrorAction SilentlyContinue

# Filter to only actual TXT records — ignore SOA/authority responses
$dmarc = $dmarcRaw | Where-Object { $_.QueryType -eq 'TXT' }

if ($dmarc -and ($dmarc.Strings -like "v=DMARC1*")) {
    $details = ($dmarc.Strings | Out-String).Trim()

    if ($dmarc.Strings -like "*p=reject*") {
        $status  = "Pass"
        $details += " | Reject policy (Excellent)"
    }
    elseif ($dmarc.Strings -like "*p=quarantine*") {
        $status  = "Pass"
        $details += " | Quarantine policy (Good)"
    }
    else {
        # p=none or missing/malformed policy tag
        $status  = "Fail"
        $details += " | None policy (Poor) - domain is not enforcing DMARC"
    }
}
elseif ($dmarcRaw -and ($dmarcRaw.QueryType -contains 'SOA')) {
    # DNS returned only an SOA authority record — no DMARC TXT exists
    $status  = "Fail"
    $details = "No DMARC record found (SOA authority response from $($dmarcRaw.PrimaryServer))"
}
else {
    $status  = "Fail"
    $details = "No DMARC record found"
}

$results += [PSCustomObject]@{
    Check   = "DMARC Record"
    Status  = $status
    Details = $details
}


# DKIM Check
$selectors = @("selector1", "selector2", "google", "k1", "dkim", "mail", "default")
$dkimFound = @()

foreach ($selector in $selectors) {
    try {
        $dkim = Resolve-DnsName "$selector._domainkey.$Domain" -Type TXT -ErrorAction Stop

        if ($dkim -and $dkim.Strings) {
            $dkimRecord = ($dkim.Strings -join "")

            if ($dkimRecord -match "v=DKIM1") {
                # Store both the selector name and its full record value
                $dkimFound += [PSCustomObject]@{
                    Selector = $selector
                    Record   = $dkimRecord
                }
            }
        }
    }
    catch {
        # Ignore missing selectors
    }
}

if ($dkimFound.Count -gt 0) {
    # Build a detailed description for every found selector
    $details = ($dkimFound | ForEach-Object {
        "$($_.Selector): $($_.Record)"
    }) -join "`n"

    $results += [PSCustomObject]@{
        Check   = "DKIM Selectors"
        Status  = "Pass"
        Details = $details
    }
}
else {
    $results += [PSCustomObject]@{
        Check   = "DKIM Selectors"
        Status  = "Fail"
        Details = "No DKIM selectors found"
    }
}

return $results
}

Export-ModuleMember -Function Test-EmailSecurity