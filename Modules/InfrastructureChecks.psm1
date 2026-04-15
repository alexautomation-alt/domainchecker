function Test-Infrastructure {
    param([string]$Domain)

    $results = @()

    # Common Subdomains
    $subs = @("www","mail","ftp","admin","test","dev","staging","api","vpn","portal")
    $found = @()
    foreach ($s in $subs) {
        try {
            Resolve-DnsName -Name "$s.$Domain" -ErrorAction Stop | Out-Null
            $found += "$s.$Domain"
        } catch {}
    }

    $status = if ($found.Count -gt 0) { "Pass" } else { "Fail" }
    $details = if ($found.Count -gt 0) { $found -join ", " } else { "No common subdomains found" }

    $results += [PSCustomObject]@{
        Check = "Subdomain Enumeration"
        Status = $status
        Details = $details
    }

    return $results
}

Export-ModuleMember -Function Test-Infrastructure