function Test-WebSecurity {
    param([string]$Domain)

    $results = @()

    # -- SSL Certificate Check ----------------------------------------
    try {
        $request = [System.Net.HttpWebRequest]::Create("https://$Domain")
        $request.Method = "HEAD"
        $request.Timeout = 10000
        $response = $request.GetResponse()
        $cert = $request.ServicePoint.Certificate
        $expiry = [DateTime]::Parse($cert.GetExpirationDateString())
        $daysLeft = ($expiry - (Get-Date)).Days
        $status = if ($daysLeft -gt 30) { "Pass" } else { "Warn" }
        $details = "Valid until $expiry ($daysLeft days)"
        $response.Close()
    } catch {
        $status = "Fail"
        $details = "SSL check failed: $_"
    }

    $results += [PSCustomObject]@{
        Check   = "SSL Certificate"
        Status  = $status
        Details = $details
    }

    # -- Security Headers Check ----------------------------------------
    try {
        $resp = Invoke-WebRequest -Uri "https://$Domain" -Method Head -UseBasicParsing
        $headers = $resp.Headers

        $headerChecks = @{
            "Strict-Transport-Security" = "HSTS"
            "Content-Security-Policy"   = "CSP"
            "X-Frame-Options"           = "Clickjacking"
            "X-Content-Type-Options"    = "MIME Sniffing"
            "Referrer-Policy"           = "Referrer"
        }

        foreach ($h in $headerChecks.Keys) {
            if ($headers.ContainsKey($h)) {
                $results += [PSCustomObject]@{
                    Check   = "$($headerChecks[$h]) Header"
                    Status  = "Pass"
                    Details = "Present"
                }
            } else {
                $results += [PSCustomObject]@{
                    Check   = "$($headerChecks[$h]) Header"
                    Status  = "Fail"
                    Details = "Missing"
                }
            }
        }
    } catch {
        $results += [PSCustomObject]@{
            Check   = "Security Headers"
            Status  = "Warn"
            Details = "Header check failed: $_"
        }
    }

    # -- MTA-STS Check -------------------------------------------------
    # Step 1 - DNS TXT record at _mta-sts.<domain>
    $mtaDnsOk = $false
    try {
        $txtRecords = Resolve-DnsName -Name "_mta-sts.$Domain" -Type TXT -ErrorAction Stop
        $stsTxt = $txtRecords |
            Where-Object { $_.Strings -match '^v=STSv1' } |
            Select-Object -First 1

        if ($stsTxt) {
            $mtaDnsOk = $true
            $results += [PSCustomObject]@{
                Check   = "MTA-STS DNS Record"
                Status  = "Pass"
                Details = ($stsTxt.Strings -join '')
            }
        } else {
            $results += [PSCustomObject]@{
                Check   = "MTA-STS DNS Record"
                Status  = "Fail"
                Details = "TXT record exists but missing v=STSv1 tag"
            }
        }
    } catch {
        $results += [PSCustomObject]@{
            Check   = "MTA-STS DNS Record"
            Status  = "Fail"
            Details = "No TXT record at _mta-sts.$Domain"
        }
    }

    # Step 2 - Policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt
    if ($mtaDnsOk) {
        $policyUrl = "https://mta-sts.$Domain/.well-known/mta-sts.txt"
        try {
            $policyResp = Invoke-WebRequest -Uri $policyUrl -UseBasicParsing -TimeoutSec 10

            if ($policyResp.StatusCode -eq 200) {
                $policyBody = $policyResp.Content

                # Parse key fields from the plain-text policy
                $mode   = if ($policyBody -match '(?m)^\s*mode:\s*(.+)$')    { $Matches[1].Trim() } else { $null }
                $maxAge = if ($policyBody -match '(?m)^\s*max_age:\s*(\d+)') { [int]$Matches[1]    } else { $null }
                $mxLines = [regex]::Matches($policyBody, '(?m)^\s*mx:\s*(.+)$') |
                           ForEach-Object { $_.Groups[1].Value.Trim() }

                # Evaluate mode
                switch ($mode) {
                    'enforce' {
                        $policyStatus  = "Pass"
                        $policyDetails = "Mode: enforce"
                    }
                    'testing' {
                        $policyStatus  = "Warn"
                        $policyDetails = "Mode: testing (not yet enforcing)"
                    }
                    'none' {
                        $policyStatus  = "Fail"
                        $policyDetails = "Mode: none (policy disabled)"
                    }
                    default {
                        $policyStatus  = "Warn"
                        $policyDetails = "Mode field missing or unrecognised"
                    }
                }

                # Warn if max_age is below 1 day (86400s)
                if ($null -ne $maxAge -and $maxAge -lt 86400) {
                    $policyStatus  = "Warn"
                    $policyDetails += " | max_age too low: ${maxAge}s"
                }

                $policyDetails += " | max_age: $maxAge | MX: $($mxLines -join ', ')"

                $results += [PSCustomObject]@{
                    Check   = "MTA-STS Policy"
                    Status  = $policyStatus
                    Details = $policyDetails
                }
            } else {
                $results += [PSCustomObject]@{
                    Check   = "MTA-STS Policy"
                    Status  = "Fail"
                    Details = "Unexpected HTTP $($policyResp.StatusCode) from $policyUrl"
                }
            }
        } catch {
            $results += [PSCustomObject]@{
                Check   = "MTA-STS Policy"
                Status  = "Fail"
                Details = "Could not retrieve policy: $_"
            }
        }
    } else {
        $results += [PSCustomObject]@{
            Check   = "MTA-STS Policy"
            Status  = "Fail"
            Details = "Skipped - DNS record missing"
        }
    }

    return $results
}

Export-ModuleMember -Function Test-WebSecurity