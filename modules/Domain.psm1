function Check-DomainAvailability {
    param (
        [string]$Domain
    )
    $result = Resolve-DnsName -Name $Domain -ErrorAction SilentlyContinue
    return $result -eq $null
}

function Get-WhoisInformation {
    param (
        [string]$Domain
    )
    $whoisCommand = "whois " + $Domain
    $whoisResult = Invoke-Expression $whoisCommand
    return $whoisResult
}