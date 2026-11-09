<#
.SYNOPSIS
    Shared helper functions for the Domain Checker modules.

.DESCRIPTION
    Dot-sourced by EmailChecks.psm1, WebChecks.psm1 and InfrastructureChecks.psm1:

        . (Join-Path $PSScriptRoot 'Common.ps1')

    Because it is dot-sourced inside each module, these functions stay private
    to the module (each module only exports its own Test-* function).

    Functions:
        Test-DnsNotFound  - true if a Resolve-DnsName error means "no record"
        Get-DnsTxt        - TXT lookup returning Found / NotFound / Error
        Invoke-DnsQuery   - any record type, answer section only
        Get-WorstStatus   - returns the more serious of two statuses
        New-CheckResult   - builds a result object in the standard format

.NOTES
    File    : Modules\Common.ps1
    Version : 2.1.0
    Author  : Alex Wilson - ACC London

    ===========================================================================
    CHANGELOG
    ===========================================================================
    2.1.0
        - Initial version. Helpers previously copied into each module were
          moved here so a fix only has to be made once.
    ===========================================================================
#>

function Test-DnsNotFound {
    # Resolve-DnsName throws for "name does not exist" (9003 / NXDOMAIN) and
    # "no records of this type" (9501). Those mean "not found", not a failure.
    param([Parameter(Mandatory)]$ErrorRecord)
    return ($ErrorRecord.FullyQualifiedErrorId -match 'DNS_ERROR_RCODE_NAME_ERROR|DNS_INFO_NO_RECORDS|9003|9501')
}

function Get-DnsTxt {
    # Looks up TXT records.
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
        # Keep real TXT answers only - ignore SOA (authority) and CNAME entries
        $answers = @(Resolve-DnsName @params | Where-Object { $_.QueryType -eq 'TXT' })
        $records = @($answers | ForEach-Object { ($_.Strings -join '') })

        if ($records.Count -gt 0) {
            return [PSCustomObject]@{ Status = 'Found'; Records = $records; Message = '' }
        }
        return [PSCustomObject]@{ Status = 'NotFound'; Records = @(); Message = '' }
    }
    catch {
        if (Test-DnsNotFound $_) {
            return [PSCustomObject]@{ Status = 'NotFound'; Records = @(); Message = '' }
        }
        return [PSCustomObject]@{ Status = 'Error'; Records = @(); Message = $_.Exception.Message }
    }
}

function Invoke-DnsQuery {
    # Generic lookup for any record type.
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
        # Older Windows builds don't recognise newer record types (e.g. CAA)
        return [PSCustomObject]@{ Status = 'Unsupported'; Answers = @(); All = @(); Message = $_.Exception.Message }
    }
    catch {
        if (Test-DnsNotFound $_) {
            return [PSCustomObject]@{ Status = 'NotFound'; Answers = @(); All = @(); Message = '' }
        }
        return [PSCustomObject]@{ Status = 'Error'; Answers = @(); All = @(); Message = $_.Exception.Message }
    }
}

function Get-WorstStatus {
    # Returns the more serious of two statuses: Fail > Warn > Pass.
    param([string]$Current, [string]$New)
    $rank = @{ Pass = 0; Warn = 1; Fail = 2 }
    if ($rank[$New] -gt $rank[$Current]) { return $New }
    return $Current
}

function New-CheckResult {
    # Builds a result object in the format Invoke-DomainCheck.ps1 expects.
    param(
        [string]$Category,
        [string]$Check,
        [string]$Status,
        [string]$Details,
        [string]$Remediation = ''
    )
    [PSCustomObject]@{
        Category    = $Category
        Check       = $Check
        Status      = $Status
        Details     = $Details
        Remediation = $Remediation
    }
}
