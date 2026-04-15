# Domain Checker - Main Entry Point Script
# This script orchestrates the PowerShell modules for domain checking

param(
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    [Parameter(Mandatory=$false)]
    [ValidateSet('availability', 'dns', 'validate', 'all')]
    [string]$CheckType = 'all',
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = './config.json'
)

# Import configuration
if (Test-Path $ConfigPath) {
    $config = Get-Content $ConfigPath | ConvertFrom-Json
} else {
    Write-Warning "Config file not found at $ConfigPath. Using defaults."
    $config = @{}
}

# Import modules
$modulePath = Join-Path (Split-Path $PSCommandPath) 'modules'
Import-Module (Join-Path $modulePath 'Validation.psm1') -Force
Import-Module (Join-Path $modulePath 'Domain.psm1') -Force
Import-Module (Join-Path $modulePath 'DNS.psm1') -Force

if (-not $Domain) {
    Write-Host 'Usage: .\domainchecker.ps1 -Domain <domain> [-CheckType <type>]'
    Write-Host 'CheckType options: availability, dns, validate, all'
    exit
}

# Run checks based on type
switch ($CheckType) {
    'availability' { Check-DomainAvailability -Domain $Domain }
    'dns' { Get-DNSRecords -Domain $Domain }
    'validate' { Test-DomainFormat -Domain $Domain }
    'all' {
        Write-Host "=== Domain Checker Results for $Domain ==="
        Test-DomainFormat -Domain $Domain
        Check-DomainAvailability -Domain $Domain
        Get-DNSRecords -Domain $Domain
    }
}