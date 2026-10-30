<#
.SYNOPSIS
    This PowerShell script ensures that the The Windows SMB server must be configured to always perform SMB packet signing.

.NOTES
    Author          : Devansh Sharma
    LinkedIn        : linkedin.com/in/devansharma28
    GitHub          : github.com/devanshdv
    Date Created    : 10-30-2026(MM-DD-YYYY)
    Last Modified   : 10-30-2026(MM-DD-YYYY)
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000120
    Documentation   : https://stigaview.com/products/win11/v2r8/WN11-SO-000120/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000500).ps1 
#>

$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$valueName = "RequireSecuritySignature"
$targetValue = 1

# Check if the registry value exists
$checkValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue

if ($null -ne $checkValue) {
    # If it exists, change the value to 1
    Write-Host "'$valueName' exists. Modifying value to $targetValue."
    Set-ItemProperty -Path $registryPath -Name $valueName -Value $targetValue
}
else {
    # If it does not exist, create a new DWORD and set it to 1
    Write-Host "'$valueName' does not exist. Creating and setting value to $targetValue."
    New-ItemProperty -Path $registryPath -Name $valueName -Value $targetValue -PropertyType DWORD
}

# Verify the final configuration
$finalCheck = (Get-ItemProperty -Path $registryPath -Name $valueName).$valueName
Write-Host "Verification complete: $valueName is now set to $finalCheck."
