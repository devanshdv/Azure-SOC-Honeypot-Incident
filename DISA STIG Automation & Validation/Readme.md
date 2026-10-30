# Automated DISA STIG Compliance & System Hardening

## Project Objective
To identify, validate, and automate the remediation of a Defense Information Systems Agency (DISA) Security Technical Implementation Guide (STIG) compliance vulnerability on a Windows 11 endpoint utilizing Tenable Nessus and PowerShell automation.

## Environment & Tooling
* **Infrastructure:** Microsoft Azure Virtual Machine (Windows 11)
* **Vulnerability Scanner:** Tenable Nessus
* **Automation:** Windows PowerShell ISE

---

## Phase 1: Environment Provisioning and Baseline Configuration
The project initiated with the deployment of a Windows 11 Virtual Machine within Microsoft Azure. To facilitate comprehensive compliance auditing, Tenable Nessus was configured with the appropriate system credentials. This authenticated configuration ensured the scanner could perform deep-level registry and policy checks against the target VM. 

![Azure VM & Tenable Authenticated Scan Configuration]<img width="1407" height="980" alt="image" src="https://github.com/user-attachments/assets/11f9f018-e653-4762-a6e0-b835a2750bed" /> <img width="1067" height="321" alt="image" src="https://github.com/user-attachments/assets/88f3ba8b-7d84-465a-a237-9a2697ab0e40" />



## Phase 2: Vulnerability Identification
An initial baseline STIG scan was executed against the Azure VM. The scan results identified a compliance failure related to Server Message Block (SMB) network operations.

* **STIG ID:** WN11-SO-000120
* **Vulnerability:** The Windows SMB server must be configured to always perform SMB packet signing.
* **Technical Check:** The system verifies if the `RequireSecuritySignature` value exists within the `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\` registry path and is set to `1`.

<img width="1220" height="503" alt="image" src="https://github.com/user-attachments/assets/11784700-7232-4cb0-9072-07898c68f426" />


## Phase 3: Manual Remediation and Validation
To confirm the exact technical requirements of the fix before scripting, the vulnerability was first remediated manually. Administrative access was used to open the Registry Editor on the target VM. The `RequireSecuritySignature` DWORD (32-bit) value was configured to `1` under the specified `LanManServer\Parameters` path. Following a system restart to apply the SMB configuration, a secondary Tenable scan was executed, successfully confirming the manual fix resolved the STIG failure.

<img width="534" height="324" alt="Screenshot 2026-10-29 221302" src="https://github.com/user-attachments/assets/32f92951-8a7e-4aba-aef7-5f00d1b2dc1f" />

Second Scan Results: <img width="534" height="324" alt="Screenshot 2026-10-29 221302" src="https://github.com/user-attachments/assets/8fc1085d-a3ec-4c16-bea7-9a34261d2353" />



## Phase 4: Remediation Rollback
To prepare the environment for automation testing, the manual registry configuration was deleted, reverting the VM to its original, non-compliant state. A third Tenable scan was executed to verify that the system was once again vulnerable and that the STIG failure had returned to the audit logs.

Deleted the manual configuration: <img width="1339" height="509" alt="Screenshot 2026-10-29 225331" src="https://github.com/user-attachments/assets/56d8a43d-22e7-4350-aedd-c3a81a5d257a" />


Re-Run the scan: <img width="1918" height="560" alt="Screenshot 2026-10-29 233117" src="https://github.com/user-attachments/assets/1c687884-10b3-469a-a1d7-1ceabe54ebcb" />


## Phase 5: Automated Remediation via PowerShell
With the remediation logic manually verified, a PowerShell script was developed to automate the deployment of the security control. The script was engineered to check the `LanManServer\Parameters` registry path to determine if the `RequireSecuritySignature` key existed. If absent, the script generated the DWORD value; if present, it modified the existing value. In both scenarios, the script enforced a final value of `1`. This script was successfully executed directly on the target VM utilizing PowerShell ISE.

PowerShell Script Implementation:
<img width="785" height="828" alt="Screenshot 2026-10-29 234433" src="https://github.com/user-attachments/assets/46e99d29-986d-46ef-9423-7dfe3c5dbaeb" />

Verify the script: <img width="880" height="875" alt="Screenshot 2026-10-29 234457" src="https://github.com/user-attachments/assets/4f441fc9-a9eb-4f8e-94ad-443eb51b4d0c" />


## Phase 6: Final Validation
Following the execution of the PowerShell script, a final credentialed Tenable scan was launched against the Azure VM. The results confirmed that the programmatic intervention successfully applied the required security configurations, permanently clearing the STIG vulnerability from the compliance report.

![Successful Automated Remediation Scan Result (Post-PowerShell)](path/to/your/image5.png)

Pass the scan: <img width="1214" height="482" alt="image" src="https://github.com/user-attachments/assets/632f70a2-2174-4ceb-b3e1-60e220833f64" />

```powershell
<#
.SYNOPSIS
This PowerShell script ensures that the The Windows SMB server must be configured to always perform SMB packet signing.

.NOTES
Author: Devansh Sharma
LinkedIn: linkedin.com/in/devansharma20
GitHub: github.com/devanshdv
Date Created: 10-30-2026(MM-DD-YYYY)
Last Modified: 10-30-2026(MM-DD-YYYY)
Version: 1.0
CVEs: N/A
Plugin IDs: N/A
STIG-ID: WN11-SO-000120
Documentation: https://stigaview.com/products/win11/v2r8/WN11-SO-000120/

.TESTED ON
Date(s) Tested:
Tested By:
Systems Tested:
PowerShell Ver.:

.USAGE
Put any usage instructions here. Example syntax: PS C:\> .\remediation_template(STIG-ID-WN10-AU-000500).ps1
#>

\$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
\$valueName = "RequireSecuritySignature"
\$targetValue = 1

# Check if the registry value exists
\$checkValue = Get-ItemProperty -Path $registryPath -Name$valueName -ErrorAction SilentlyContinue

if ($null -ne$checkValue) {
    # If it exists, change the value to 1
    Write-Host "'\$valueName' exists. Modifying value to \$targetValue."
    Set-ItemProperty -Path \$registryPath -Name $valueName -Value$targetValue
} 
else {
    # If it does not exist, create a new DWORD and set it to 1
    Write-Host "'\$valueName' does not exist. Creating and setting value to \$targetValue."
    New-ItemProperty -Path \$registryPath -Name $valueName -Value$targetValue -PropertyType DWORD
}

# Verify the final configuration
$finalCheck = (Get-ItemProperty -Path$registryPath -Name $valueName).$valueName
Write-Host "Verification complete: $valueName is now set to$finalCheck."
```
