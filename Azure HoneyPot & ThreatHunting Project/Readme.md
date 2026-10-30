# Azure Honeypot & Microsoft Sentinel Incident Response

## Objective
Deployed an Azure virtual machine (`dataorg-dv-28m`) functioning as a honeypot to attract and analyze live, inbound brute-force and ransomware attacks. Utilized Microsoft Sentinel and Log Analytics to separate automated botnet noise from successful interactive compromises.


## Tools & Technologies
* **Cloud Infrastructure:** Microsoft Azure (Virtual Machines, NSGs)
* **SIEM / Log Management:** Microsoft Sentinel, Log Analytics Workspaces
* **Query Language:** Kusto Query Language (KQL)
* **Visualization:** Azure Workbooks (Geomapping)

## Objective
Deployed an Azure virtual machine (`dataorg-dv-28m`) functioning as a honeypot to attract and analyze live, inbound brute-force and ransomware attacks. Utilized Microsoft Sentinel and Log Analytics to separate automated botnet noise from successful interactive compromises.

## Tools & Technologies
* **Cloud Infrastructure:** Microsoft Azure (Virtual Machines, Network Security Groups)
* **SIEM / Log Management:** Microsoft Sentinel, Log Analytics Workspaces, Azure Monitor Agent (AMA)
* **Endpoint Detection & Response (EDR):** Microsoft Defender for Endpoint (MDE)
* **Query Language:** Kusto Query Language (KQL)
* **Visualization:** Azure Workbooks (Geomapping)
* **Database:** MySQL Server 8.0

---
# Phase-by-Phase Execution
## Part 1: Environment Setup & Telemetry Architecture

This project required a deliberately vulnerable, yet heavily monitored, cloud environment to safely capture and analyze live threat actor behavior.

### 1. Architectural Overview
The foundation of this lab is an Azure Windows 11 Virtual Machine acting as the primary honeypot. To ensure comprehensive visibility, the architecture routes MySQL application logs through the Azure Monitor Agent (AMA) to a Log Analytics Workspace (`LAW-Cyber-Range`), while OS-level telemetry is ingested directly into Microsoft Defender for Endpoint (MDE).

<img width="607" height="398" alt="image" src="https://github.com/user-attachments/assets/cd2831eb-9f01-463b-b19f-662a981b9fbe" />

### 2. Endpoint Detection and Response (EDR) Onboarding
Before exposing the asset to the internet, it was critical to establish baseline security monitoring. The virtual machine (`dataorg-dv-28m`) was onboarded into Microsoft Defender for Endpoint. This guarantees that all OS-level activities—specifically `DeviceLogonEvents`, process executions, and network connections—are recorded for forensic analysis once the brute-force campaigns begin.

<img width="1907" height="771" alt="Screenshot 2026-10-09 211844" src="https://github.com/user-attachments/assets/2824c7af-ed5f-4e81-9762-d28beff98c90" />


### 3. Database Provisioning
A local MySQL Server instance was installed on the virtual machine to serve as the primary attack vector. Using MySQL Workbench, a new standard TCP/IP connection named `DataOrg-SQLDVM` was established on port 3306.

<img width="1090" height="743" alt="Screenshot 2026-10-09 213056" src="https://github.com/user-attachments/assets/b353becd-97c6-4cf2-9735-5f9a80cb631f" />


### 4. Injecting the "Crown Jewels" (Honeypot Bait)
To entice threat actors and monitor exfiltration tactics, an attractive target had to be created. A custom SQL script was executed to build a dummy database named `dvm_corp`. This database was populated with thousands of rows of synthetic Personally Identifiable Information (PII), including fake customer records, masked payment cards, and application credentials.

<img width="1067" height="758" alt="Screenshot 2026-10-09 213715" src="https://github.com/user-attachments/assets/374382d5-a35c-4b28-85a2-526e18d94315" />


### 5. Configuring Local Audit Logging
By default, MySQL does not log every query, which is insufficient for a SOC environment. The underlying `my.ini` configuration file in the `C:\ProgramData\MySQL\MySQL Server 8.0\` directory was replaced with a custom configuration designed to force verbose logging.

<img width="1604" height="838" alt="Screenshot 2026-10-09 214242" src="https://github.com/user-attachments/assets/d181733b-1bed-43ef-9ca5-60c869c3b079" />


Following the file replacement, global logging variables were explicitly enabled via MySQL Workbench (`SET GLOBAL general_log = 'ON';`) to ensure all inbound connections, authentications, and SQL queries were written to the local disk.

<img width="1064" height="530" alt="Screenshot 2026-10-09 214301" src="https://github.com/user-attachments/assets/1944d5e6-417f-4bd2-ab43-50cb3121133f" />


### 6. Telemetry Verification & Service Restart
To validate the logging pipeline, sample queries (e.g., `SELECT * FROM dvm_corp.payments`) were executed against the dummy database. 

<img width="968" height="575" alt="Screenshot 2026-10-09 214411" src="https://github.com/user-attachments/assets/765e3068-d614-4d8b-a7bc-145cc1a923f8" />


The `MySQL80` service was then restarted via Windows Services (`services.msc`) to flush the cache and apply the new `my.ini` configurations permanently. 

<img width="660" height="433" alt="Screenshot 2026-10-09 214953" src="https://github.com/user-attachments/assets/d6953b60-7599-432f-937a-ad23fefc6125" />


Inspection of the local `mysql_general.log` file confirmed that the application was successfully recording rich telemetry, including timestamps, connection IDs, and the exact SQL syntax of the sample queries.

<img width="1426" height="638" alt="Screenshot 2026-10-09 215131" src="https://github.com/user-attachments/assets/8aaf665b-83fb-42e1-97d9-2c1ba827df53" />


### 7. Azure Data Collection Rule (DCR) Configuration
With local logs generating successfully, the final step was to route this data into the SIEM. A Data Collection Rule (`dcr-Org-DV-28M`) was created in Azure. 

<img width="752" height="515" alt="Screenshot 2026-10-09 220948" src="https://github.com/user-attachments/assets/a0287023-8a2e-4f22-ad39-2f532577555c" />


This rule instructs the Azure Monitor Agent (AMA) installed on the VM to parse the local `mysql_general.log` text file and stream it directly into the `MySQLAudit_CL` custom log table within the Sentinel workspace. 


<img width="1129" height="847" alt="Screenshot 2026-10-09 230823" src="https://github.com/user-attachments/assets/3da5c2c7-ed71-4422-8f1b-29c23afd162c" />



---

## Part 2: Detection Engineering & Attack Simulation

### 8. Detection Engineering & SIEM Alerting
With the telemetry flowing into the Log Analytics Workspace, custom detection rules (Analytics Rules) were engineered within Microsoft Sentinel using KQL.

<img width="1700" height="950" alt="Screenshot 2026-10-09 230642" src="https://github.com/user-attachments/assets/2ee8dc6d-54a7-468a-bebc-c23c6f677eae" />


**Rule 1: Virtual Machine Logons**  
Designed to monitor successful interactive logons to the highly targeted `administrator` and `guest` accounts:

```kusto
let MyDevice = "dataorg-dv-28m";
DeviceLogonEvents
| where DeviceName == MyDevice
| where AccountName in~ ("administrator", "guest")
| where ActionType == "LogonSuccess"
| project TimeGenerated, RemoteIP, AccountName, DeviceName, ActionType, LogonType
`````
**Rule 2: SQL Server - Failed Login → Successful Login Detection
An advanced behavioral detection tracking IP addresses that generated multiple Access denied errors followed by a successful Connect event, indicating a compromised database credential:
```kusto
let MyDevice = "dataorg-dv-28m";
let MyTimeframe = ago(7d);
let FailedConnections =
    MySQLAudit_CL
    | where TimeGenerated > MyTimeframe
    | extend RawData = replace_string(RawData, "\t", " ")
    | extend DeviceName = tostring(split(_ResourceId, "/")[-1])
    | where DeviceName == MyDevice
    | where RawData has "Access denied"
    | extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
    | distinct ConnectionId;
MySQLAudit_CL
| where TimeGenerated > MyTimeframe
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Connect"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| extend ActionType = case(RawData has "Access denied", "LogonFailure", ConnectionId in (FailedConnections), "Ignore", "LogonSuccess")
| where ActionType != "Ignore"
| extend Username = replace_string(tostring(split(tostring(split(RawData,"@")[0]), " ")[-1]), "'", "")
| extend IpAddress = replace_string(tostring(split(split(RawData,"@")[1], " ")[0]), "'", "")
| where ActionType == "LogonSuccess"
| project TimeGenerated, DeviceName, Username, IpAddress, ActionType, RawData
| order by TimeGenerated desc
`````
These rules were scheduled to run every 10 minutes, with Entity Mapping configured for HostName and IP to ensure alerts generated actionable incident graphs.
### 9. Intentionally Downgrading Security (The Lure)
To transform the standard virtual machine into an attractive honeypot, standard local accounts (administrator and guest) were enabled and configured with weak passwords.

<img width="839" height="531" alt="Screenshot 2026-10-09 233228" src="https://github.com/user-attachments/assets/1b9ad3aa-af12-44d0-bda4-2cd3a864c3f3" />

These accounts were granted remote access by adding them to the Remote Desktop Users group.

<img width="870" height="692" alt="Screenshot 2026-10-09 234203" src="https://github.com/user-attachments/assets/64ee6bcf-f0df-487f-bcaf-af79faa15783" />

<img width="1200" height="798" alt="Screenshot 2026-10-09 235532" src="https://github.com/user-attachments/assets/25ea7894-e0c0-4f69-b02c-4c8d3d962ff9" />



Finally, a new priority rule (DANGER-allow-all-inbound) was implemented in the Azure Network Security Group (NSG), exposing RDP (3389) and MySQL (3306) directly to the public internet.

<img width="1301" height="808" alt="Screenshot 2026-10-10 001601" src="https://github.com/user-attachments/assets/4754e035-bcec-4f60-b1c4-705760123bf4" />


---

## Part 3: Incident Response & Executive Findings

By exposing the vulnerable VM to the public internet, the environment immediately became a target for automated global botnets and opportunistic threat actors. The SIEM successfully captured the entire attack lifecycle, from initial reconnaissance to total host compromise.

**Key Attack Lifecycle Milestones:**
* **Massive Inbound Reconnaissance:** Thousands of automated attempts to brute-force the Windows OS (RDP) and the MySQL database.
* **Database Compromise & Exfiltration:** Threat actors successfully guessed the MySQL root credentials, mapped the schema, and executed data exfiltration (`SELECT * FROM dvm_corp.customers`).
* **Destructive Ransomware:** The execution of automated scripts dropped all production tables and inserted a `RECOVER_YOUR_DATA` extortion demand.
* **Host Takeover:** Successful RDP brute-forcing led to an interactive graphical session by a secondary threat actor.

---

## 📁 Project Deliverables & Artifacts

To review the complete investigation, executive summary, and the raw code used in this environment, please refer to the following repository files:

* 📄 **[Comprehensive Incident Response Report (PDF)](https://github.com/devanshdv/Security-Engineering-Portfolio/blob/main/Azure%20HoneyPot%20%26%20ThreatHunting%20Project/Incident%20Report-HoneyPot%20Project.pdf)**
  * *Includes the executive summary, detailed timeline of events, MITRE ATT&CK mapping, and recommended remediation steps.*
* 💻 **[Raw KQL Investigation Queries](https://github.com/devanshdv/Security-Engineering-Portfolio/blob/main/Azure%20HoneyPot%20%26%20ThreatHunting%20Project/DFIR%20Report-HoneyPot%20Project.pdf)**
  * *Contains all Kusto Query Language scripts engineered for threat detection, log parsing, and Azure Workbook geomapping.*

---
*This project was built to demonstrate practical, hands-on experience with cloud infrastructure, SIEM engineering, and digital forensics. Feel free to reach out on [LinkedIn](www.linkedin.com/in/devansharma28) if you have any questions about the methodology!*
