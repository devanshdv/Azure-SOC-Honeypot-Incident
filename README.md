# Azure Honeypot & Microsoft Sentinel Incident Response
*(Drag and drop your image_c7a023.jpg file right here to embed the map)*

## Objective
Deployed an Azure virtual machine (`dataorg-dv-28m`) functioning as a honeypot to attract and analyze live, inbound brute-force and ransomware attacks. Utilized Microsoft Sentinel and Log Analytics to separate automated botnet noise from successful interactive compromises.

## Tools & Technologies
* **Cloud Infrastructure:** Microsoft Azure (Virtual Machines, NSGs)
* **SIEM / Log Management:** Microsoft Sentinel, Log Analytics Workspaces
* **Query Language:** Kusto Query Language (KQL)
* **Visualization:** Azure Workbooks (Geomapping)

## Core Findings & Methodology
* Mapped global inbound attack telemetry utilizing `DeviceLogonEvents` and `MySQLAudit_CL`.
* Designed a custom Azure Workbook Geomap to visually contrast thousands of failed brute-force attempts (green) against the specific geographic origin of a successful compromise (red).
* Executed a full DFIR investigation timeline, tracking the initial point of entry, unauthorized database reconnaissance, and the execution of a destructive ransomware payload.

## Project Files
* **[Incident Response Report (PDF)](insert-link-to-pdf-here)**
* **[Raw KQL Investigation Queries](insert-link-to-kql-file-here)**
