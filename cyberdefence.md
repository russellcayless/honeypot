# Cyber Range Capstone

**Live-Exposed Honeypot Lab — End-to-End Checklist**  
Build hard → instrument → baseline → detect → weaken & expose. Windows VM + MySQL, telemetry to LAW-Cyber-Range.

This checklist walks the full defensive lifecycle for an internet-exposed asset. You build and harden the box, wire up logging, capture a clean baseline, write your detections while the environment is still quiet, and only then deliberately weaken and expose it so real attacker traffic supplies the breach. Work the phases in order — detections must exist before exposure so you catch your own incident.

---

**Phase 0 — Honeypot Architecture**


<img width="1767" alt="Screen Shot 2025-05-07 at 11 26 51 PM" src="https://github.com/russellcayless/Entra/blob/cd5c32551922714de262c72fbfa6ef7e6cd16ef3/defaultloginscreen.png" />

---

**Phase 1 — Build the VM Honeypot (locked down while we build it)**

 - Deploy a Windows 11 VM in your own resource group (strong username and password) — ensure you configure a public IP address
 - Name the VM something good, like “CORP-XXX-YYY” or something that looks legit, not “lab_test_1”
 - Deny all inbound traffic from the internet
 - Onboard the VM to Microsoft Defender for Endpoint (MDE), ensure it is showing up in the DeviceInfo table

---

**Phase 2 — Install & populate MySQL**

 - On your VM, install Microsoft Visual C++ 2019 Redistributable Package (x64) (My SQL Requirement) (ref) 
 - On your VM Install MySQL (ref), Install with “Developer Default” or “Full” so it installs Workbench/the GUI
   - Install with all defaults
   - For the MySQL root password, on this phase, make it something strong, store it in a password manager for now (or somewhere you feel comfortable)
   - Everything else Defaults
 - Start MySQL Workbench after the installation, create a new connection, and connect to MySQL
 - Create a database and ingest dummy data → Download db_info_import.sql onto your VM and import it into your instance of MySQL (open SQL script, then execute it) 
   - ⚠️this will seem like MySQL Workbench has frozen, it will just take some time. If the connection drops or it fails, just enter the MySQL password if needed and try again → change users from 5000 to 1000 or less if it fails too many times
 - On the Schemas tab, refresh it to observe the new schema (database) “lnp_corp”
 - **Enable MySQL audit / general query logging** so every connection (success and failure) and query is written to a log file. Do that by running this query:
——————————————————————————
SET GLOBAL general_log = 'ON';
SET GLOBAL log_output = 'FILE';
SHOW VARIABLES LIKE 'general_log%';
——————————————————————————
 - Download my.ini and replace this file on your VM with it:C:\ProgramData\MySQL\MySQL Server 8.0\my.ini
   - This file tells MySQL to log everything to, it also allows login over the network:
"C:\ProgramData\MySQL\MySQL Server 8.0\Data\mysql_general.log"
 - Restart the MySQL80 service (services.msc)
 - Run a few “SELECT” queries and then check the mysql_general.log to ensure the logs are coming through.
 - Note the MySQL log file path (needed for the DCR in Phase 3)
   
 ---

**Phase 3 — Wire logging to Log Analytics**

 - Ensure your VM is ON and RUNNING, this is important
 - Confirm device telemetry is flowing to LAW-Cyber-Range (check the DeviceInfo Table)
 - Create a custom-text-log DCR pointing AMA at the MySQL log file → lands in a custom table: MySQLAudit_CL 
 - It’s VERY important this is correct (Logs may take up to 30 minutes to appear)
__________________________
File pattern:		C:\ProgramData\MySQL\MySQL Server 8.0\Data\mysql_general.log
Table name:		MySQLAudit_CL
Record delimiter:	TimeStamp
Timestamps format:	ISO 8601
__________________________

<img width="1767" alt="Screen Shot 2025-05-07 at 11 26 51 PM" src="https://github.com/russellcayless/Entra/blob/cd5c32551922714de262c72fbfa6ef7e6cd16ef3/defaultloginscreen.png" />

<img width="1767" alt="Screen Shot 2025-05-07 at 11 26 51 PM" src="https://github.com/russellcayless/Entra/blob/cd5c32551922714de262c72fbfa6ef7e6cd16ef3/defaultloginscreen.png" />

 - Immediately after successfully creating the DCR, The Azure Monitor Agent will start to be installed on your VM. Browse to your VM → Settings → Extensions + applications, and look for “AzureMonitorWindowsAgent”:

<img width="1767" alt="Screen Shot 2025-05-07 at 11 26 51 PM" src="https://github.com/russellcayless/Entra/blob/cd5c32551922714de262c72fbfa6ef7e6cd16ef3/defaultloginscreen.png" />

 - Verify ingestion: query MySQLAudit_CL and confirm test connections / queries appear
   -**MySQLAudit_CL
      | project TimeGenerated, RawData, _ResourceId
      | where _ResourceId endswith "your-VM-Name"**
 - Verify core device tables are populating. Once your logs are coming through, you can move on to Phase 4. ⚠️This table contains EVERYONE’S MySQL logs, you have to filter yours to match your ResourceId. For example:
    -**MySQLAudit_CL
     | where _ResourceId endswith "josh-mde-lab**

---


