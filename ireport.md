# **Incident Report — MySQL Extortion / Ransom on s-121292839**

Report status: Draft — built from 5 exported log sources only. Sections marked Not determined from available logs need follow-up (SIEM/host EDR portal, cloud provider abuse contacts, backups team).

## **1. Executive Summary**

An internet-reachable MySQL instance on host **s-121292839** was accessed with full root/% privileges by multiple external IPs starting **22 Aug 2026 14:31 UTC.** The attacker(s) enumerated and read three databases (**lnp_corp, sakila, world**) — including a **credentials** table — then **dropped all three databases** and left a ransom note in a newly created **RECOVER_YOUR_DATA** database demanding 0.011 BTC. The attack recurred at least five more times through **23 Aug 05:00 UTC**, each time re-creating the ransom note, indicating the exposure was never closed during that window. Separately, the same host absorbed a 40-attempt Windows **administrator** brute force from a different IP on 22 Aug; no logs confirm that brute force succeeded. No host-level malware execution or file-encryption activity was found in the Windows telemetry provided — the confirmed impact is database-layer (drop + extortion note), not a host-based ransomware/encryptor.

---

## **2. Incident Details**

 - Detection date/time
   - **Not determined from available logs** — no alert/detection record was supplied; log export ends 23 Aug 2026 09:00:47
 - Reporter
   - **Not determined from available logs**
 - Classification
   - Unauthorized database access / data destruction / extortion (MySQL "RECOVER_YOUR_DATA" ransom pattern). Not a confirmed file-                                      encrypting ransomware event on the host.
 - Severity
   - **High** — confirmed data destruction (3 DBs dropped) and credential/customer data exposure risk; DB was internet-facing with **root@%**                           and grant option
 - Affected system(s)
   - **s-121292839** (Windows host running MySQL)
 - Affected data
   - MySQL databases: lnp_corp (incl. credentials, customers, payments, orders tables), sakila, world

---

## **3. Impact Assessment**

 - **Confidentiality:** Attacker ran **SELECT** * against **credentials, customers, payments, orders, staff,** and other tables before dropping the databases — treat as a confirmed data-read/exfiltration-risk event, not just destruction. No **DeviceNetworkEvents/NTANetAnalytics** were provided, so actual data egress to an external destination is not determined from available logs.
 - **Integrity/Availability:** **lnp_corp, sakila,** and **world** databases were dropped **(DROP DATABASE)**. A **SHUTDOWN** and **RESET MASTER / PURGE BINARY LOGS** were also issued, which **destroys binlog-based recovery/forensic data** for the instance.
 - **Scope:** Single host/single MySQL instance confirmed. No evidence of lateral movement to other hosts in the provided data (only one **DeviceName** appears across all sources).
 - **Business impact:** Loss of the **lnp_corp** production-looking database (customer/payment/credential tables) is the primary business risk pending confirmation of backup availability. **Not determined from available logs.**

---

## **4. Indicators of Compromise**

⚠ Discrepancy note: The BTC address, email, URL, and DATAID provided as "known IOCs" for this case do not appear anywhere in the supplied logs. The logs contain a different but same-template ransom note. Both sets are listed below — treat the "Provided (unconfirmed in logs)" row as needing separate validation, and use the "Confirmed in logs" rows for this specific incident.

<img width="1767" alt="Screen Shot 2025-05-07 at 11 26 51 PM" src="https://github.com/russellcayless/honeypot/blob/e4c9f21c84d0a68b380b4486996388e9a856a7d0/ioc_summary_table.png" />

---

## **5. Timeline (all times as recorded in source logs)**

<img width="1767" alt="Screen Shot 2025-05-07 at 11 26 51 PM" src="https://github.com/russellcayless/honeypot/blob/92a59ea2de03bd67bba4599e4ddd79f9be14b317/incident_timeline.png" />

---

## **6. Root Cause / Attack Vector**

 - **Confirmed:** MySQL was reachable with a root account that had % (any-host) grant, and that account was successfully authenticated from at least 6 external IPs with no evidence of MFA or IP allow-listing. This matches a known opportunistic "MySQL ransom bot" pattern (mass internet scan → default/weak/no-password root → drop DBs → extortion note), not a targeted intrusion.
 - **Unresolved:** Whether the **root@%** account was newly created by the attacker at 13:21:07, or was a pre-existing/legitimate account whose credential leaked, **cannot be determined from the supplied Auth Logs** — that connection has no matching auth-log entry (source IP, session owner unknown).
 - Unresolved: Whether the Windows **administrator** brute force **(64.76.8.21)** and/or the successful logon from **59.15.116.99** are related to the MySQL compromise (e.g., used to reconfigure MySQL's bind address/firewall) or a coincidental, separate opportunistic attack. No process/registry evidence ties a Windows session to the MySQL config change. **Not determined from available logs — DeviceRegistryEvents and DeviceNetworkEvents** were not provided.
 - Host-level indicators (process execution, file writes) show no malware, encryptor, or persistence mechanism — consistent with an attack that never required host code execution (MySQL exposed directly to the internet).

---

## **7. Response Actions**

**Taken (evidenced in logs):** None — no containment action (firewall change, account disable, service restart by a defender) appears in the provided data; the ransom note was re-created 5 times over 15 hours, indicating the port/account remained exposed throughout.

**Recommended / immediate:**

 - 1. Remove internet exposure of MySQL port 3306 (firewall/NSG rule to LAN/VPN only); confirm **bind-address** is not **0.0.0.0.** 
 - 2. Rotate/disable the **root@%** account; audit all MySQL accounts for %-host grants and **WITH GRANT OPTION.**
 - 3. Disable/reset the Windows **administrator** account or enforce account lockout + MFA; investigate the **59.15.116.99** successful logon as a priority.
 - 4. Restore **lnp_corp, sakila, world** from last-known-good backup; verify backup integrity (binlogs were purged by the attacker, so point-in-time recovery past 22 Aug 14:32 is likely unavailable).
 - 5. Treat data in the dropped databases (esp. **credentials, customers, payments**) as potentially exposed; assess breach-notification obligations.

---

## **8. Evidence**

 - **mysqlaudit_-_Auth_Logs.csv** — MySQL connection/auth events with source IP (76 rows)
 - **mysqlaudit_-_Queries.csv** — MySQL query audit log (191 rows) — ransom note text, DROP/GRANT statements
 - **DeviceLogonEvents.csv** — Windows interactive/network logon events (42 rows)
 - **DeviceProcessEvents.csv** — Windows process execution (57 rows) — reviewed, no malicious activity found
 - **DeviceFileEvents.csv** — Windows file create/delete events (1,048 rows) — reviewed, no ransom/malware artifacts found
 - **Not provided / requested for follow-up: DeviceNetworkEvents, DeviceRegistryEvents, NTANetAnalytics**, MySQL server config/my.cnf, cloud firewall/NSG rules, backup job logs
   
[Analyst: paste supporting screenshots/query result exports below each KQL block in Section 9 evidence log as they are collected.]

---

## **9. Suggested Hunt Queries by Section**

**Section 3 — Data read before drop**
```
kql
MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName contains "S-121292839"
| where TimeGenerated between (
    datetime(2026-08-22T14:00:00Z) .. 
    datetime(2026-08-23T09:00:00Z))
| where RawData has_any ("SELECT", "DROP DATABASE", 
    "RECOVER_YOUR_DATA", "SHUTDOWN", 
    "PURGE BINARY LOGS", "RESET MASTER")
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+\S+", 1, RawData)
| extend Action = case(
    RawData has "DROP DATABASE", "Database Dropped",
    RawData has "SELECT", "Data Read",
    RawData has "RECOVER_YOUR_DATA", "Ransom Note",
    RawData has "SHUTDOWN", "Service Shutdown",
    RawData has "PURGE BINARY LOGS", "Evidence Destroyed",
    RawData has "RESET MASTER", "Evidence Destroyed",
    "Other")
| project TimeGenerated, DeviceName, Action, RawData
| order by TimeGenerated asc
```
<img width="1767" alt="Screen Shot 2025-05-07 at 11 26 51 PM" src="https://github.com/russellcayless/honeypot/blob/b18451f648e6ae4665b1283a8e1af2a0e06faeb3/Q1.png" />

**Section 4 — Ransom note content extraction**
```
kql
MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where RawData has_any ("bc1q", "onionmail", "spoo.me", 
    "RECOVER_YOUR_DATA", "BTC")
| project TimeGenerated, DeviceName, RawData
| order by TimeGenerated asc
```
<img width="1767" alt="Screen Shot 2025-05-07 at 11 26 51 PM" src="https://github.com/russellcayless/honeypot/blob/0ee1f38fded6cb8eff098c56eea14473379ef4ab/Q2.png" />

**Section 4 — IOC pivot across confirmed sources**
```
let attackerIPs = dynamic([
    "64.89.163.166","64.89.163.90",
    "64.89.163.154","64.89.163.141",
    "34.156.133.0","104.199.72.69",
    "64.76.8.21","59.15.116.99"
]);
DeviceLogonEvents
| where RemoteIP in (attackerIPs)
| where DeviceName contains "S-121292839"
| project TimeGenerated, DeviceName, AccountName, 
  ActionType, RemoteIP, LogonType
| order by TimeGenerated asc
```
<img width="1767" alt="Screen Shot 2025-05-07 at 11 26 51 PM" src="https://github.com/russellcayless/honeypot/blob/0ee1f38fded6cb8eff098c56eea14473379ef4ab/Q3.png" />

**Section 5 — Timeline reconstruction of first intrusion**
```
kql
MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName contains "S-121292839"
| where TimeGenerated between (
    datetime(2026-08-22T14:30:00Z) .. 
    datetime(2026-08-22T15:00:00Z))
| extend Action = case(
    RawData has "DROP DATABASE", "Database Dropped",
    RawData has "SELECT", "Data Read",
    RawData has "RECOVER_YOUR_DATA", "Ransom Note Created",
    RawData has "GRANT", "Privileges Modified",
    RawData has "SHUTDOWN", "MySQL Shutdown",
    RawData has "Connect", "Connection",
    "Other")
| project TimeGenerated, Action, RawData
| order by TimeGenerated asc
```
<img width="1767" alt="Screen Shot 2025-05-07 at 11 26 51 PM" src="https://github.com/russellcayless/honeypot/blob/d7a547382be5b5fd4d9d2dab3e8ca76a20eca609/Q4.png" />

**Section 5 — Timeline of attacker logon window**
```
kql
DeviceLogonEvents
| where DeviceName == "s-121292839"
| where TimeGenerated between (
    datetime(2026-08-22T14:00:00Z) .. 
    datetime(2026-08-23T09:00:00Z))
| project TimeGenerated, AccountName, 
  ActionType, RemoteIP, LogonType
| order by TimeGenerated asc
```
<img width="1767" alt="Screen Shot 2025-05-07 at 11 26 51 PM" src="https://github.com/russellcayless/honeypot/blob/d7a547382be5b5fd4d9d2dab3e8ca76a20eca609/Q5.png" />

**Section 6 — Who created root@% and when**
```
kql
MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName contains "S-121292839"
| where RawData has_any ("CREATE USER", "GRANT ALL PRIVILEGES", 
    "WITH GRANT OPTION", "IDENTIFIED BY")
| project TimeGenerated, DeviceName, RawData
| order by TimeGenerated asc
```
<img width="1767" alt="Screen Shot 2025-05-07 at 11 26 51 PM" src="https://github.com/russellcayless/honeypot/blob/8edd93c05df6504487d778169fdf22c0ef1ad887/Q6.png" />

**Section 6 — Windows brute force analysis**
```
kql
DeviceLogonEvents
| where DeviceName == "s-121292839"
| where AccountName == "administrator"
| summarize 
    FailCount = countif(ActionType == "LogonFailed"),
    SuccessCount = countif(ActionType == "LogonSuccess")
    by RemoteIP, bin(TimeGenerated, 1h)
| order by TimeGenerated asc
```
<img width="1767" alt="Screen Shot 2025-05-07 at 11 26 51 PM" src="https://github.com/russellcayless/honeypot/blob/d7a547382be5b5fd4d9d2dab3e8ca76a20eca609/Q7.png" />

**Section 6 — Unexplained successful admin logon**
```
kql
DeviceLogonEvents
| where DeviceName == "s-121292839"
| where AccountName == "administrator"
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, 
  RemoteIP, LogonType, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="1767" alt="Screen Shot 2025-05-07 at 11 26 51 PM" src="https://github.com/russellcayless/honeypot/blob/d7a547382be5b5fd4d9d2dab3e8ca76a20eca609/Q8.png" />
---

**Section 7 — Post incident verification**
```
kql
DeviceLogonEvents
| where DeviceName == "s-121292839"
| where TimeGenerated > datetime(2026-08-23T09:00:00Z)
| where AccountName == "administrator"
| project TimeGenerated, AccountName, 
  ActionType, RemoteIP
| order by TimeGenerated asc
```
<img width="1767" alt="Screen Shot 2025-05-07 at 11 26 51 PM" src="https://github.com/russellcayless/honeypot/blob/d7a547382be5b5fd4d9d2dab3e8ca76a20eca609/Q9.png" />

**Section 8 — Full evidence pull from all Defender tables**
```
kql
let timeStart = datetime(2026-08-22T13:00:00Z);
let timeEnd = datetime(2026-08-23T09:00:00Z);
let device = "s-121292839";
DeviceLogonEvents
| where DeviceName == device
| where TimeGenerated between (timeStart .. timeEnd)
| extend TableName = "LogonEvents"
| union (
    DeviceProcessEvents
    | where DeviceName == device
    | where TimeGenerated between (timeStart .. timeEnd)
    | extend TableName = "ProcessEvents"
)
| union (
    DeviceFileEvents
    | where DeviceName == device
    | where TimeGenerated between (timeStart .. timeEnd)
    | extend TableName = "FileEvents"
)
| project TimeGenerated, TableName, 
  DeviceName, ActionType, FileName,
  AccountName, RemoteIP
| order by TimeGenerated asc
```
<img width="1767" alt="Screen Shot 2025-05-07 at 11 26 51 PM" src="https://github.com/russellcayless/honeypot/blob/d7a547382be5b5fd4d9d2dab3e8ca76a20eca609/Q10.png" />
---

## **10. Lessons Learned / Recommendations (prioritized)**

 - 1. **[Critical]** Never expose MySQL (3306) directly to the internet; require VPN/bastion or cloud-provider private networking. This single control would have prevented the incident.
 - 2. **[Critical]** Eliminate **'root'@'%'** and any wildcard-host grants; enforce least-privilege, host-scoped MySQL accounts, and disable remote root login entirely.
 - 3. **[High]** Enable account lockout / rate-limiting on Windows RDP-exposed accounts; the **administrator** account absorbed 40 failed logons with no apparent lockout, and a same-day successful logon from an unexplained IP was never investigated in real time.
 - 4. **[High]** Onboard **DeviceNetworkEvents, DeviceRegistryEvents,** and **NTANetAnalytics** into the hunting workflow — their absence left the initial-access vector, config-change actor, and any data egress unconfirmed in this investigation.
 - 5. **[Medium]** Alert on **DROP DATABASE, SHUTDOWN, RESET MASTER, and PURGE BINARY LOGS** issued by application/service DB accounts — these are rarely legitimate and were the clearest high-fidelity signal in this incident.
 - 6. **[Medium]** Verify and test backups for **lnp_corp/sakila/world** immediately; binlog purge means recovery is backup-dependent only.


