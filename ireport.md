**Incident Report — MySQL Extortion / Ransom on s-121292839**
Report status: Draft — built from 5 exported log sources only. Sections marked Not determined from available logs need follow-up (SIEM/host EDR portal, cloud provider abuse contacts, backups team).

**1. Executive Summary**
An internet-reachable MySQL instance on host s-121292839 was accessed with full root/% privileges by multiple external IPs starting 22 Aug 2026 14:31 UTC. The attacker(s) enumerated and read three databases (lnp_corp, sakila, world) — including a credentials table — then dropped all three databases and left a ransom note in a newly created RECOVER_YOUR_DATA database demanding 0.011 BTC. The attack recurred at least five more times through 23 Aug 05:00 UTC, each time re-creating the ransom note, indicating the exposure was never closed during that window. Separately, the same host absorbed a 40-attempt Windows administrator brute force from a different IP on 22 Aug; no logs confirm that brute force succeeded. No host-level malware execution or file-encryption activity was found in the Windows telemetry provided — the confirmed impact is database-layer (drop + extortion note), not a host-based ransomware/encryptor.

---

**2. Incident Details**
Field
Value
Detection date/time
Not determined from available logs — no alert/detection record was supplied; log export ends 23 Aug 2026 09:00:47
Reporter
Not determined from available logs
Classification
Unauthorized database access / data destruction / extortion (MySQL "RECOVER_YOUR_DATA" ransom pattern). Not a confirmed file-encrypting ransomware event on the host.
Severity
High — confirmed data destruction (3 DBs dropped) and credential/customer data exposure risk; DB was internet-facing with root@% and grant option
Affected system(s)
s-121292839 (Windows host running MySQL)
Affected data
MySQL databases: lnp_corp (incl. credentials, customers, payments, orders tables), sakila, world

---

**3. Impact Assessment**
Confidentiality: Attacker ran SELECT * against credentials, customers, payments, orders, staff, and other tables before dropping the databases — treat as a confirmed data-read/exfiltration-risk event, not just destruction. No DeviceNetworkEvents/NTANetAnalytics were provided, so actual data egress to an external destination is not determined from available logs.
Integrity/Availability: lnp_corp, sakila, and world databases were dropped (DROP DATABASE). A SHUTDOWN and RESET MASTER / PURGE BINARY LOGS were also issued, which destroys binlog-based recovery/forensic data for the instance.
Scope: Single host/single MySQL instance confirmed. No evidence of lateral movement to other hosts in the provided data (only one DeviceName appears across all sources).
Business impact: Loss of the lnp_corp production-looking database (customer/payment/credential tables) is the primary business risk pending confirmation of backup availability. Not determined from available logs.

---

**4. Indicators of Compromise**
⚠ Discrepancy note: The BTC address, email, URL, and DATAID provided as "known IOCs" for this case do not appear anywhere in the supplied logs. The logs contain a different but same-template ransom note. Both sets are listed below — treat the "Provided (unconfirmed in logs)" row as needing separate validation, and use the "Confirmed in logs" rows for this specific incident.

