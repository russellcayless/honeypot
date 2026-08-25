# DFIR Host Assessment — S-121292839 (MDE Live Response Package)

**1. Baseline Determination**  


Only one MDE investigation package was supplied 
(MDE_Investigation_Package__2_.zip). There is no second archive to diff against — the "(2)" in the filename is not a package-order marker; the zip contains a single, internally-consistent live-response collection.

- Collection timestamps (Forensics Collection Summary.csv, Autoruns.txt, Prefetch mtimes): 2026-08-23T08:59:51Z – 09:12Z.
- This is therefore treated as a single post-window snapshot, not a pre/post pair.
  True category-by-category ADDED/REMOVED/CHANGED diffing (Step 2) could not be performed as specified. Instead, findings below are based on (a) what's present in this single snapshot assessed against known-good Windows/lab-host baselines, and (b) the internal time series available inside the package itself — the Security event log spans 2026-08-23T02:29:35Z – 08:59:56Z, which does provide a real before/after window for logon activity, account state, and process history within that ~6.5 hr span.
- Gap: No earlier collection exists to confirm whether autoruns/services/scheduled tasks changed relative to install time (2026-08-21 19:55) or relative to the prior MySQL incident (2026-08-22, per separately reviewed data). Flagged throughout as "single-snapshot, no baseline available."
---

**2. Summary Verdict** 

**Compromise indicators found: INCONCLUSIVE (host under active, sustained external attack; no confirmed successful intrusion artifact in this package, but one unresolved live connection needs immediate hands-on triage).**

**Confidence: Medium.**

One-line justification: the host is being actively, continuously brute-forced against RDP/SMB by at least 8 external IPs (7,145 failed logons in 6.5 hours) and still exposes MySQL (3306/33060) and RDP (3389) directly to 0.0.0.0 — but no successful external logon (4624) was recorded anywhere in the covered window, and no new persistence (accounts, autoruns, services, scheduled tasks) was found; the one open question is two **live ESTABLISHED TCP sessions on port 3389 at the moment of collection**, one from a confirmed brute-force IP, with no matching success/failure event to explain them.

---
**5. Probable Incident Type** 

**Undetermined for this package in isolation** — no successful intrusion is confirmed in the covered window. In the context of the broader host history (this is the same host that suffered a MySQL "RECOVER_YOUR_DATA" extortion/ransom event via an internet-exposed root@% account on 2026-08-22), this package shows the **same class of exposure (internet-facing admin services with weak/brute-forceable auth) continuing to be actively targeted**, now against RDP/SMB rather than MySQL specifically. If the P1 live-connection question resolves to a successful, unauthorized RDP logon, this would represent a second, related intrusion attempt exploiting the same root cause (unrestricted external exposure of administrative services on S-121292839).

---

**6. Gaps**

- No true baseline package — Step 1/2 diff methodology as specified could not be executed; all "ADDED/REMOVED/CHANGED" calls above are inferred from single-snapshot review + the log's internal time range, not a package-to-package comparison.
- Security event log only covers 02:29–08:59 UTC on 23 Aug despite being queried for 16 Aug onward — no visibility into 16–22 Aug or the first ~2 hours of 23 Aug from this artifact.
- No TermServices-RemoteConnectionManager / TerminalServices-LocalSessionManager operational logs, RDP session (event 21/22/25) data, or netstat history were collected — this is exactly what's needed to resolve the two live 3389 connections (P1) and was not in scope of this package.
pfirewall.log was never enabled, so there's no historical record of allowed/blocked connections to corroborate the brute force at the network layer.
- No DeviceNetworkEvents/NTA data (as in the prior incident) — can't confirm whether 208.118.125.58 or 217.160.151.42 sent any payload after the TCP handshake.
Security.txt (the intended human-readable export) was empty; all analysis here required direct EVTX parsing — confirm the collection tooling is exporting .txt correctly for future packages.

**Recommended immediate action:** independently verify current RDP session state on the host (e.g., qwinsta/query session, or re-pull TerminalServices-LocalSessionManager operational log) to resolve whether 217.160.151.42 / 208.118.125.58 hold an authenticated session — this is more urgent than the rest of this report.

---





