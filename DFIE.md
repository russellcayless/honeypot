# DFIR Host Assessment — S-121292839 (MDE Live Response Package)

**1. Baseline Determination**  


Only one MDE investigation package was supplied (MDE_Investigation_Package__2_.zip). There is no second archive to diff against — the "(2)" in the filename is not a package-order marker; the zip contains a single, internally-consistent live-response collection.
Collection timestamps (Forensics Collection Summary.csv, Autoruns.txt, Prefetch mtimes): 2026-08-23T08:59:51Z – 09:12Z.
This is therefore treated as a single post-window snapshot, not a pre/post pair. True category-by-category ADDED/REMOVED/CHANGED diffing (Step 2) could not be performed as specified. Instead, findings below are based on (a) what's present in this single snapshot assessed against known-good Windows/lab-host baselines, and (b) the internal time series available inside the package itself — the Security event log spans 2026-08-23T02:29:35Z – 08:59:56Z, which does provide a real before/after window for logon activity, account state, and process history within that ~6.5 hr span.
Gap: No earlier collection exists to confirm whether autoruns/services/scheduled tasks changed relative to install time (2026-08-21 19:55) or relative to the prior MySQL incident (2026-08-22, per separately reviewed data). Flagged throughout as "single-snapshot, no baseline available."
---

## ✅ Lab Objective  
By branding your organization’s Microsoft 365 sign-in experience, users can visually confirm they are on the real company login portal:

- Custom background image (e.g., company logo or office skyline)
- Sign-in page text (e.g., “Welcome to Carter Accountants Secure Login”)
- Organization logo in the sign-in box





Only one MDE investigation package was supplied (MDE_Investigation_Package__2_.zip). There is no second archive to diff against — the "(2)" in the filename is not a package-order marker; the zip contains a single, internally-consistent live-response collection.
Collection timestamps (Forensics Collection Summary.csv, Autoruns.txt, Prefetch mtimes): 2026-08-23T08:59:51Z – 09:12Z.
This is therefore treated as a single post-window snapshot, not a pre/post pair. True category-by-category ADDED/REMOVED/CHANGED diffing (Step 2) could not be performed as specified. Instead, findings below are based on (a) what's present in this single snapshot assessed against known-good Windows/lab-host baselines, and (b) the internal time series available inside the package itself — the Security event log spans 2026-08-23T02:29:35Z – 08:59:56Z, which does provide a real before/after window for logon activity, account state, and process history within that ~6.5 hr span.
Gap: No earlier collection exists to confirm whether autoruns/services/scheduled tasks changed relative to install time (2026-08-21 19:55) or relative to the prior MySQL incident (2026-08-22, per separately reviewed data). Flagged throughout as "single-snapshot, no baseline available."
