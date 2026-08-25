# Cyber Range Capstone

**Live-Exposed Honeypot Lab — End-to-End Checklist**  
Build hard → instrument → baseline → detect → weaken & expose. Windows VM + MySQL, telemetry to LAW-Cyber-Range.

This checklist walks the full defensive lifecycle for an internet-exposed asset. You build and harden the box, wire up logging, capture a clean baseline, write your detections while the environment is still quiet, and only then deliberately weaken and expose it so real attacker traffic supplies the breach. Work the phases in order — detections must exist before exposure so you catch your own incident.

---

**Phase 0 — Honeypot Architecture**

---

**Phase 1 — Build the VM Honeypot (locked down while we build it)**

-Deploy a Windows 11 VM in your own resource group (strong username and password) — ensure you configure a public IP address
--Name the VM something good, like “CORP-XXX-YYY” or something that looks legit, not “lab_test_1”
-Deny all inbound traffic from the internet
-Onboard the VM to Microsoft Defender for Endpoint (MDE), ensure it is showing up in the DeviceInfo table




## ✅ Lab Objective  
By branding your organization’s Microsoft 365 sign-in experience, users can visually confirm they are on the real company login portal:

- Custom background image (e.g., company logo or office skyline)
- Sign-in page text (e.g., “Welcome to Carter Accountants Secure Login”)
- Organization logo in the sign-in box

## Default login screen

<img width="1767" alt="Screen Shot 2025-05-07 at 11 26 51 PM" src="https://github.com/russellcayless/Entra/blob/cd5c32551922714de262c72fbfa6ef7e6cd16ef3/defaultloginscreen.png" />

---

Build hard → instrument → baseline → detect → weaken & expose. Windows VM + MySQL, telemetry to LAW-Cyber-Range.

