# Alpme Extension Forensic Auditor (Universal Edition)

**Author:** PenguinBTW ([@PenguinBTW](https://github.com/PenguinBTW))  
**Discord:** `@penguinbtw`  
**Copyright:** © 2026 PenguinBTW. All Rights Reserved.  
**Classification:** Incident Response / Malware Detection Utility  
**Threat Focus:** Trojanized VS Code Extension `alpme-1.0.25` (Pay-Per-Install Dropper / Infostealer)

---

## 🌐 Universal IDE Compatibility

This tool is engineered with dynamic auto-discovery to detect, audit, and clean installations across **all** major Visual Studio Code forks, wrappers, and distributions:

* **Google Antigravity IDE**
* **Cursor**
* **Windsurf**
* **Visual Studio Code** (Standard & Insiders)
* **VSCodium**
* Any custom or corporate IDE fork utilizing VS Code's internal storage engine

---

## 🔍 Overview

This repository contains a standalone, zero-dependency forensic detection and audit utility engineered to identify, extract, and report malware dropped by the trojanized **"Alpme" (v1.0.25)** extension.

Promoted across YouTube and Discord as a "cracked" AI coding assistant, the extension bundled an obfuscated Pay-Per-Install (PPI) dropper that secretly fetches and executes secondary Windows binaries (such as `Infostealer/Win.Lzveil` and `Trojan:Win32/Wacatac`) in the background.

---

## ⚡ What This Tool Does

1. **Auto-Discovers & Audits All IDE Databases (`state.vscdb`)**:
   * Dynamically locates and inspects all SQLite storage across all installed VS Code forks in `%APPDATA%`.
   * Uses native in-memory .NET byte streaming (`FileShare.ReadWrite`) to read locked databases without needing external SQLite drivers or closing your IDE.
   * Extracts **all historical payload paths** and **cryptographic SHA-256 hashes** cached under `alpme.partnerSoftware.*`.
   * Generates clickable VirusTotal threat intelligence lookup links for every hash.

2. **Universal Memory Hunter**:
   * Scans active Windows processes for masquerading names (`svchost-*.exe`, `wuauclt-*.exe`, `winhlp-*.exe`, `pkg-*.exe`).
   * Detects internal staged executables (`24si.exe`, `25si.exe`, `28si.exe`, `29si.exe`).
   * Flags suspicious processes executing out of `%TEMP%` with defensive `try/catch` path normalization (immune to 8.3 short paths like `ADMINI~1`).

3. **Surgical `%TEMP%` Subfolder Sweeper**:
   * Recursively scans `%TEMP%` subdirectories up to Depth 3 (`pkg-*`, `winhlp-*`).
   * Eliminates false positives by strictly requiring `.exe` extension and matching the dropper's mathematical naming signatures.

---

## 🚀 How to Run

### Option 1: 1-Click Batch Execution (Recommended)
1. Download or clone this repository.
2. Double-click **`alpme_detector_universal.bat`**.
   * It automatically bypasses PowerShell execution restrictions and pauses so you can copy any detected hashes.

### Option 2: Run via PowerShell
Open PowerShell as Administrator in this folder and run:
```powershell
.\alpme_detector_universal.bat
```

---

## 🛑 What to Do If Malware Is Found

If the utility reports `[!] INFECTION EVIDENCE FOUND`:

> [!IMPORTANT]
> **Need help or have questions?** Message **`@penguinbtw` on Discord** for more info or assistance if you get a positive scan on your machine!

1. **Quarantine the Binary**: Note the file path shown (e.g., `%TEMP%\pkg-*\25si.exe`) and delete the folder.
2. **Purge Extension Cache**: Delete your extension directory (e.g. `%USERPROFILE%\.vscode\extensions\*alpme*` or `%USERPROFILE%\.antigravity\extensions\*alpme*`).
3. **Invalidate Web Sessions Immediately**:
   * Go to your Google, GitHub, and Discord account security settings and click **"Sign out of all other sessions / devices"** to revoke any stolen session cookies.
4. **Rotate Credentials**:
   * Change passwords for accounts saved in your browser.
   * Rotate any OpenAI, Anthropic, AWS, or GitHub tokens stored on your machine.
5. **Nuke and Pave (Recommended)**: Back up your personal files (documents/media only, no executables) and perform a clean reinstallation of Windows.

---

## 📜 License & Attribution

Author: **PenguinBTW**  
Discord: **`@penguinbtw`**  
Copyright © 2026 PenguinBTW. All Rights Reserved.

This tool is distributed for defensive cybersecurity, threat hunting, and educational incident response purposes. Non-commercial redistribution with author attribution is permitted.
