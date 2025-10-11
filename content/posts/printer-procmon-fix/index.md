+++
title = "Using ProcMon to Troubleshoot Printing Freezes in Word"
slug = "procmon-printing-freeze"
date = "2025-10-11T12:00:00-04:00"
author = "RoninSec"
cover = "/img/procmon-printing-freeze-banner.png"
tags = ["procmon", "troubleshooting", "windows-printing", "office", "sysinternals"]
keywords = ["ProcMon", "Word not responding", "printing freeze", "spooler", "unknown SID", "ACL", "USB printer"]
description = "Diagnosing a strange Microsoft Word printing freeze using Process Monitor (ProcMon) — from initial symptoms to discovering an orphaned SID in printer permissions."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Using ProcMon to Troubleshoot Printing Freezes in Word

Recently, I worked a case where a user’s brand-new PC would **freeze in Word every time they tried to print**. The app would hang with “Not Responding” for several minutes before the job finally pushed through.

At first glance, this looked like a driver or spooler problem — but the actual root cause was something much stranger. Here’s how I approached it, and how Procmon helped me narrow things down.

---

## Reproducing the Problem

- User: Jake, workstation **WS01**
- Symptom: Word freezes with _Not Responding_ when printing to an HP OfficeJet (USB-connected).
- Restarting the PC, repairing Office, and resetting the spooler service made no difference.
- Even re-installing the printer via HP Smart with the correct driver didn’t help.

At this point, it was time to dig deeper with **Process Monitor (Procmon)**.

---

## Using Procmon to Capture the Freeze

### Step 1 – Setup

- Downloaded **Procmon** from Sysinternals.
- Started capture, cleared buffer, enabled _Drop Filtered Events_ and _Advanced Output_.
- Added filters for:
    - `WINWORD.EXE`
    - `spoolsv.exe` (Print Spooler)
    - `splwow64.exe` (32-bit/64-bit broker)
    - `PrintIsolationHost.exe`
    - `Path contains \spool\PRINTERS` (spool files)

### Step 2 – Reproduce

- Hit Print in Word, waited for the freeze.
- Stopped capture as soon as the print went through.

### Step 3 – Analyze

- Sorted by **Duration** to look for slow events.
- Found lots of activity on `C:\Windows\System32\spool\PRINTERS\00003.SPL` and `00003.SHD`.
- Word was writing spool data, Spooler was creating and cleaning up the job files.
- Importantly: **no abnormal access denials, no unusually long delays, no AV filters locking the files**.

---

## What the Logs Showed

Procmon confirmed that:

- Word was correctly creating and writing `.SPL` spool files.    
- Spooler was processing those files normally.
- No evidence of corruption, driver DLL misbehavior, or antivirus blocking the spool folder.

So while the logs didn’t reveal the smoking gun, they **helped rule out** several likely suspects.

---

## The Real Culprit: An Unknown SID

With drivers, spooler, and AV cleared, I dug into the **printer’s security properties**.

There, I found an **Unknown SID** listed in the ACL — likely a leftover from a profile copied from an old machine.

Every time Word tried to print, Windows would attempt to resolve that orphaned SID to check permissions. Since the account no longer existed, the lookup would stall, causing Word to hang until the check timed out.

Removing the invalid SID from the printer’s Security tab fixed the issue immediately. Printing returned to normal with no freezes.

---

## Key Takeaways

- **Procmon doesn’t always give you the direct answer** — but it’s invaluable for ruling things out. In this case, it showed spooler I/O behaving normally, which pushed me to check permissions.
- **Unknown SIDs in printer ACLs can cause hangs.** Windows will pause while it tries to resolve them, even on a simple USB printer.
- Always consider ACLs/security properties when troubleshooting print freezes — not just drivers, spooler, or AV.

---

## Summary

**Symptom:** Word froze when printing, showing _Not Responding_.  
**Investigation:** Procmon trace showed normal spool file behavior, no clear failures.  
**Root Cause:** Printer ACL contained an invalid/unknown SID, stalling permission checks.  
**Resolution:** Removed the unknown SID → printing worked instantly.

---

👉 Have you ever had a troubleshooting case where Procmon didn’t show the answer directly, but helped steer you to the real fix? This was a perfect example for me — sometimes the “negative result” (what’s _not_ broken) is just as valuable.
