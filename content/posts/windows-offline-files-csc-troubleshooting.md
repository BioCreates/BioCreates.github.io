+++
title = "When NTFS Permissions Weren't the Problem: Troubleshooting a Windows Offline Files Trap"
slug = "windows-offline-files-csc-troubleshooting"
date = "2026-07-23"
author = "RoninSec"
cover = "/img/windows-offline-files-csc-troubleshooting-banner.png"
tags = ["windows", "troubleshooting", "ntfs", "offline-files", "sysadmin"]
keywords = ["windows offline files", "client side caching", "ntfs permissions", "csc cache", "windows file access", "file unavailable", "windows troubleshooting"]
description = "A Windows file access issue looked like broken NTFS permissions but the real culprit was Offline Files and Client-Side Caching."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# When NTFS Permissions Weren't the Problem: Troubleshooting a Windows Offline Files Trap

Some troubleshooting sessions remind me why it is so important to slow down and trust the evidence instead of the first theory.

This case started as what looked like a straightforward NTFS permissions problem. A user could browse to a shared project directory but could not open the files inside it. Windows even warned that the permissions were "incorrectly ordered," which seemed like a reasonable explanation.

It turned out to be a complete red herring.

The actual issue had nothing to do with NTFS permissions. The filesystem was doing exactly what it was supposed to do. The real problem lived one layer above it.

---

## The Symptom

The user reported they could browse to a shared project directory on a Windows workstation but could not open any files.

Instead of receiving the familiar "Access is denied" message, Windows displayed:

> "This file is currently not available for use on this computer."

While reviewing the folder's security settings, I also noticed a warning stating that the permissions were incorrectly ordered and suggesting they be reordered.

At first glance, everything pointed toward an ACL problem.

The permissions themselves looked perfectly reasonable:

* The user had Full Control.
* Administrators had Full Control.
* SYSTEM had Full Control.
* Ownership appeared correct.
* There were no obvious conflicting Deny entries.

Despite that, the files remained inaccessible.

---

## The Investigation

Rather than assuming the ACL warning explained everything, I walked through the problem methodically.

### 1. Verify NTFS permissions

The first step was confirming that the permissions actually matched what Windows claimed.

Everything checked out.

No missing permissions.

No ownership issues.

No inheritance problems that immediately stood out.

### 2. Reorder the Access Control Entries

Windows offered to reorder the ACL into canonical order.

Canonical ordering generally follows this sequence:

1. Explicit Deny
2. Explicit Allow
3. Inherited Deny
4. Inherited Allow

I allowed Windows to reorder the entries.

The warning disappeared.

The problem did not.

That was my first indication that I was troubleshooting the wrong subsystem.

### 3. Focus on the wording of the error

Instead of continuing to adjust permissions, I stopped and looked carefully at the error itself.

If NTFS permissions were preventing access, I would normally expect messages such as:

* "Access is denied."
* "You do not have permission to access this folder."

Instead, Windows was saying the file was **not available**.

That subtle difference mattered.

It suggested Windows knew the file existed but could not retrieve its contents.

### 4. Check Offline Files

My next step was to verify whether Offline Files was enabled.

I opened the Offline Files control panel using:

```cmd
control.exe /name Microsoft.OfflineFiles
```

Offline Files was enabled.

That immediately became my leading suspect.

---

## What the Evidence Showed

Windows Offline Files uses a subsystem called Client-Side Caching, commonly referred to as CSC.

Its purpose is simple:

* Cache shared files locally.
* Allow users to continue working while disconnected.
* Synchronize changes when connectivity returns.

The important detail is where CSC sits in the Windows I/O path.

Many people think file access looks like this:

Application -> NTFS -> Disk

When Offline Files is enabled, it is more accurate to think of it like this:

Application -> CSC -> NTFS -> Disk

CSC gets the first opportunity to service the request.

If the cache is healthy, everything works transparently.

If the cache becomes stale or corrupted, Windows may never reach NTFS at all.

That explained every symptom I was seeing:

* The permissions were correct.
* Effective access appeared correct.
* Explorer could enumerate the directory.
* Files could not be opened.
* The error was not "Access is denied."

The permissions were not lying.

They simply were not involved in the failure.

---

## The Root Cause

The workstation had Offline Files enabled, and the affected directory was being intercepted by the Client-Side Caching subsystem.

While I cannot definitively prove exactly why the cache became invalid, the evidence strongly pointed to a stale or corrupted CSC cache.

To test the theory, I:

1. Disabled Offline Files.
2. Rebooted the workstation.

Immediately after the reboot, the files opened normally.

No ACL changes were necessary.

No ownership changes were required.

No permissions had ever been preventing access.

The problem disappeared as soon as CSC was removed from the file access path.

---

## Key Takeaways

* Read Windows error messages carefully. Small wording differences often point to completely different subsystems.
* An ACL warning does not necessarily explain an access problem.
* Reordering Access Control Entries is generally safe, but it does not change who has access.
* Offline Files and Client-Side Caching can intercept file access before NTFS evaluates permissions.
* If permissions appear correct but files remain unavailable, investigate caching, synchronization, encryption, and filter drivers before rewriting ACLs.
* The best troubleshooting often comes from eliminating assumptions instead of immediately applying fixes.

---

## Summary

**Symptom**

A user could browse a shared project directory but received "This file is currently not available for use on this computer" when attempting to open files.

**Investigation**

Verified NTFS permissions, corrected ACL ordering, paid close attention to the wording of the error message, and checked whether Windows Offline Files was enabled.

```cmd
control.exe /name Microsoft.OfflineFiles
```

**Root Cause**

Windows Offline Files, through the Client-Side Caching subsystem, intercepted file access using a stale or corrupted cache before NTFS permissions were evaluated.

**Resolution**

Disabled Offline Files, rebooted the workstation, and confirmed that file access was immediately restored without modifying permissions or ownership.

Have you ever chased an NTFS permissions problem only to discover the real culprit was a completely different Windows subsystem?
