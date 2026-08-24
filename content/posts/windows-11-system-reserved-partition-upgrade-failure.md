+++
title = "Troubleshooting a Windows 11 Upgrade Failure Caused by the System Reserved Partition"
slug = "windows-11-system-reserved-partition-upgrade-failure"
date = "2026-08-24"
author = "RoninSec"
cover = "/img/windows-11-system-reserved-partition-upgrade-failure-banner.png"
tags = ["windows-11", "troubleshooting", "windows-update", "boot-repair", "partition-management"]
keywords = ["windows 11 upgrade", "system reserved partition", "bootrec", "automatic repair", "windows troubleshooting", "schannel error", "sfc dism chkdsk"]
description = "A practical walkthrough of diagnosing an Automatic Repair loop and Windows 11 upgrade failure caused by an undersized System Reserved Partition."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Troubleshooting a Windows 11 Upgrade Failure Caused by the System Reserved Partition

Sometimes Windows gives you an error that sounds far more intimidating than it really is. Other times, it gives you an error that sounds simple but hides the actual root cause.

This case started with a workstation trapped in an Automatic Repair loop. After the usual integrity checks came back clean, the investigation took an unexpected turn into boot partitions and Windows setup requirements. Here is how I worked through it.

---

## The Symptom

The workstation exhibited several symptoms:

* Intermittent Automatic Repair loop during boot.
* Repeated restarts required before reaching the desktop.
* Windows 11 upgrade consistently failed.
* Event Viewer contained multiple Schannel errors.

One of the Schannel errors looked similar to:

```text
Event ID: 36871
Source: Schannel

A fatal error occurred while creating a TLS client credential.
The internal error state is 10013.
```

The process involved was an Adobe background synchronization service.

At first glance, this looked suspicious. However, it ultimately turned out to be unrelated to the boot and upgrade issues.

---

## The Investigation

Rather than immediately assuming disk corruption, I followed the standard repair workflow.

### 1. Verify Windows Component Integrity

The first step was repairing the Windows image and checking protected system files.

```cmd
DISM /Online /Cleanup-Image /RestoreHealth
```

Then:

```cmd
sfc /scannow
```

Finally:

```cmd
chkdsk /scan
```

or, when appropriate,

```cmd
chkdsk /f
```

Reviewing the CBS log showed no unrepaired corruption. System files were healthy, which allowed me to move corruption lower on the list of likely causes.

---

### 2. Investigate Boot Configuration

My next instinct was to repair the boot loader.

I attempted:

```cmd
bootrec /fixmbr
bootrec /fixboot
bootrec /scanos
bootrec /rebuildbcd
```

Instead, Windows responded with:

```text
'bootrec' is not recognized as an internal or external command.
```

### Gotcha #1

This was not because Windows 11 removed Bootrec.

The command was executed from a normal administrative Command Prompt inside Windows.

`bootrec.exe` is intended to run from the Windows Recovery Environment (WinRE), not from the live operating system.

If you need Bootrec, boot into:

* Troubleshoot
* Advanced Options
* Command Prompt

Only then will the tool be available.

---

### 3. Look Beyond the Boot Loop

While preparing for additional recovery steps, I attempted the Windows 11 upgrade again.

Instead of a TPM or CPU compatibility error, setup reported:

```text
This PC doesn't currently meet Windows 11 system requirements.

We couldn't update the system reserved partition.
```

This changed the direction of the investigation entirely.

---

## What the Evidence Showed

At this point:

* DISM completed successfully.
* SFC found no unrepaired system files.
* CHKDSK did not reveal significant file system corruption.
* Schannel errors were tied to an application attempting TLS communication.
* The Windows 11 installer consistently failed because it could not modify the System Reserved Partition.

The common thread was no longer operating system corruption.

It was storage layout.

---

## The Root Cause

The workstation's System Reserved Partition (SRP) was too small or too full.

Older Windows installations commonly created System Reserved Partitions around 100 MB.

Modern Windows 11 upgrades frequently require additional free space in this partition to update:

* Boot files
* Recovery environment
* Boot Configuration Data (BCD)
* Language resources
* Security components

When Setup cannot write those files, it aborts the upgrade with the somewhat misleading message:

```text
We couldn't update the system reserved partition.
```

The operating system itself may still function normally, but the upgrade cannot continue.

---

## Why Disk Management Is Not Enough

A natural first thought is to open Disk Management and resize the partition.

Unfortunately, Windows Disk Management cannot extend or move the System Reserved Partition.

The options are typically unavailable because the partition is protected and because Disk Management cannot relocate adjacent partitions.

### Gotcha #2

This is one of those situations where the built-in Windows tools simply are not capable of performing the required operation.

A third-party partition manager is generally required.

Examples include:

* MiniTool Partition Wizard
* AOMEI Partition Assistant
* GParted Live

The general workflow is:

1. Shrink the Windows partition.
2. Move the Windows partition if necessary.
3. Create unallocated space adjacent to the System Reserved Partition.
4. Expand the System Reserved Partition.
5. Retry the Windows 11 upgrade.

As always, verify backups before modifying partitions.

If BitLocker is enabled, suspend or decrypt it before making partition changes.

---

## What About the Schannel Errors?

The Schannel Event ID 36871 messages initially looked concerning.

However, the evidence pointed toward an Adobe background synchronization process failing to establish a TLS session.

Those events:

* did not explain the Automatic Repair loop,
* did not explain the Windows 11 upgrade failure,
* and were likely unrelated application-level errors.

This serves as a good reminder that not every red error in Event Viewer is the root cause.

Sometimes they are simply background noise.

---

## Key Takeaways

* Always start with DISM, SFC, and CHKDSK before assuming major corruption.
* Review the CBS log rather than relying only on SFC's console output.
* Bootrec is a Windows Recovery Environment tool, not a normal Windows command.
* Schannel errors should be investigated, but verify whether they are actually related to the primary issue.
* Windows Disk Management cannot resize the System Reserved Partition.
* Older installations frequently have undersized System Reserved Partitions that block Windows 11 upgrades.
* The upgrade error is often solved by expanding the System Reserved Partition rather than reinstalling Windows.

---

## Summary

**Symptom**

* Automatic Repair loop
* Windows 11 upgrade failure
* Schannel TLS errors in Event Viewer

**Investigation**

* Ran DISM, SFC, and CHKDSK
* Reviewed CBS log
* Attempted Bootrec repair
* Investigated Windows setup failure

**Root Cause**

The System Reserved Partition was too small or lacked sufficient free space for Windows 11 setup to update boot components.

**Resolution**

Expand the System Reserved Partition using a dedicated partition management tool, then retry the Windows 11 upgrade. Continue using Bootrec only from the Windows Recovery Environment when boot repair is actually required.

Turns out the smallest partition on the disk caused the biggest headache. Windows really does have a talent for keeping us humble.
