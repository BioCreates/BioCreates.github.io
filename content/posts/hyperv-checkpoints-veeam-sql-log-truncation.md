+++
title = "Understanding Hyper-V Checkpoints, Veeam Backups, and SQL Log Truncation"
slug = "hyperv-checkpoints-veeam-sql-log-truncation"
date = "2026-08-02"
author = "RoninSec"
cover = "/img/hyperv-checkpoints-veeam-sql-log-truncation-banner.png"
tags = ["hyper-v", "veeam", "sql-server", "virtualization", "backup"]
keywords = ["hyper-v checkpoints", "avhdx merge", "veeam backup", "sql transaction logs", "iscsi lun", "backup troubleshooting"]
description = "A practical walkthrough of investigating Hyper-V checkpoints, Veeam backup behavior, SQL log warnings, and storage growth."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Understanding Hyper-V Checkpoints, Veeam Backups, and SQL Log Truncation

Sometimes the best troubleshooting sessions are the ones where nothing is actually broken anymore, but you finally understand why everything works the way it does.

I recently chased down what initially looked like a Hyper-V checkpoint problem. That investigation quickly expanded into understanding how Veeam performs backups, why AVHDX files exist, when SQL transaction log warnings matter, and why my backup repository continued filling up even after reducing retention.

By the end, I hadn't just cleared an alert. I had a much better mental model of the entire backup process.

---

## The Symptom

A monitoring script on a Hyper-V host reported that one virtual machine still had a checkpoint while the others did not.

The output looked similar to this:

```text
Checking VirtualMachine (Name = 'APP-SERVER')
- WARN checkpoint was found
```

I already knew that lingering checkpoints were generally considered bad, but I wanted to understand why instead of simply deleting them.

---

## Investigation

### 1. Understanding what Veeam actually does

The first realization was that this checkpoint was not unusual.

Veeam creates a temporary Hyper-V checkpoint during a backup so the virtual machine can continue running while the backup reads a stable copy of the virtual disk.

The process looks like this:

1. Hyper-V creates a checkpoint.
2. The parent VHDX becomes read-only.
3. New writes are redirected into an AVHDX differencing disk.
4. Veeam backs up the parent VHDX.
5. Hyper-V merges the AVHDX back into the VHDX.
6. The checkpoint disappears.

That last step is the important one.

The alert was not telling me that a checkpoint existed.

It was telling me that the cleanup phase had not completed successfully.

---

### 2. Checking whether anything still needed merging

The first command checks for existing checkpoints.

```powershell
Get-VM | Get-VMSnapshot
```

No output means no checkpoints exist.

Next I verified which disk each VM was actually using.

```powershell
Get-VM | Get-VMHardDiskDrive | Select-Object VMName, Path
```

Every VM pointed directly to a `.vhdx` file.

There were no `.avhdx` files attached.

That confirmed every checkpoint had already merged successfully.

---

### 3. How to remove a lingering checkpoint

If a checkpoint remains after the backup completes, Hyper-V can safely perform an online merge.

```powershell
Get-VM "APP-SERVER" | Get-VMSnapshot | Remove-VMSnapshot -Verbose -Confirm
```

This initiates the merge without shutting down the VM.

One important lesson:

Never delete an AVHDX file manually.

Always let Hyper-V manage the merge.

---

## Gotchas I Learned

Several things can cause checkpoint cleanup to fail.

* Running out of storage during the merge
* Interrupting the backup
* Host crashes or unexpected reboots
* Older Hyper-V versions with merge issues
* Storage performance bottlenecks

One especially important gotcha is free space.

Before removing a checkpoint, I now verify there is enough storage available.

```powershell
Get-PSDrive -PSProvider FileSystem |
Select Name, @{Name="FreeGB";Expression={[math]::Round($_.Free/1GB,2)}}
```

I also check how large any AVHDX files have become.

```powershell
Get-VMHardDiskDrive -VMName "APP-SERVER" |
Select Path | ForEach-Object {
    Get-ChildItem (Split-Path $_.Path) *.avhdx |
    Select Name, @{Name="SizeGB";Expression={[math]::Round($_.Length/1GB,2)}}
}
```

A checkpoint is not a complete copy of the virtual disk.

It is a differencing disk that stores every write made after the checkpoint was created.

If a checkpoint is left around for days or weeks on a busy server, the AVHDX can become surprisingly large.

---

## What Happens If the Host Runs Out of Space?

This was another valuable lesson.

If Hyper-V cannot safely continue writing because storage becomes exhausted, it may pause the virtual machine.

A paused VM is not merely slower.

It effectively stops.

Users experience frozen applications, disconnected sessions, and what looks like a complete outage until the VM resumes.

That alone is a good reason to keep an eye on lingering checkpoints.

---

## The Storage Rabbit Hole

While investigating backups, I also noticed my backup repository was running low on storage.

The repository lived on an iSCSI LUN hosted on a NAS.

Even though the volume still had free space available, I could not increase the LUN size.

The reason turned out to be simple.

The LUN was already configured to the maximum size of the underlying volume.

Without adding larger drives, adding additional drives, or migrating to new storage, the LUN could not grow.

Reducing backup retention would buy some time, but it would not magically increase available capacity.

---

## Why Reducing Retention Did Not Immediately Free Space

I reduced daily retention and also lowered the GFS policy.

To my surprise, available storage actually dropped slightly after making the changes.

This initially seemed backwards.

The explanation was that Veeam does not immediately delete restore points when retention changes.

Cleanup happens during later backup cycles after restore points fall outside the new policy.

GFS restore points also remain pinned until they naturally expire.

Changing the settings does not instantly reclaim storage.

That was an important distinction I had not appreciated before.

---

## SQL Transaction Log Warnings

While reviewing backup health, I also investigated recurring SQL transaction log truncation warnings.

At first I wondered whether these alerts could simply be ignored.

The answer was: sometimes.

If SQL databases use the Full recovery model and no other process performs transaction log backups, these warnings matter because transaction logs can continue growing until they eventually consume all available disk space.

If another backup process already manages SQL logs, or the databases use the Simple recovery model, the warning may not represent a real problem.

To help verify database configuration directly from the VM, I put together a PowerShell check.

```powershell
Add-Type -AssemblyName "Microsoft.SqlServer.Smo"

$server = New-Object Microsoft.SqlServer.Management.Smo.Server "localhost"

$server.Databases | ForEach-Object {
    $_.LogFiles | ForEach-Object {
        [PSCustomObject]@{
            Database = $_.Parent.Name
            RecoveryModel = $_.Parent.RecoveryModel
            LogFile = $_.FileName
            LogSizeMB = [math]::Round($_.Size/1MB,2)
            LogUsedPct = [math]::Round($_.UsedSpace/$_.Size*100,2)
        }
    }
} | Format-Table -AutoSize
```

This gives a quick overview of which databases may actually be at risk.

---

## What the Evidence Showed

The original checkpoint alert ultimately resolved itself after the next successful backup.

The verification commands confirmed there were no remaining checkpoints and no AVHDX files attached to any virtual machines.

The storage issue was not caused by a faulty LUN.

It was simply a capacity limitation.

The SQL warnings still deserved investigation, but they were not automatically critical without understanding the database recovery model.

Most importantly, I walked away understanding why each of these behaviors exists instead of treating them as mysterious alerts.

---

## Key Takeaways

* Hyper-V checkpoints during Veeam backups are expected.
* Alerts indicate cleanup failures, not checkpoint creation.
* Never manually delete AVHDX files.
* Verify checkpoints with PowerShell before taking action.
* Ensure adequate free storage before initiating merges.
* Reduced retention does not immediately reclaim repository space.
* SQL truncation warnings require context before deciding whether they can be ignored.
* Understanding the system is far more valuable than memorizing commands.

---

## Summary

**Symptom**

A Hyper-V checkpoint alert, growing backup storage usage, and recurring SQL transaction log warnings.

**Investigation**

Verified checkpoint state, confirmed VHDX versus AVHDX usage, reviewed repository retention behavior, examined iSCSI storage limitations, and researched SQL transaction log handling.

**Root Cause**

The checkpoint alert represented a temporary cleanup issue, storage growth was expected behavior under retention and GFS rules, and SQL warnings depended on recovery model and backup configuration.

**Resolution**

Validated that checkpoints had merged successfully, confirmed healthy VM disk attachments, adjusted backup retention appropriately, identified storage limitations, and established a repeatable process for evaluating SQL log warnings.

Turns out the scariest alert of the day was really just asking me to learn something instead of panic.
