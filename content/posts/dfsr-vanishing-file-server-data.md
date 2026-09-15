+++
title = "When DFSR Synced the Wrong State: Investigating Vanishing File Server Data"
slug = "dfsr-vanishing-file-server-data"
date = "2026-09-15"
author = "RoninSec"
cover = "/img/dfsr-vanishing-file-server-data-banner.png"
tags = ["windows-server", "dfsr", "incident-response", "veeam", "troubleshooting"]
keywords = ["dfsr troubleshooting", "windows file server", "dfsr backlog", "veeam backup", "file deletion investigation", "dfs replication"]
description = "A real-world investigation into missing file server data, DFS Replication behavior, backup pauses, and the evidence needed before recovery."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# When DFSR Synced the Wrong State: Investigating Vanishing File Server Data

I came in to find a particularly unpleasant file server mystery: multiple directories still existed, but the files inside them were gone.

Even stranger, the affected directories appeared to have changed at roughly the same time.

My first thought was obvious: who deleted them?

The investigation eventually pointed much more strongly toward DFS Replication than a person manually deleting thousands of files. More importantly, it became a useful lesson in distinguishing what the evidence proves from what merely looks suspicious.

---

## The Symptom

The affected data lived beneath a path similar to:

```text
D:\Company\SERVICE FILES
```

The parent folders and subfolders remained, but much of their content had disappeared.

File auditing had not been enabled beforehand, which immediately removed one of the best sources of attribution.

With Object Access auditing configured in advance, useful Security events can include:

* 4663 - Object access
* 4656 - Handle requested
* 4660 - Object deleted
* 5145 - SMB share access

Without that historical auditing, I could not simply search Event Viewer and find "USER-X deleted FILE-Y."

Fortunately, the server had both DFS Replication and recoverable backups/shadow copies.

---

## The Investigation

### 1. Preserve Logs Before Restoring

I did not immediately restore the files. Recovery was available, but I wanted to preserve evidence first.

Useful logs can be exported with:

```powershell
New-Item -Path C:\Forensics -ItemType Directory -Force

wevtutil epl Security C:\Forensics\Security.evtx
wevtutil epl "DFS Replication" C:\Forensics\DFSR.evtx
wevtutil epl System C:\Forensics\System.evtx
wevtutil epl Application C:\Forensics\Application.evtx
```

Restoring data and changing replication state can make an investigation harder, so preservation came first.

### 2. The DFSR Event That Changed the Investigation

I found a DFSR message reporting:

```text
Error: 9036 (Paused for backup or restore)
```

The environment used Veeam, so a backup operation interacting with VSS was an obvious explanation for the pause.

Important distinction: Event 9036 does not mean "DFSR deleted the files."

A backup-related DFSR pause can be normal.

The interesting question became what DFSR did before and after that pause.

### 3. Identify the Actual Replicated Folder

I initially tried:

```powershell
Get-DfsrPreservedFiles -Path "D:\Company\SERVICE FILES"
```

That failed with a manifest error and Access Denied.

This was an important gotcha: `SERVICE FILES` was only a subdirectory. I needed to understand the actual DFSR membership configuration.

```powershell
Get-DfsrMembership | Select-Object GroupName, FolderName, ContentPath
```

That revealed the replicated folder root was higher in the tree, similar to:

```text
D:\Company
```

### 4. Another Gotcha: Get-DfsrPreservedFiles

Even using the replicated root, `Get-DfsrPreservedFiles` continued returning errors.

I also initially looked beneath:

```text
C:\System Volume Information\DFSR
```

But the replicated data lived on `D:`, so the relevant DFSR storage was on that volume.

Checking:

```powershell
Get-ChildItem "D:\System Volume Information\DFSR" -Force
```

showed DFSR databases, configuration information, and internal tables on both replication members.

The database directories also had timestamps close to the incident window. That was suspicious and worth correlating with DFSR events, but a timestamp alone does not prove that a database rebuild caused the deletion.

That distinction matters.

### 5. Dump the DFSR Configuration

I captured the Active Directory DFSR configuration:

```cmd
dfsrdiag dumpadcfg > C:\Temp\DFSR_AD_Config.txt
```

`dumpadcfg` essentially answers:

"What does Active Directory say this DFSR environment should look like?"

It exposes replication groups, replicated folders, members, connections, content paths, staging paths, and other configuration information.

### 6. Check What DFSR Is Doing Right Now

Next:

```cmd
dfsrdiag replstate > C:\Temp\DFSR_ReplState.txt
```

This is different from configuration.

`dumpadcfg` shows how DFSR is configured.

`replstate` shows what DFSR is currently doing.

In my case, replication was active and a small number of inbound updates were scheduled.

### 7. Understand the Backlog

I also checked replication in both directions:

```cmd
dfsrdiag backlog /rgname:"example.local\shares\company" /rfname:"Company" /smem:SERVER-A /rmem:SERVER-B
```

Then reversed it:

```cmd
dfsrdiag backlog /rgname:"example.local\shares\company" /rfname:"Company" /smem:SERVER-B /rmem:SERVER-A
```

The backlog is basically DFSR's outstanding delivery queue.

If SERVER-A has 500 updates that SERVER-B has not processed, there is a backlog.

If the backlog reaches zero, the partners have processed the known DFSR updates between them.

The critical lesson is:

**Zero backlog does not mean the data is correct.**

It means DFSR believes the members are caught up.

Two servers can therefore converge on the wrong state. If a legitimate deletion propagates everywhere, DFSR can report no backlog while the administrator is staring at empty directories.

---

## What the Evidence Showed

The strongest findings were:

* The affected data was inside a DFSR replicated folder.
* DFSR experienced a backup/restore-related pause around the incident.
* The environment was actively using Veeam.
* DFSR metadata/database timestamps were close to the incident period.
* Replication subsequently appeared operational.
* File auditing was unavailable, preventing direct attribution of individual deletions.

The pattern was consistent with a DFSR-related propagation event.

What I could **not** conclusively prove from the evidence collected was that Veeam directly caused the deletion, or that a specific DFSR database rebuild definitively originated the empty state.

That is an important incident-response lesson: correlation is evidence, not automatically causation.

---

## The Root Cause

The working root-cause assessment was that an undesirable file state propagated through DFSR around a backup-related replication interruption.

Veeam/VSS explained why DFSR paused, but Event 9036 by itself was not proof that the backup deleted anything.

A useful analogy is two offices maintaining identical filing cabinets. DFSR is the courier carrying changes between them. If one office legitimately reports that 5,000 papers were removed, the courier does exactly its job and removes those papers from the other office too.

The courier can successfully synchronize a disaster.

Recovery therefore required restoring the missing data while carefully watching replication so the restored files were not immediately affected again.

---

## Key Takeaways

* Enable file auditing on critical shares before you need it.
* Event 9036 means DFSR paused for backup or restore; it does not itself prove deletion.
* Always identify the actual DFSR replicated root before troubleshooting subdirectories.
* Check `System Volume Information\DFSR` on the volume hosting the replicated data.
* `dfsrdiag dumpadcfg` shows DFSR's AD configuration.
* `dfsrdiag replstate` shows current replication activity.
* `dfsrdiag backlog` shows outstanding updates between members.
* Zero backlog means "caught up," not "correct."
* Preserve event logs before performing major recovery operations.
* Monitor DFSR events around backup windows and investigate unexpected initialization, database recovery, replication failures, or large deletion waves.
* Keep recoverable backups or shadow copies independent of replication. Replication is availability, not backup.

---

## Summary

**Symptom:** Folder structures remained, but large amounts of file content disappeared at approximately the same time.

**Investigation:** Reviewed Security and DFSR evidence, identified the actual replicated root, inspected DFSR metadata, dumped the AD configuration, checked live replication state, and examined replication backlog.

**Root Cause:** Evidence strongly implicated DFSR propagation around a backup-related interruption, but the available logs did not conclusively prove that Veeam itself or a specific database reinitialization originated the deletions.

**Resolution:** Preserve evidence, temporarily control backup/replication activity as necessary, restore the missing data from a known-good recovery source, and closely monitor DFSR afterward for recurrence.

DFSR did exactly what replication software does best: make sure everyone has the same problem.
