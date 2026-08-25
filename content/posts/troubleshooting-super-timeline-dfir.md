+++
title = "Troubleshooting a Super Timeline in DFIR"
slug = "troubleshooting-super-timeline-dfir"
date = "2026-08-23"
author = "RoninSec"
cover = "/img/troubleshooting-super-timeline-dfir-banner.png"
tags = ["dfir", "plaso", "windows-forensics", "ntfs", "timeline-analysis"]
keywords = ["dfir", "plaso", "timeline", "ntfs", "event-log", "usn-journal", "mft"]
description = "A practical DFIR walk-through covering timeline build issues, parser conflicts, and how I read the resulting NTFS and log evidence."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Troubleshooting a Super Timeline in DFIR

I spent this lab session building a Windows super timeline, fighting through tool version mismatches, and then using the results to read filesystem and log evidence like a story. The interesting part was not just getting the timeline built. It was seeing how many small clues line up once the data is finally in one place.

---

## The Symptom

I started with an old DFIR lab write-up and quickly found that the commands in the article did not map cleanly to my environment. The first roadblock was a Python library mismatch. The timeline tool was loading the wrong `pyparsing` version, which caused a crash during startup. After that, I hit a second problem: the command line itself was not being parsed the way the tutorial expected.

The big lesson was simple. In DFIR, old instructions are helpful, but they are not gospel. Tool versions move. Syntax changes. Dependencies drift. The evidence does not care, but the tool absolutely does.

---

## The Investigation

### 1. I checked which binaries and Python packages were actually being used

```bash
which log2timeline.py
python3 -c "import sys, plaso; print('python', sys.executable); print('plaso pkg file:', plaso.__file__)"
python3 -c "import pyparsing; print('pyparsing', pyparsing.__version__, pyparsing.__file__)"
dpkg -l | grep -i plaso
dpkg -l | grep -i pyparsing
```

I was looking for two things here: the exact executable path for the timeline tool, and the exact version and install location of `pyparsing`. That told me whether I was dealing with the system install or a pip install living somewhere else.

### 2. I cleaned out the conflicting Python packages

The big gotcha was that pip and apt had both touched the same Python space. That kind of overlap is a classic way to break forensic tooling.

```bash
sudo python3 -m pip uninstall -y pyparsing python-evtx
sudo rm -rf /usr/local/lib/python3.10/dist-packages/pyparsing*
sudo rm -rf /usr/local/lib/python3.10/dist-packages/python_evtx*
sudo apt install --reinstall python3-pyparsing python3-plaso plaso-tools plaso-data
```

That step mattered because the system package for `pyparsing` was version 3.x, while the pip copy had been shadowing it in `/usr/local`. Once I removed the shadow copy, the tool stopped tripping over the wrong API.

### 3. I used the correct log2timeline syntax

The old article expected a slightly different calling pattern. My version wanted the output storage file to be explicit.

```bash
log2timeline.py --status_view window -f /usr/share/plaso/filter_windows.yaml \
  --storage_file /cases/case001/dc01/timeline.plaso \
  /cases/case001/dc01/disk/image.E01 \
  --partitions all
```

That `--storage_file` switch fixed the weird "unrecognized arguments" behavior. Once I made the output destination explicit, the command finally behaved like a normal command instead of a stubborn puzzle box.

### 4. I checked the storage summary

```bash
pinfo.py timeline.plaso
```

This gave me the high-level view of the timeline: sessions, event counts, warnings, and parser breakdowns. That summary is where I got my first real sense of scale.

---

## What the Evidence Showed

The storage summary showed a large number of events, with the biggest chunks coming from Windows Event Logs, registry-derived artifacts, the USN journal, and bodyfile data. That told me the timeline was pulling from the right places.

The warning section was also useful. It showed a few extraction warnings and a larger number of recovery warnings for some EVTX and bodyfile sources. That did not automatically mean the data was bad. It meant I needed to be careful and treat recovered records as useful, but not always perfect.

From there, I opened the super timeline in Timeline Explorer and started searching for a specific phrase from the lab data. That pivot exposed file activity around a suspicious filename, then related MFT file name records, shortcut records, shell item entries, and USN change records. In other words, the timeline did exactly what I wanted: it turned one suspicious filename into a little ecosystem of related activity.

One MFT line in particular was a good teaching moment:

```text
[MFT FILE_NAME] FileShare\Secret\Szechuan Sauce.txt (Offset: 0x7b659c00) Owner identifier: 0 Group identifier: 0 Mode: ---a-----------
```

That line is filesystem metadata, not file content. It told me the file existed in NTFS, where it lived, and that the archive bit was set. The archive bit is a small detail, but it often means the file was created or modified. The related USN and shortcut events helped confirm the file was active around the same time.

I also reviewed a Windows Security 4624 event. That one was important because it showed a successful logon for the Administrator account with Logon Type 10, which usually means Remote Desktop. The source was an external IP address. That does not prove compromise by itself, but it is absolutely the kind of thing I would want to validate with surrounding events, failed logons, and follow-on process creation.

---

## The Root Cause

The root cause of the tooling trouble was not one single thing. It was a stack of small issues:

* A pip-installed Python package was shadowing the system package.
* The timeline tool expected newer syntax than the tutorial used.
* The article I was following was old enough that some command patterns no longer matched my install.
* The package manager threw unrelated dependency noise during reinstall, which made the whole thing feel worse than it was.

Once I cleaned up the Python conflicts and used the correct storage-file syntax, the rest of the workflow started making sense again.

---

## Key Takeaways

* Old DFIR write-ups are still useful, but I always verify the commands against the current build.
* Python package shadowing can break forensic tools in ways that look like application bugs.
* `--storage_file` was the key to getting this timeline build to run correctly.
* `pinfo.py` is worth running early because it tells me whether the storage actually collected useful evidence.
* MFT, USN, LNK, shell items, and Event Logs make more sense when I read them together, not in isolation.
* A successful Administrator RDP logon is not proof of compromise, but it is definitely worth a closer look.

---

## Summary

> **Symptom:** The super timeline build kept failing because the tool and the tutorial were out of sync, and Python dependencies were conflicting.
>
> **Investigation:** I checked the active binaries and Python modules, removed shadowing pip packages, reinstalled the system packages, used `--storage_file`, and then validated the output with `pinfo.py`.
>
> **Root Cause:** A mixed Python environment plus older command syntax from the lab article.
>
> **Resolution:** Cleaned up the dependency conflict, ran the timeline with explicit output storage, and used the resulting storage file to pivot into NTFS and log evidence.

The timeline was messy, but the evidence still spilled the tea.
