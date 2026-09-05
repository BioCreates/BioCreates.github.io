+++
title = "Hunting Scheduled Task Persistence With Sysmon And Wazuh"
slug = "wazuh-sysmon-scheduled-task-persistence"
date = "2026-09-05"
author = "RoninSec"
cover = "/img/wazuh-sysmon-scheduled-task-persistence-banner.png"
tags = ["wazuh", "sysmon", "detection-engineering", "windows-security", "threat-hunting"]
keywords = ["wazuh", "sysmon", "scheduled tasks", "schtasks", "persistence detection", "windows event logs", "custom rules"]
description = "A hands-on Wazuh and Sysmon lab that turned a missing schtasks event into a practical lesson about telemetry, rules, and detection engineering."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Hunting Scheduled Task Persistence With Sysmon And Wazuh

I started this lab expecting something simple: generate persistence activity on a Windows VM, confirm Sysmon sees it, and then find it in Wazuh.

The registry test worked almost immediately.

Scheduled tasks? Not so much.

That sent me down a troubleshooting rabbit hole that ended up teaching me more about how Wazuh actually handles Sysmon events than the original lab probably intended.

---

## The First Persistence Test

I started with a registry Run key pointing to the classic harmless test payload, `calc.exe`.

```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestPersist /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
```

Sysmon captured the registry modification, and I was able to locate the resulting event in Wazuh.

Instead of manually digging through every Sysmon event, I narrowed things down using the provider and event ID:

```text
data.win.system.providerName:"Microsoft-Windows-Sysmon" AND data.win.system.eventID:1
```

Event ID 1 is Sysmon's Process Create event, which is extremely useful because it can include fields such as:

* Image
* CommandLine
* ParentImage
* ParentCommandLine
* User
* ProcessId
* Hashes

Expanding an event in Wazuh let me see exactly what command had executed.

I also stumbled across an important side lesson: commands containing credentials can expose those credentials in Sysmon's `CommandLine` field. For example, using `net user` with a password directly on the command line can result in that password being recorded in process creation telemetry.

That is useful to defenders, but also a reminder not to casually place secrets on command lines.

Windows can provide similar process creation auditing through the Security log, but Advanced Audit Policy must be configured appropriately. That was outside the scope of this lab, so I stuck with Sysmon.

---

## Detecting Scheduled Task Creation

Next I moved to another common persistence mechanism: scheduled tasks.

I created a harmless test task:

```cmd
schtasks /create /sc minute /mo 50 /tn "TestTask" /tr "calc.exe"
```

Sysmon immediately recorded it as Event ID 1.

The event clearly showed:

```text
Image: C:\Windows\System32\schtasks.exe
OriginalFileName: schtasks.exe
CommandLine: schtasks /create /sc minute /mo 50 /tn "TestTask" /tr "calc.exe"
ParentImage: C:\Windows\System32\cmd.exe
```

Perfect.

Except Wazuh did not show it.

At all.

---

## The Investigation

I did not want to immediately start changing configuration because other Sysmon events were already reaching Wazuh. That meant the basic telemetry pipeline was working.

### 1. Verify Sysmon Locally

I confirmed recent Process Create events directly from Windows:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
Where-Object { $_.Id -eq 1 } |
Select-Object -First 5
```

The `schtasks.exe` event was definitely there.

### 2. Verify The Wazuh Agent Subscription

The Windows Wazuh agent configuration already contained:

```text
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

The agent log also confirmed that it was analyzing the Sysmon channel:

```cmd
type "C:\Program Files (x86)\ossec-agent\ossec.log" | findstr Sysmon
```

This produced messages similar to:

```text
wazuh-agent: INFO: (1951): Analyzing event log: 'Microsoft-Windows-Sysmon/Operational'.
```

So I had a strange situation:

Sysmon worked.

Wazuh worked.

Other Sysmon events worked.

But this particular Process Create event was nowhere to be found in the Wazuh alerts I was searching.

### 3. Check Wazuh's Local Rules

Because my Wazuh deployment runs in Docker, the custom rules file lives inside the manager container:

```text
/var/ossec/etc/rules/local_rules.xml
```

I confirmed it existed with:

```bash
sudo docker exec -it single-node-wazuh.manager-1 ls /var/ossec/etc/rules/
```

Then viewed it:

```bash
sudo docker exec -it single-node-wazuh.manager-1 cat /var/ossec/etc/rules/local_rules.xml
```

Before touching anything, I made a backup:

```bash
sudo docker exec -it single-node-wazuh.manager-1 bash -lc 'cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak'
```

That backup ended up being useful.

---

## Gotcha: Sysmon Saw It, But Wazuh Did Not Alert

This one had me chasing ghosts.

I initially suspected my search query, but the important distinction was between Sysmon collecting telemetry and Wazuh creating an alert from that telemetry.

A Sysmon event existing on the endpoint does not automatically mean Wazuh will generate an alert for it. Wazuh's analysis engine evaluates incoming events against its ruleset, and the `schtasks.exe` activity I was testing was not producing the alert I expected.

I added a custom rule tied to the Sysmon Event ID 1 rule group:

```text
<group name="windows,sysmon,persistence,">
  <rule id="100502" level="10">
    <description>Sysmon ProcessCreate: schtasks.exe observed</description>
    <if_group>sysmon_event1</if_group>
    <match>\\schtasks.exe</match>
  </rule>
</group>
```

I then restarted the Wazuh manager:

```bash
sudo docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

I generated another scheduled task:

```cmd
schtasks /create /sc minute /mo 50 /tn "TestTask" /tr "calc.exe"
```

And then...

BOOM.

The new `schtasks.exe` Process Create events appeared in Wazuh.

The query that worked in my environment was:

```text
data.win.system.eventID:1 AND data.win.eventdata.image:*\\schtasks.exe
```

An important detail was that only events generated after the rule was loaded appeared as alerts. The older scheduled task events did not suddenly populate afterward.

---

## One Roadblock Worth Remembering

My first custom rule attempt failed to load because I used an invalid `regex` construction.

Wazuh reported:

```text
ERROR: (5107): Syntax error on tag 'regex'
CRITICAL: (1220): Error loading the rules: 'etc/rules/local_rules.xml'.
```

This is exactly why I backed up `local_rules.xml` first.

I restored it:

```bash
sudo docker exec -it single-node-wazuh.manager-1 bash -lc 'cp /var/ossec/etc/rules/local_rules.xml.bak /var/ossec/etc/rules/local_rules.xml'
```

Then I switched to the simpler `if_group` plus `match` rule shown above.

Lesson learned: keep the first detection rule simple, prove that it works, and then make it more sophisticated.

---

## What The Evidence Showed

The troubleshooting process established several separate facts:

1. Sysmon was correctly recording `schtasks.exe` as Event ID 1.
2. The Wazuh agent was subscribed to the Sysmon Operational channel.
3. Other Sysmon telemetry was successfully reaching Wazuh.
4. The scheduled task activity was not generating the Wazuh alert I expected.
5. Adding a custom rule associated with `sysmon_event1` caused subsequent `schtasks.exe` events to appear.
6. Previously generated events did not retroactively become alerts.

I did not conclusively prove every internal processing decision Wazuh made with the earlier events, so I would not describe them as "lost" at a specific stage without additional instrumentation. What I can prove is that they were absent from the alert data I was searching, while newly generated events appeared after the rule was loaded.

That distinction matters.

---

## Key Takeaways

* Sysmon collecting an event and Wazuh alerting on it are two different things.
* Sysmon Event ID 1 provides excellent process creation telemetry, including command lines and parent processes.
* Always confirm the event locally before blaming the SIEM.
* Check the Wazuh agent's event channel subscription before changing anything.
* Custom Wazuh rules belong on the manager, not the Windows endpoint.
* In my Docker deployment, the file was `/var/ossec/etc/rules/local_rules.xml`.
* Back up `local_rules.xml` before experimenting.
* Restart the Wazuh manager after changing rules.
* Rules are evaluated when events are processed. Adding a rule does not retroactively generate alerts for older events.
* Use the actual field names present in your environment. Mine used `data.win.system.*` and `data.win.eventdata.*`.
* Do not assume "the log exists" means "the detection exists."

---

## Summary

> **Symptom:** Sysmon clearly recorded `schtasks.exe` Process Create events, but I could not find corresponding Wazuh alerts.
>
> **Investigation:** I verified Sysmon Event ID 1 locally, confirmed the Wazuh agent was monitoring the Sysmon Operational channel, checked the manager, inspected the local rules file, and tested fresh scheduled task activity.
>
> **Root Cause:** The scheduled task process creation activity was not producing the Wazuh alert I expected with the existing ruleset.
>
> **Resolution:** I added a custom `sysmon_event1` rule matching `schtasks.exe`, restarted the Wazuh manager, generated a fresh scheduled task event, and successfully found it using `data.win.system.eventID:1 AND data.win.eventdata.image:*\\schtasks.exe`.

The biggest lesson from this lab was not how to run `schtasks`. It was learning that telemetry and detection are not the same thing. Sysmon can have the receipts, but sometimes Wazuh still needs to be told which ones are worth putting under the spotlight.

Turns out the scheduled task was not hiding - it just had not made Wazuh's guest list yet.
