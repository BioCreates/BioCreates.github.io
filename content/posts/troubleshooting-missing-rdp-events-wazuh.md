+++
title = "Troubleshooting Missing RDP Events in Wazuh"
slug = "troubleshooting-missing-rdp-events-wazuh"
date = "2026-09-19"
author = "RoninSec"
cover = "/img/troubleshooting-missing-rdp-events-wazuh-banner.png"
tags = ["wazuh", "windows", "rdp", "threat-hunting", "siem"]
keywords = ["wazuh rdp events", "event id 1149", "terminalservices remoteconnectionmanager", "wazuh custom rules", "windows event channels", "threat hunting"]
description = "A practical Wazuh troubleshooting walkthrough for collecting Windows RDP Event ID 1149 and turning a silent event channel into a visible alert."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Troubleshooting Missing RDP Events in Wazuh

I was building out a fresh Wazuh lab and wanted visibility into Remote Desktop authentication activity. Windows was clearly recording the events, the Wazuh agent claimed it was monitoring the channel, and yet nothing useful appeared in the Threat Hunting dashboard.

That made this a good troubleshooting exercise because the obvious suspect - the event channel path - turned out not to be the problem at all.

---

## The Symptom

The Windows event channel I wanted to collect was:

```text
Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
```

My first suspicion was the channel name itself.

There are several hyphens in:

```text
TerminalServices-RemoteConnectionManager
```

I wondered whether Wazuh might interpret the hyphens as some kind of hierarchy instead of treating the full string as one Windows Event Log channel.

It does not.

The entire value is a valid Windows Event Channel name, and the slash before `Operational` is part of the actual channel path.

My agent configuration contained:

```text
<localfile>
  <location>Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Windows itself confirmed that events were present in the channel.

---

## The Investigation

### 1. Verify Windows Actually Has Events

Before blaming Wazuh, I checked the source.

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -MaxEvents 5 |
    Format-Table TimeCreated, Id, ProviderName -Auto
```

The log contained events, so Windows logging was working.

That eliminated one entire branch of troubleshooting immediately.

### 2. Verify the Wazuh Agent Recognizes the Channel

Next I inspected the agent log:

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log"
```

The important line was:

```text
wazuh-agent: INFO: (1951): Analyzing event log: 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'.
```

That was strong evidence that the channel name was valid and Wazuh had successfully registered it for collection.

I also saw:

```text
wazuh-agent: INFO: (4102): Connected to the server ([192.168.1.83]:1514/tcp).
```

So the agent also had connectivity to the manager.

### 3. Notice the Duplicate Configuration Warning

The logs also showed:

```text
WARNING: (1958): Log file 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' is duplicated.
```

At first this looked suspicious.

The agent belonged to a centralized Wazuh group that already defined the RDP and Sysmon channels. I had later added the same channels directly into the endpoint's `ossec.conf`.

That created duplicate definitions.

I removed the local duplicates and allowed the group configuration to handle the channels.

This was a legitimate configuration problem worth cleaning up, but it was not the original cause. The missing alert behavior had existed before I introduced the duplicate entries.

That distinction matters during troubleshooting: not every warning you discover is the problem you are actually chasing.

### 4. Separate Collection From Alerting

The next question was whether I was expecting Wazuh to display something simply because it had collected it.

Wazuh has multiple stages:

```text
Windows Event Log
        |
        v
Wazuh Agent
        |
        v
Wazuh Manager
        |
        v
Decoder and Rule Evaluation
        |
        +---- matching rule ----> alert
        |
        +---- no useful match --> no Threat Hunting alert
```

The agent saying "Analyzing event log" proves that the source is configured for collection.

It does not prove that a useful alert will be generated.

This was the turning point.

---

## What the Evidence Showed

The Windows endpoint had Event ID 1149 events in:

```text
Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
```

The Wazuh agent successfully loaded that channel.

The agent was connected to the manager.

What I had not yet proven directly was whether the raw event existed in the manager's archive files. My Wazuh deployment was running as Docker containers under WSL, so I prepared to inspect the manager container:

```bash
docker ps
```

The manager could then be entered with:

```bash
docker exec -it single-node-wazuh.manager-1 bash
```

Useful locations for future troubleshooting are:

```bash
/var/ossec/logs/archives/archives.json
```

and:

```bash
/var/ossec/logs/alerts/alerts.json
```

For example:

```bash
grep -i "TerminalServices-RemoteConnectionManager" /var/ossec/logs/archives/archives.json | tail -n 20
```

However, before I needed to finish that investigation, I tested the rule layer.

---

## The Root Cause

I created a custom Wazuh rule specifically for RDP Event ID 1149:

```text
<group name="windows,rdp,authentication,">
  <rule id="921149" level="6">
    <if_group>windows</if_group>
    <field name="win.system.channel">Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational</field>
    <field name="win.system.eventID">1149</field>
    <description>RDP: user authentication succeeded (1149)</description>
  </rule>
</group>
```

After adding the rule and reloading the manager, the event appeared in the Threat Hunting dashboard.

Success.

The practical root cause was not a malformed event channel path. The missing piece was a rule that converted the collected Event ID 1149 data into an alert Wazuh would surface in the dashboard.

One detail I deliberately did not claim as proven: I never completed the raw `archives.json` verification before the rule solved the problem. The evidence strongly supported a collection-versus-alerting issue, and the successful rule confirmed the alerting side, but checking the archive would still be the cleanest way to prove every pipeline stage independently.

---

## Why `if_group` Uses `windows`

The rule contains:

```text
<if_group>windows</if_group>
```

This scopes the child rule to events that have already been classified within the Windows rule chain.

Conceptually:

```text
Windows event
    |
    v
windows group
    |
    v
RDP-specific field matching
    |
    v
Event ID 1149 alert
```

It keeps the custom detection tied to the appropriate parent rule context instead of evaluating it as an unrelated standalone rule.

The outer group:

```text
windows,rdp,authentication
```

also gives the custom rule useful organizational tags.

---

## Gotchas and Roadblocks

* A valid Windows Event Channel can contain multiple hyphens. They do not represent folder separators to Wazuh.
* `Analyzing event log` confirms the channel was accepted, but it does not guarantee that a dashboard alert will exist.
* Centralized group configuration can silently overlap with local `ossec.conf` entries and produce duplicate log warnings.
* A duplicate warning can be real without being the actual root cause.
* Threat Hunting visibility depends on rule evaluation, not merely on Windows generating an event.
* When troubleshooting Wazuh, separate source generation, agent collection, transport, manager ingestion, rule matching, and indexing into distinct stages.
* `archives.json` and `alerts.json` are extremely useful for determining exactly where the pipeline stops.

---

## Key Takeaways

* Verify the Windows event first with `Get-WinEvent`.
* Confirm the agent reports `Analyzing event log`.
* Check for duplicate centralized and local configurations.
* Do not confuse "collected" with "alerted."
* Use a custom rule when the default Wazuh ruleset does not surface the event you care about.
* For RDP authentication, Event ID 1149 from `RemoteConnectionManager/Operational` is a useful signal to monitor.
* When uncertainty remains, inspect `archives.json` before changing more configuration.

---

## Summary

> **Symptom:** Windows RDP Event ID 1149 existed locally but did not appear as an alert in Wazuh Threat Hunting.
>
> **Investigation:** Verified the Windows channel, confirmed the Wazuh agent subscribed to it, removed duplicate local and centralized definitions, and separated event collection from rule-based alert generation.
>
> **Root Cause:** The event channel configuration was valid, but there was no useful matching rule producing an alert for Event ID 1149.
>
> **Resolution:** Added a custom Windows RDP rule matching the TerminalServices RemoteConnectionManager channel and Event ID 1149, after which the event immediately appeared in Threat Hunting.

Sometimes the log is not missing at all - it is just waiting for a rule to give it a reason to make some noise.
