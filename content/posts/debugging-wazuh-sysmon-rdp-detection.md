+++
title = "Debugging Wazuh Sysmon RDP Detection When The Events Exist But The Alerts Do Not"
slug = "debugging-wazuh-sysmon-rdp-detection"
date = "2026-09-14"
author = "RoninSec"
cover = "/img/debugging-wazuh-sysmon-rdp-detection-banner.png"
tags = ["wazuh", "sysmon", "rdp-detection", "windows-security", "detection-engineering"]
keywords = ["wazuh sysmon", "sysmon event id 3", "rdp detection", "wazuh custom rules", "wazuh ruleset test", "destination port 3389"]
description = "A practical walkthrough of debugging Wazuh custom RDP detection when Sysmon Event ID 3 reaches the manager but never becomes an alert."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Debugging Wazuh Sysmon RDP Detection When The Events Exist But The Alerts Do Not

There is a special kind of frustration in detection engineering: generating exactly the event you want, proving that the SIEM received it, and then watching absolutely nothing appear in the alert dashboard.

That was my situation while building a Wazuh rule for RDP activity using Sysmon Event ID 3.

The good news was that Sysmon worked. The Wazuh agent worked. The manager received the events. The bad news was that my custom detection still refused to fire.

Here is how I worked through it.

---

## The Symptom

My goal was straightforward: detect network connections involving RDP on TCP port 3389 using Sysmon NetworkConnect events.

I wanted to eventually distinguish between outbound RDP initiated by a workstation and inbound RDP received by another system.

I created custom Wazuh rules, generated RDP traffic, and searched the Wazuh UI.

Nothing.

At first this made me question the entire pipeline. Was Sysmon configured incorrectly? Was the agent collecting the Sysmon Operational channel? Was Wazuh dropping Event ID 3?

Instead of changing more configuration, I checked the raw evidence.

---

## The Investigation

### 1. Verify That Sysmon Events Actually Reach The Manager

Because my Wazuh deployment was running in Docker, I searched the manager's archives directly.

```bash
sudo docker exec -it "$MANAGER" bash -lc "grep -F 'Microsoft-Windows-Sysmon' /var/ossec/logs/archives/archives.json | grep '\"eventID\":\"3\"' | tail -n 20"
```

That immediately changed the investigation.

The archive contained events resembling:

```text
providerName: Microsoft-Windows-Sysmon
eventID: 3
ruleName: RDP
protocol: tcp
initiated: false
sourceIp: 192.168.1.106
destinationIp: 192.168.1.8
destinationPort: 3389
destinationPortName: ms-wbt-server
```

The event was also decoded as:

```text
decoder: windows_eventchannel
location: EventChannel
```

That proved several important things.

Sysmon was generating Event ID 3. The endpoint agent was forwarding it. Wazuh was receiving it. The Windows EventChannel decoder understood it. Most importantly, `destinationPort` really contained `3389`.

The problem had moved downstream into rule matching and alert generation.

### 2. Inspect The Exact Field Names

One of my earlier rules referenced:

```text
win.eventdata.DestinationPort
```

But the decoded event showed:

```text
win.eventdata.destinationPort
```

That lowercase `d` matters when referencing the decoded dynamic field.

Rather than guessing from Microsoft's original XML naming, I needed to build the Wazuh rule against the field names Wazuh actually exposed after decoding.

A cleaner condition therefore became:

```text
<field name="win.eventdata.destinationPort">^3389$</field>
```

The same lesson applies to fields such as `initiated`, `image`, and `destinationIp`: inspect the decoded Wazuh event instead of assuming the original Windows field capitalization survives unchanged.

### 3. Simplify The Rule

I experimented with chaining the custom rule to Wazuh's existing Sysmon Event ID 3 handling using rule ID 61605 and the `sysmon_event3` group.

An early attempt looked roughly like this:

```text
<group name="windows,sysmon,rdp">
  <rule id="100200" level="13">
    <if_group>sysmon_event3</if_group>
    <if_sid>61605</if_sid>
    <dstport>3389</dstport>
    <description>Successful RDP connection</description>
  </rule>
</group>
```

There were too many assumptions packed into that rule.

`dstport` depends on a decoder populating Wazuh's generic `dstport` field. My Sysmon event instead exposed the value under `win.eventdata.destinationPort`.

I was also combining `if_group` and `if_sid` while still trying to establish basic matching. Even when chaining is intentional, adding multiple dependencies during initial troubleshooting makes it harder to identify which condition failed.

I simplified the detection around fields I could directly prove existed:

```text
<group name="windows,sysmon,lateral_movement,">
  <rule id="100504" level="10">
    <description>Sysmon NetConnect: RDP outbound (destination port 3389)</description>
    <field name="win.system.providerName">^Microsoft-Windows-Sysmon$</field>
    <field name="win.system.eventID">^3$</field>
    <field name="win.eventdata.initiated">^true$</field>
    <field name="win.eventdata.destinationPort">^3389$</field>
    <group>lateral_movement,rdp,sysmon,network,</group>
  </rule>

  <rule id="100505" level="10">
    <description>Sysmon NetConnect: RDP inbound (destination port 3389)</description>
    <field name="win.system.providerName">^Microsoft-Windows-Sysmon$</field>
    <field name="win.system.eventID">^3$</field>
    <field name="win.eventdata.initiated">^false$</field>
    <field name="win.eventdata.destinationPort">^3389$</field>
    <group>lateral_movement,rdp,sysmon,network,</group>
  </rule>
</group>
```

### 4. Test The Rule Correctly

Another roadblock appeared in Wazuh Ruleset Test.

I pasted formatted JSON like this:

```text
{
  "win": {
    ...
  }
}
```

The test output repeatedly said:

```text
Phase 2: Completed decoding.
No decoder matched.
```

The important clue was that Wazuh displayed each individual line as a separate `full event`.

It was not testing one JSON document. It was testing `{`, `"win": {`, and the following lines as separate events.

For this workflow, the test event needed to be supplied as one complete log line. I also wanted it to resemble an actual Windows EventChannel event as closely as possible rather than constructing an overly minimal synthetic event.

This was a great reminder that a failed Ruleset Test does not automatically mean the rule is wrong. The test input itself can be wrong.

---

## What The Evidence Showed

The strongest evidence came from `archives.json`.

Real RDP connections were unquestionably reaching the manager as Sysmon Event ID 3 with `destinationPort` equal to `3389`. Inbound connections also showed `initiated:false`, which gave me another useful dimension for detection logic.

This narrowed the pipeline to:

```text
Sysmon -> Wazuh Agent -> Manager -> Decoder -> Rule Evaluation -> Alert
   OK          OK          OK         OK            ?
```

That is a much better troubleshooting position than randomly editing Sysmon configuration.

---

## The Root Cause

There was not one single definitively proven failure. Several rule-development problems were uncovered:

* I referenced decoded Sysmon fields using incorrect capitalization.
* I initially used generic `dstport` instead of the actual decoded `win.eventdata.destinationPort` field.
* I complicated testing with both `if_sid` and `if_group` before proving a simple field-based rule.
* I fed Ruleset Test multi-line JSON, causing each line to be evaluated independently.

The important distinction was that the events were in the archives but were not becoming the custom alerts I expected. That pointed away from collection and toward filtering.

After editing local rules, I can reload the Wazuh manager rather than treating a full Docker container restart as the first troubleshooting step. A restart is something I would reserve for cases where reload fails or another component actually requires it.

---

## Key Takeaways

* Check `archives.json` before assuming telemetry is missing.
* Separate collection problems from detection problems.
* Build rules against Wazuh's decoded field names, not assumptions about the original Windows XML.
* Sysmon Event ID 3 is NetworkConnect and provides useful RDP fields including `destinationPort` and `initiated`.
* Start with the smallest rule that can possibly match.
* Add `if_sid`, `if_group`, process constraints, and other dependencies only after basic matching works.
* Treat Ruleset Test input as part of the experiment.
* Seeing an event in archives does not guarantee it will exist in the alert index.
* Always compare a rule against a real decoded event when debugging field names.

---

## Summary

> **Symptom:** Sysmon RDP NetworkConnect events existed on the endpoint but the expected custom Wazuh alert did not appear.
>
> **Investigation:** I searched the manager archives, confirmed Sysmon Event ID 3 was decoded, inspected the actual dynamic fields, simplified the custom rule, and investigated misleading Ruleset Test failures.
>
> **Root Cause:** The investigation exposed mismatched field references, unnecessary rule dependencies, and incorrectly formatted Ruleset Test input. No single failure was conclusively isolated as the sole cause.
>
> **Resolution:** Base the RDP detection on the decoded `win.eventdata.destinationPort` and `initiated` fields, test with a complete single-line event, and validate each stage of the Wazuh pipeline independently.

The logs were innocent all along - my rule was the one refusing to cooperate.
