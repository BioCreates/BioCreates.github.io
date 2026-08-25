+++
title = "Diagnosing Random Zyxel Switch Reboots Caused by Layer 2 Loops"
slug = "zyxel-switch-random-reboots-layer2-loop"
date = "2026-08-25"
author = "RoninSec"
cover = "/img/zyxel-switch-random-reboots-layer2-loop-banner.png"
tags = ["networking", "zyxel", "switching", "troubleshooting", "spanning-tree"]
keywords = ["zyxel gs1920", "random switch reboot", "rstp", "spanning tree", "port flapping", "layer2 loop", "switch troubleshooting"]
description = "A real-world troubleshooting walkthrough showing how enabling Rapid Spanning Tree stabilized a Zyxel switch suffering from unexplained reboots."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Diagnosing Random Zyxel Switch Reboots Caused by Layer 2 Loops

Sometimes the problem is exactly what the user describes. Other times, the reported symptom is just the result of something happening much deeper in the network.

This case started with a managed switch that would randomly power off and come back online. At first glance it sounded like failing hardware or an unstable power source. By the end of the investigation, the evidence pointed somewhere completely different.

---

## The Symptom

A client reported that their Zyxel GS1920-48 switch would randomly turn off and then come back online by itself.

The initial assumptions were the usual suspects:

1. Power supply or outlet instability
2. Overheating
3. Firmware bug
4. PoE overload
5. Hardware failure

Before changing anything, I reviewed the switch logs to see if they told a different story.

---

## The Investigation

### 1. Review the System Logs

The first thing I looked for was evidence of the reboot itself.

The logs repeatedly contained messages similar to:

```text
System has reset without management command
Image 1 F/W version V4.50(AAOA.2) boot up
```

That confirmed the switch was restarting on its own rather than someone manually rebooting it.

Immediately after each reboot, the logs also showed the PoE ports reinitializing, which is expected after a restart.

---

### 2. Look for Patterns

The next thing that stood out was not the reboot.

It was this.

```text
Port 8 link up
Port 8 link down
Port 8 link up
Port 8 link down
...
```

Not once or twice.

Hundreds of times.

A port that constantly transitions between link up and link down usually points toward one of these possibilities:

* Faulty cable
* Bad network interface
* Device repeatedly rebooting
* Physical network loop
* Electrical issue

At this point there was no proof which one it was, but it was clearly worth investigating.

---

### 3. Check Spanning Tree

One question became important:

"Is Spanning Tree enabled?"

The answer was no.

With Spanning Tree disabled, a physical loop can create a broadcast storm that overwhelms the switch. Depending on the platform, this can lead to extremely high CPU utilization, network instability, or even watchdog resets.

That made enabling Rapid Spanning Tree Protocol (RSTP) the safest next troubleshooting step.

---

### 4. Enable RSTP

After enabling RSTP, the switch immediately began participating in loop prevention.

One interesting observation appeared in the interface status.

Port 7 entered a **BLOCKING** state while nearly every other interface remained in **FORWARDING**.

At first glance, seeing a blocked port can look alarming.

In reality, this is exactly what Spanning Tree is supposed to do.

It detected two possible forwarding paths and intentionally blocked one to prevent a Layer 2 loop.

---

## What the Evidence Showed

After enabling RSTP, two things happened almost immediately.

First, the spontaneous reboots stopped.

Second, the endless Port 8 link up/link down messages disappeared.

While this does not absolutely prove that a Layer 2 loop caused every reboot, it is very strong evidence that network topology played a major role.

There was still one unknown.

Nobody knew where Port 8 physically terminated.

The client agreed to trace that cable while I continued monitoring the switch.

Because the symptoms disappeared after enabling RSTP, there was no immediate reason to make additional disruptive changes.

---

## The Root Cause

The exact physical cause was never definitively proven because the far end of Port 8 had not yet been identified.

However, the evidence strongly supported the following sequence:

1. A Layer 2 loop or unstable connection existed on or beyond Port 8.
2. Spanning Tree was disabled, allowing the condition to impact switching.
3. The switch repeatedly experienced instability severe enough to restart itself.
4. After RSTP was enabled, the switch detected the redundant path and prevented the loop.
5. Stability returned immediately.

Another observation was that the switch was still running firmware released in 2018.

Although updating firmware is generally recommended, the client chose not to perform an upgrade during this troubleshooting session. Since the issue appeared resolved after enabling RSTP, I left the firmware unchanged and documented it as a future recommendation.

---

## Key Takeaways

* Always review logs before assuming hardware failure.
* Repeated "System has reset without management command" confirms an unexpected reboot but does not explain why.
* Constant link flapping on a single port is often more valuable than the reboot messages themselves.
* A BLOCKING port is not necessarily a problem. It often means Spanning Tree is successfully preventing a network loop.
* Do not disable Spanning Tree without understanding the consequences.
* An outdated firmware version should be documented, but do not assume it is the root cause simply because it is old.
* When the symptoms stop after a configuration change, continue monitoring before introducing additional changes.

---

## Summary

**Symptom**

A managed switch repeatedly rebooted itself while one interface generated constant link up/link down events.

**Investigation**

Reviewed system logs, identified spontaneous resets, observed persistent Port 8 flapping, verified Spanning Tree was disabled, and enabled Rapid Spanning Tree Protocol.

**Root Cause**

Most likely a Layer 2 loop or unstable network path that became disruptive because Spanning Tree was not active. The exact physical source remained under investigation.

**Resolution**

Enabled RSTP, which immediately stabilized the switch. Port 7 entered a BLOCKING state as expected, Port 8 stopped flapping, spontaneous reboots ceased, and the client elected to monitor the environment before performing a firmware upgrade.

One final reminder: a BLOCKING port is often evidence that your network is protecting itself, not that something is broken. Before disabling STP or forcing a blocked port to forward, trace the cable, identify where it terminates, and remember that the real problem may be the loop you have not found yet.
