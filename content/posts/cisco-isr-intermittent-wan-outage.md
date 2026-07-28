+++
title = "Chasing an Intermittent WAN Outage on a Cisco ISR"
slug = "cisco-isr-intermittent-wan-outage"
date = "2026-07-28"
author = "RoninSec"
cover = "/img/cisco-isr-intermittent-wan-outage-banner.png"
tags = ["cisco", "networking", "troubleshooting", "ios-xe", "eem"]
keywords = ["cisco isr", "wan outage", "cpe mac lock", "event manager", "nat troubleshooting", "arp cache", "ios xe"]
description = "A methodical investigation into an intermittent Cisco ISR internet outage that ultimately pointed toward an ISP-side CPE MAC lock."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Chasing an Intermittent WAN Outage on a Cisco ISR

Sometimes the hardest network problems are the ones that fix themselves after a reboot.

I recently worked through an intermittent internet outage on a Cisco ISR router where every reboot bought several more hours of uptime before the problem returned. Nothing obvious was overloaded, the WAN interface stayed up, and users simply lost internet access.

This wasn't a story about finding a smoking gun. It was a story about eliminating possibilities until one theory became much more likely than the others.

---

## The Symptom

The environment would operate normally for hours before internet connectivity suddenly stopped.

The interesting part was that:

* The WAN interface remained up.
* Internal clients could still communicate locally.
* Rebooting network equipment restored service.
* The problem returned later.

That immediately ruled out a complete hardware failure and suggested either stale state somewhere in the forwarding path or an upstream issue.

Possible causes included:

1. NAT exhaustion
2. ARP cache problems
3. Memory leaks
4. High CPU utilization
5. ISP modem behavior
6. Software defects

Rather than guessing, I started collecting evidence.

---

## The Investigation

### 1. Verify router health

The first step was making sure the router itself was healthy.

```bash
show version
show processes cpu sorted
show processes memory sorted
```

CPU utilization remained around 1 to 2 percent.

Memory usage was healthy with plenty of free RAM and no obvious process continually increasing its memory footprint.

At this point, the router itself did not appear to be under stress.

---

### 2. Verify ARP and NAT state

Next I confirmed the router was maintaining normal Layer 3 neighbor information.

```bash
show ip arp
show ip nat translations
```

The WAN gateway continued to resolve correctly through ARP.

There was no evidence that the NAT table was overflowing or becoming excessively large.

Neither of these checks proved they were innocent, but nothing immediately suggested they were responsible.

---

### 3. Review DHCP behavior

While reviewing logs I noticed multiple DHCP conflict messages similar to:

```text
%DHCPD-4-PING_CONFLICT
```

This indicated the DHCP server detected addresses already in use before attempting to lease them.

The likely explanation was several statically addressed devices living inside the DHCP pool.

Although this was not likely causing the WAN outage, it was still worth cleaning up by excluding those addresses from DHCP.

---

### 4. Enable continuous monitoring

Intermittent problems are frustrating because they disappear before you can observe them.

Instead of waiting for another outage, I configured Cisco Embedded Event Manager (EEM) applets to collect hourly snapshots.

The applets logged:

* NAT translations
* ARP table
* CPU utilization
* Memory utilization

They also periodically tested WAN reachability.

Useful verification commands included:

```bash
show event manager policy registered
show run | section event manager
show logging
```

This created a baseline so I could compare healthy operation against future failures.

---

## A Small Roadblock

One unexpected challenge came while writing the EEM policy.

I initially attempted to use string matching with the `contains` keyword against the ping output.

That failed because this IOS-XE release only supported numeric comparison operators inside EEM conditionals.

The workaround was using a regular expression instead.

```text
regexp "0 percent" "$_cli_result" result
```

From there, the policy could test whether the regular expression matched before taking action.

Another syntax issue appeared because an `end` statement accidentally existed outside the conditional block, causing EEM validation errors until the action ordering was corrected.

These little IOS quirks are exactly why I always verify an applet after writing it instead of assuming it loaded correctly.

---

## What the Evidence Showed

After leaving the monitoring in place overnight, several things became clear.

The hourly logging continued exactly as expected.

CPU remained stable.

Memory remained stable.

No unexpected interface flaps occurred.

The router continued operating normally.

More importantly, there was no evidence suggesting:

* runaway CPU
* memory exhaustion
* excessive NAT growth
* abnormal ARP behavior

The longer the monitoring ran without exposing an internal router issue, the more attention shifted toward the upstream modem.

---

## The Most Likely Root Cause

Although I cannot say this was conclusively proven, the strongest remaining explanation became an ISP-side CPE MAC lock.

CPE stands for Customer Premises Equipment.

Many cable providers associate service with the MAC address of the first device connected to the modem. If the modem's ARP or MAC state becomes stale, or if the modem fails to relearn the connected device correctly, the router may continue believing everything is healthy while traffic silently stops flowing.

That explains several observations:

* The WAN interface never actually failed.
* Rebooting restored service.
* The router itself showed no resource problems.

A complete modem power cycle forces the modem to forget the previous MAC association and learn the router again.

That behavior matched what I was seeing much better than any internal router failure.

---

## Correct Reboot Procedure

If I suspect a MAC lock, I now follow this order:

1. Power off the modem.
2. Wait approximately 60 to 120 seconds.
3. Reboot the router.
4. Power the modem back on.
5. Wait for the modem to fully synchronize.
6. Allow the router to establish the WAN connection.

This helps ensure the modem learns the router's WAN MAC cleanly.

---

## Key Takeaways

* Do not assume a reboot proves the router was the problem.
* Baseline CPU and memory before chasing obscure bugs.
* Continuous logging is often more valuable than staring at a healthy system.
* DHCP conflicts should be cleaned up even if they are unrelated.
* Verify EEM policies after creating them.
* Consider the ISP modem whenever the WAN stays up but traffic disappears.
* Eliminate possibilities methodically instead of jumping straight to firmware upgrades.

---

## Summary

**Symptom**

Intermittent loss of internet connectivity despite healthy router interfaces.

**Investigation**

Reviewed CPU, memory, ARP, NAT, DHCP logs, and implemented Cisco EEM monitoring to capture hourly operational snapshots.

**Root Cause**

Not definitively proven, but evidence strongly suggested an ISP-side CPE MAC lock rather than a router resource issue.

**Resolution**

Implemented continuous monitoring, planned DHCP cleanup, established a proper modem and router reboot sequence, and identified the ISP modem as the primary focus if the outage returns.

Sometimes the best troubleshooting tool is patience, because logs remember what reboots conveniently erase.
