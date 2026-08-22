+++
title = "Troubleshooting Enterprise Wi-Fi: When It Wasn't DHCP After All"
slug = "troubleshooting-enterprise-wifi-not-dhcp"
date = "2026-08-22"
author = "RoninSec"
cover = "/img/troubleshooting-enterprise-wifi-not-dhcp-banner.png"
tags = ["wireless-networking", "troubleshooting", "dhcp", "network-analysis", "wifi", "enterprise-it"]
keywords = ["wifi troubleshooting", "dhcp scope", "tx retries", "wireless interference", "enterprise wifi", "network diagnostics", "access point channels"]
description = "A methodical walkthrough of diagnosing slow enterprise Wi-Fi by separating DHCP concerns from wireless interference using real troubleshooting evidence."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Troubleshooting Enterprise Wi-Fi: When It Wasn't DHCP After All

Sometimes the hardest part of troubleshooting is ignoring the first assumption.

A client reported slow wireless performance, users randomly losing connectivity, and messages such as "Connected, no internet." One wired user had also briefly lost connectivity, which made the problem look much bigger than just Wi-Fi.

My first instinct was not to start changing settings. Instead, I wanted evidence.

---

## The Symptom

The client reported several complaints from wireless users:

* Very slow internet performance.
* Random disconnects.
* "Connected, no internet."
* "Can't connect to this network."

One wired workstation had also disconnected briefly, adding uncertainty about whether this was a wireless-only issue or a broader network problem.

An initial speed test from a wireless client was alarming:

* Download: approximately 0.02 Mbps
* Upload: approximately 1.78 Mbps

The environment consisted of:

* Multiple enterprise wireless access points.
* A firewall acting as the primary gateway.
* Windows DHCP.

At this point, several possibilities existed:

1. DHCP exhaustion.
2. DNS failures.
3. Firewall or routing issues.
4. Wireless interference.
5. Hardware failures.

---

## The Investigation

### 1. Verify Access Point Health

The first stop was the wireless controller.

The access points were:

* Online.
* Running current firmware.
* Showing stable uptime measured in months.
* Connected at gigabit speeds.
* Operating with low CPU and memory utilization.

Nothing suggested failing hardware.

However, one metric immediately stood out.

Several access points showed unusually high TX Retry percentages.

* Approximately 28 percent on one AP.
* Approximately 37 percent on another AP.

Generally speaking, I like to see TX retries well below 10 percent.

High retry rates indicate that wireless frames are not successfully reaching their destination on the first attempt. Every retry means additional airtime, more congestion, and slower user experience.

---

### 2. Examine Channel Assignments

Next I reviewed channel utilization.

The surprise?

Multiple access points were operating on the same 2.4 GHz channel.

Although the deployment used multiple radios, the overlapping channels meant the access points were effectively competing with each other.

A better layout would have been:

* AP 1 -> Channel 1
* AP 2 -> Channel 6
* AP 3 -> Channel 11

Using the three non-overlapping channels minimizes self-interference in the 2.4 GHz spectrum.

One important operational consideration:

Changing wireless channels causes connected clients to disconnect briefly while the radio reconfigures. Most devices reconnect automatically within several seconds, but production environments should schedule these changes during low-usage periods.

---

### 3. Verify DHCP

Because users reported losing connectivity, DHCP was the next suspect.

I reviewed:

* DHCP scope.
* Address exclusions.
* Reservations.
* Active leases.

The scope still contained plenty of available addresses.

There was no evidence of address exhaustion.

Some reservations were inactive, but inactive reservations are normal and do not consume active leases.

This was an important finding because DHCP is frequently blamed for connectivity problems even when it is functioning perfectly.

---

### 4. Consider Firewall and DNS

At this point, DHCP looked healthy.

The remaining possibilities included:

* DNS delays.
* Firewall bottlenecks.
* Routing issues.
* Wireless congestion.

Without corresponding firewall logs showing packet drops or excessive resource utilization, there was not enough evidence to conclude the firewall was responsible.

That is an important distinction.

Good troubleshooting separates possibilities from proven facts.

---

## Useful Commands

When troubleshooting similar environments, I like to gather a baseline from affected clients.

Check IP configuration:

```cmd
ipconfig /all
```

Test gateway reachability:

```cmd
ping <DEFAULT-GATEWAY>
```

Test raw internet connectivity:

```cmd
ping 8.8.8.8
```

Test DNS resolution:

```cmd
nslookup google.com
```

These simple tests quickly separate:

* DHCP issues.
* Routing issues.
* DNS failures.
* Internet connectivity problems.

---

## What the Evidence Showed

Several observations became clear during the investigation.

The wireless infrastructure itself remained online and healthy.

The DHCP server had available addresses and showed no evidence of exhaustion.

The largest red flag was consistently elevated TX Retry percentages across multiple access points.

Combined with overlapping 2.4 GHz channels, this strongly suggested wireless interference rather than DHCP failure.

One interesting twist was the single wired user reporting a disconnect.

While this initially widened the investigation, there was not enough supporting evidence to conclude the wired event shared the same root cause. It may have been unrelated or simply coincidental.

That uncertainty is worth documenting rather than forcing a conclusion.

---

## The Root Cause

The investigation pointed toward wireless interference as the primary contributor.

Specifically:

* High TX Retry percentages.
* Channel overlap on the 2.4 GHz radios.
* Otherwise healthy access point hardware.
* Healthy DHCP scope.
* No evidence proving firewall failure.

While DNS and firewall performance remained items worth validating, neither had enough supporting evidence to become the primary diagnosis.

---

## Gotchas Encountered

Several aspects of this case could have easily sent the investigation down the wrong path.

* A single wired user made the issue appear larger than it ultimately seemed.
* Extremely slow speed tests naturally encourage blaming the ISP, but there was no supporting evidence.
* DHCP is often the first suspect, yet the lease pool was healthy.
* Healthy signal strength does not guarantee healthy wireless performance. High TX retries can exist even when signal levels appear acceptable.
* Making channel changes during business hours can briefly disconnect users, so timing matters.

---

## Key Takeaways

* Never assume DHCP is the problem until you verify the scope.
* High TX Retry percentages deserve immediate attention.
* Healthy signal strength does not rule out wireless interference.
* Check channel assignments before replacing hardware.
* Separate confirmed evidence from reasonable suspicion.
* Document what was ruled out just as carefully as what was confirmed.

---

## Summary

**Symptom**

Users experienced slow Wi-Fi, intermittent disconnects, and "Connected, no internet" messages.

**Investigation**

Reviewed access point health, wireless performance metrics, DHCP leases, channel assignments, and considered firewall and DNS involvement.

**Root Cause**

Evidence strongly indicated wireless interference caused by channel overlap and elevated TX retries. DHCP exhaustion was ruled out.

**Resolution**

Recommend redistributing access points across non-overlapping 2.4 GHz channels, encouraging 5 GHz usage where possible, validating DNS responsiveness, and continuing firewall monitoring if symptoms persist.

Troubleshooting is a lot like detective work: the loudest suspect is rarely the guilty one, but the packet traces never lie.
