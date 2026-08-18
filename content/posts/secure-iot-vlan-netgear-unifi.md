+++
title = "Designing A Secure IoT VLAN With A Netgear Access Point And UniFi Gateway"
slug = "secure-iot-vlan-netgear-unifi"
date = "2026-08-18"
author = "RoninSec"
cover = "/img/secure-iot-vlan-netgear-unifi-banner.png"
tags = ["networking", "vlan", "iot-security", "unifi", "wireless"]
keywords = ["iot vlan", "netgear wap", "unifi udm", "wireless security", "vlan tagging", "geo ip blocking", "network segmentation"]
description = "A practical walkthrough of securely segmenting IoT devices with VLANs, avoiding management lockouts, and hardening a wireless network."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Designing A Secure IoT VLAN With A Netgear Access Point And UniFi Gateway

One of my favorite networking lessons is that not every outage starts with something broken. Sometimes it starts with the thought, "If I click Apply, am I about to lock myself out?"

That was exactly the situation while configuring a dedicated IoT wireless network using a standalone wireless access point connected to a UniFi gateway. The goal was simple: isolate Internet of Things (IoT) devices onto their own VLAN without accidentally losing management access to the access point.

Fortunately, this turned into one of those projects where understanding the "why" behind each setting was far more valuable than simply copying someone else's configuration.

---

## The Symptom

The objective was to build a dedicated wireless network for IoT devices.

The environment looked roughly like this:

* Default LAN: 192.168.120.0/24
* IoT VLAN: VLAN 10
* IoT subnet: 192.168.11.0/24
* UniFi gateway performing routing and DHCP
* Standalone wireless access point broadcasting the wireless networks

The biggest concern was this question:

> If I change the SSID's VLAN from 1 to 10, will I immediately lose access to the management interface?

Anyone who has accidentally changed the management VLAN on a switch or access point knows why this question matters.

---

## Investigation

### 1. Verify the VLAN Exists

Before touching the access point, I confirmed the gateway already had VLAN 10 configured with its own subnet and DHCP scope.

This ensures wireless clients have somewhere to obtain an address after tagging traffic.

---

### 2. Understand The Difference Between Client VLANs And Management VLANs

This turned out to be the most important lesson of the entire project.

The SSID configuration contained a simple field:

* VLAN ID: 1

Changing this field does **not** move the management interface of the access point.

Instead, it tells the access point:

> "Tag all wireless client traffic for this SSID with VLAN 10."

The management interface remains wherever it was previously configured unless the management VLAN itself is changed elsewhere.

That distinction is huge.

Changing the SSID VLAN is generally safe.

Changing the management VLAN can absolutely disconnect you if your workstation is no longer on the correct network.

---

### 3. Review Advanced Wireless Settings

Rather than accepting defaults blindly, I walked through each advanced option to understand what it actually does.

For an IoT-only SSID, the following configuration made sense:

| Setting                  | Recommended Value | Reason                                               |
| ------------------------ | ----------------- | ---------------------------------------------------- |
| MU-MIMO                  | Enabled           | Better performance with multiple clients             |
| RTS Threshold            | 2346              | Leave default unless troubleshooting collisions      |
| DTIM Interval            | 2                 | Good balance between responsiveness and battery life |
| Beacon Interval          | 100 ms            | Reliable client discovery                            |
| Broadcast Rate Limiting  | Enabled           | Reduces unnecessary broadcast traffic                |
| Load Balancing           | Disabled          | Only one AP serves this network                      |
| Sticky Client Disconnect | Disabled          | Avoid unnecessary reconnects                         |
| ARP Proxy                | Enabled           | Reduces broadcast ARP traffic                        |

None of these settings magically improve security, but together they create a cleaner and more efficient wireless network for devices that rarely need high throughput.

---

### 4. Configure Geo-IP Blocking

Since the gateway also supported regional firewall blocking, I decided to add another layer of defense.

The configuration was straightforward:

* Action: Block
* Direction: All directions

Countries were selected based on organizational needs rather than trying to block the entire Internet.

This is not a replacement for proper firewall rules or intrusion prevention.

It simply removes a large amount of unnecessary traffic from locations where legitimate communication is not expected.

---

## What The Evidence Showed

The biggest takeaway was that the access point separates two very different concepts:

* Client VLAN tagging
* Management networking

Changing the SSID VLAN only affects wireless clients joining that SSID.

Changing the management VLAN changes how administrators reach the device itself.

Understanding that distinction eliminated the fear of clicking Apply.

The project also reinforced that many "advanced" wireless settings are really optimization settings rather than security settings.

Knowing what they do makes future troubleshooting much easier.

---

## Root Cause

There was never actually a networking fault.

The real issue was uncertainty about how VLAN tagging was implemented on the access point.

Without understanding the difference between client traffic and management traffic, it is very easy to assume that changing a VLAN setting will immediately disconnect the administrator.

In this case, that assumption would have been incorrect.

---

## Key Takeaways

* Separate IoT devices onto their own VLAN whenever possible.
* Always distinguish between an SSID VLAN and a management VLAN.
* Verify DHCP exists for the target VLAN before moving clients.
* Review advanced wireless settings instead of blindly accepting defaults.
* Geo-IP blocking is a useful supplemental control, not a primary security control.
* Broadcast reduction and ARP optimization can improve noisy IoT environments.
* Understand what each setting does before changing it.

---

## Summary

**Symptom**

Needed to move IoT devices onto their own VLAN while avoiding accidental loss of access to the wireless access point.

**Investigation**

Reviewed VLAN configuration, analyzed advanced wireless settings, confirmed the purpose of SSID VLAN tagging versus management networking, and implemented additional gateway hardening through Geo-IP blocking.

**Root Cause**

The concern stemmed from confusing wireless client VLAN tagging with the access point's management VLAN.

**Resolution**

Configured the SSID to use VLAN 10 for client traffic while leaving management networking unchanged, optimized wireless settings for IoT devices, and enabled regional blocking as an additional security layer.

Because nothing says "I understand VLANs now" quite like confidently clicking Apply after realizing the only thing changing was the clients, not the device managing them. And yes, the biggest gotcha was discovering that "VLAN ID" does not always mean "the VLAN you are currently standing on."
