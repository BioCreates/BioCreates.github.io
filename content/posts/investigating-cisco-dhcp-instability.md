+++
title = "Investigating Suspected DHCP Instability on a Cisco Router and Switch"
slug = "investigating-cisco-dhcp-instability"
date = "2026-08-01"
author = "RoninSec"
cover = "/img/investigating-cisco-dhcp-instability-banner.png"
tags = ["cisco", "dhcp", "network-troubleshooting", "switching", "routing"]
keywords = ["cisco dhcp", "isr router", "cisco 3750", "dhcp troubleshooting", "dot1q trunk", "show ip dhcp", "network diagnostics"]
description = "A methodical investigation into suspected DHCP instability that turned into a lesson on validating assumptions before chasing the wrong problem."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Investigating Suspected DHCP Instability on a Cisco Router and Switch

Sometimes the most valuable troubleshooting session is the one where you do not find the problem you expected.

I started this session convinced that DHCP was the culprit because users were reportedly changing IP addresses. By the end, I had confirmed the router was serving DHCP correctly, verified the switch and router trunk configuration, corrected a boot configuration mistake, and narrowed the investigation considerably.

No dramatic fix. No magical command. Just good troubleshooting.

---

## The Symptom

Users appeared to be changing IP addresses unexpectedly, so DHCP became the primary suspect.

Before diving into packet captures or replacing hardware, I wanted to answer a simple question:

**Is DHCP actually misbehaving?**

While reviewing the environment, I also took the opportunity to verify the router's IOS image after recently transferring it over TFTP.

---

## Step 1 - Verify the Router Image

After transferring the IOS image, I checked the flash storage.

```bash
dir bootflash:
```

The expected ISR image was present.

I then attempted to verify the image but immediately ran into an unexpected error because I referenced the wrong filename.

```bash
verify /md5 flash:c1900-universalk9.bin
```

Result:

```text
Permission denied
```

At first glance this looked like a permissions problem.

It wasn't.

The router simply did not have that file. I had accidentally referenced an old 1900-series image name instead of the ISR4200 image that was actually stored in bootflash.

Lesson learned: always verify the filename before assuming the error message is telling the whole story.

I corrected the boot variable:

```bash
configure terminal
no boot system
boot system flash:isr4200-universalk9_ias.17.03.04a.SPA.bin
end
write memory
```

That confirmed the router would boot the proper image during the next reload.

---

## Step 2 - Review the Switch Configuration

The switch configuration was fairly minimal.

The important interface looked like this:

```bash
interface GigabitEthernet1/0/24
 description Connection to Router
 switchport trunk encapsulation dot1q
 switchport mode trunk
```

Initially I questioned whether this was actually the router uplink.

Rather than trusting an interface description, I compared it against the router configuration.

The router LAN interface was configured as:

```bash
interface GigabitEthernet0/0/0.1
 encapsulation dot1Q 1 native
 ip address 192.168.120.1 255.255.255.0
```

This was the confirmation I needed.

The router expected an 802.1Q trunk carrying native VLAN 1, and the switch port was configured exactly that way.

Sometimes the configuration itself answers the question better than documentation ever could.

---

## Step 3 - Investigate DHCP

The DHCP configuration looked straightforward.

```bash
show run | section dhcp
```

Output included:

```text
Excluded:
192.168.120.1-9
192.168.120.200-254

Pool:
192.168.120.0/24
Gateway: 192.168.120.1
DNS:
8.8.8.8
9.9.9.9
```

Nothing immediately stood out.

Next I checked the pool itself.

```bash
show ip dhcp pool LAN
```

Interesting results:

* 254 total addresses
* 70 excluded
* Only 1 leased address

At first this looked suspicious.

Then I remembered something important.

A low lease count does **not** automatically mean DHCP is broken.

It may simply mean:

* most devices are statically addressed
* devices are offline
* the environment is much smaller than expected

Evidence matters more than assumptions.

---

## Step 4 - Verify From the Client

Rather than staring at router output, I checked an actual workstation.

```cmd
ipconfig /all
```

The results answered several questions immediately.

The client had:

* a valid address
* the expected subnet
* the correct default gateway
* the correct DNS servers
* a 24-hour lease
* the router listed as the DHCP server

That eliminated several possibilities.

There was no evidence that:

* another DHCP server was handing out leases
* lease duration was unusually short
* the client was bouncing between DHCP servers

In other words, DHCP looked healthy from both ends.

---

## What the Evidence Actually Showed

By the end of the investigation I had verified:

* The router was serving DHCP correctly.
* The client received its lease from the expected DHCP server.
* Lease duration was normal.
* DNS settings matched the router configuration.
* The switch trunk matched the router subinterface configuration.
* The router boot configuration referenced the correct IOS image.

What I **did not** prove was that DHCP caused users to receive different IP addresses.

That distinction matters.

It is incredibly easy to become attached to your first theory and ignore evidence that contradicts it.

---

## Root Cause

No definitive DHCP issue was identified during this investigation.

Instead, the session revealed that my original hypothesis was unsupported by the available evidence.

The environment appeared to have:

* healthy DHCP configuration
* healthy client lease behavior
* correctly configured trunking
* properly configured router interfaces

If users continue reporting address changes, the next investigation should focus on:

1. Static devices.
2. MAC address changes.
3. Wireless roaming.
4. Port flapping.
5. Rogue devices connected intermittently.
6. Switch MAC address learning and interface events.

Those areas are now much more likely than the DHCP server itself.

---

## Key Takeaways

* Verify assumptions before troubleshooting.
* Compare router and switch configurations together.
* Do not trust interface descriptions without confirming them.
* "Permission denied" is not always a permissions problem.
* A DHCP server issuing very few leases is not automatically broken.
* Client-side validation is just as important as router diagnostics.
* Evidence should drive the investigation, not the initial hypothesis.

---

## Summary

**Symptom**

Users appeared to be changing IP addresses unexpectedly.

**Investigation**

Verified the IOS image, corrected the boot variable, reviewed switch trunking, validated DHCP configuration, inspected the DHCP pool, and confirmed client lease information.

**Root Cause**

No evidence supported DHCP instability. The investigation ruled out the DHCP server as the immediate cause.

**Resolution**

Confirmed the router and switch were configured correctly, validated DHCP operation, corrected the boot configuration, and established a clearer direction for future troubleshooting.

Because nothing says "network engineering" quite like spending an hour chasing DHCP only to discover the real bug was your assumption... and an incorrect filename thrown in for good measure.
