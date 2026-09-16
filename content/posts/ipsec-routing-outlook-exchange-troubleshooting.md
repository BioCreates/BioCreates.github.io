+++
title = "Troubleshooting IPSec Routing and Outlook Exchange Issues in the Real World"
slug = "ipsec-routing-outlook-exchange-troubleshooting"
date = "2026-09-16"
author = "RoninSec"
cover = "/img/ipsec-routing-outlook-exchange-troubleshooting-banner.png"
tags = ["ipsec", "network-troubleshooting", "outlook", "exchange", "microsoft-365"]
keywords = ["ipsec tunnel", "phase 2 selectors", "outlook ost", "shared calendar", "sharepoint", "onedrive", "network routing"]
description = "A practical troubleshooting session covering IPSec traffic selectors, Outlook cache rebuilds, shared calendars, and SharePoint access."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Troubleshooting IPSec Routing and Outlook Exchange Issues in the Real World

Some support sessions stay neatly inside one technology. This was not one of them.

I went from deciphering a vague OneDrive and SharePoint request, to figuring out why a workstation could not reach a domain controller across an IPSec tunnel, to handling a few Outlook and Exchange troubleshooting tasks.

The IPSec problem was the most interesting because it demonstrated an important lesson: seeing an active VPN tunnel does not mean the traffic you care about is actually using it.

---

## The Symptom

A workstation at a remote location needed to communicate with a domain controller on another LAN through an IPSec site-to-site VPN.

The workstation was approximately:

```text
IP address:      172.16.101.154
Subnet mask:     255.255.255.0
Default gateway: 172.16.101.1
```

The destination network was:

```text
192.168.2.0/24
```

The VPN appeared to be established, but attempts to ping the domain controller received no response.

My first question was whether the workstation needed a static route.

That was a reasonable possibility, but before changing anything, I wanted to see what Windows was already doing.

---

## The Investigation

### 1. Check the workstation routing table

I started with:

```cmd
route print
```

The important entries showed a normal connected route for the workstation LAN and a default route:

```text
Network Destination    Netmask          Gateway
0.0.0.0                0.0.0.0          172.16.101.1
172.16.101.0            255.255.255.0    On-link
```

I also checked:

```cmd
ipconfig /all
```

This confirmed that the workstation was correctly using `172.16.101.1` as its default gateway.

At this point, adding a static route to Windows would have been premature.

Traffic destined for `192.168.2.0/24` does not need a workstation-specific route when the workstation's default gateway is the firewall or router responsible for the VPN. Windows can simply send the packet to its gateway.

The gateway then decides whether that packet belongs in the IPSec tunnel.

### 2. Inspect the IPSec tunnel

This was where the problem became much clearer.

The tunnel's configured networks were effectively:

```text
192.168.2.0/24 <-> 172.17.210.0/24
```

But the workstation was actually on:

```text
172.16.101.0/24
```

That is a completely different subnet.

The VPN could be green, established, and perfectly healthy while still refusing to carry this workstation's traffic.

### 3. Understand the Phase 2 mismatch

With policy-based IPSec, Phase 2 traffic selectors define which traffic should be protected by the tunnel.

The tunnel expected traffic matching:

```text
172.17.210.0/24 <-> 192.168.2.0/24
```

Our packet instead looked like:

```text
172.16.101.154 -> 192.168.2.x
```

It did not match the configured selector.

That changed the troubleshooting direction completely.

---

## What the Evidence Showed

The Windows routing table was not the primary problem.

A route such as this could technically be added:

```cmd
route add 192.168.2.0 mask 255.255.255.0 172.16.101.1 -p
```

But it would be redundant in this situation. Windows was already sending unknown destinations to `172.16.101.1` through its default route.

More importantly, adding that route would not magically make the firewall's IPSec policy accept `172.16.101.0/24`.

This is a useful troubleshooting distinction:

```text
Windows routing decides where the workstation sends the packet.

IPSec selectors decide whether the firewall puts that packet into the VPN.
```

A static route fixes the first problem, not the second.

---

## The Root Cause

The likely root cause was a Phase 2 traffic selector mismatch.

The remote workstation lived on:

```text
172.16.101.0/24
```

while the IPSec configuration referenced:

```text
172.17.210.0/24
```

The appropriate configuration therefore needed to include:

```text
172.16.101.0/24 <-> 192.168.2.0/24
```

on the relevant VPN configuration at both ends.

If `172.17.210.0/24` was legitimately used by another network, I would not blindly replace it. I would determine whether an additional Phase 2 selector was required.

That was an important gotcha. Changing a working selector without understanding why it exists could fix one location while breaking another.

I also would not consider the case fully proven until testing after the VPN configuration change. Even with correct selectors, ICMP could still fail because of firewall rules, Windows Firewall on the domain controller, NAT behavior, or a missing return path.

---

## Outlook and Exchange Side Quests

The same support session also produced a few useful Microsoft 365 notes.

To rebuild a classic Outlook Exchange cache, I can close Outlook and navigate to:

```text
%localappdata%\Microsoft\Outlook
```

Then rename the affected `.ost` file and reopen Outlook. Outlook recreates the OST and downloads the mailbox data again from Exchange.

Renaming is my preferred first move because it preserves the old file temporarily instead of immediately deleting it.

Another issue involved Shared Calendar Improvements. When troubleshooting shared-calendar synchronization, disabling the newer shared-calendar behavior can be a useful diagnostic step. The exact available toggle or policy mechanism depends on the Outlook build and organizational configuration, so I verify the supported setting before deploying registry or tenant-wide changes.

There was also a vaguely worded request to "attach" a user's OneDrive to SharePoint. The user would not even have a workstation.

The important distinction was that OneDrive does not need to be attached to SharePoint like a network drive. In this scenario, the practical requirements were more likely OneDrive provisioning, appropriate SharePoint permissions, and mobile or browser access to the required SharePoint content.

That is another support lesson worth remembering: sometimes the first troubleshooting problem is translating the ticket into what the technology actually does.

---

## Key Takeaways

* An active IPSec tunnel does not prove that a particular subnet is included in it.
* Check `route print` before adding Windows static routes.
* A normal default route to the VPN firewall is often sufficient on endpoints.
* Verify Phase 2 traffic selectors against the actual source and destination subnets.
* Always consider the return path when troubleshooting site-to-site connectivity.
* Do not replace an existing VPN selector until you know why it exists.
* An OST is a local Exchange cache and can generally be rebuilt from server-side mailbox data.
* Vague requests such as "attach OneDrive to SharePoint" should be translated into specific requirements like provisioning, permissions, and access.
* A failed ping after correcting routing does not automatically mean IPSec is still broken. ICMP filtering may be the next layer to investigate.

---

## Summary

> **Symptom:** A workstation on `172.16.101.0/24` could not reach a domain controller on `192.168.2.0/24` despite an apparently active IPSec tunnel.
>
> **Investigation:** I checked `route print` and `ipconfig /all`, verified the workstation's default gateway, and then compared the workstation subnet against the VPN's Phase 2 selectors.
>
> **Root Cause:** The VPN was configured for `172.17.210.0/24 <-> 192.168.2.0/24`, while the workstation actually lived on `172.16.101.0/24`. The evidence strongly indicated a traffic-selector mismatch rather than a missing Windows route.
>
> **Resolution:** Configure the appropriate `172.16.101.0/24 <-> 192.168.2.0/24` VPN selector on both sides as required, preserve any legitimately needed existing selectors, rekey the tunnel, and test connectivity and return routing afterward.

The tunnel was green, the route table was innocent, and Phase 2 was quietly sitting in the corner holding the smoking packet.
