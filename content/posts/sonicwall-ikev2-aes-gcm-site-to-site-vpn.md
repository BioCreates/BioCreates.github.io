+++
title = "Troubleshooting A SonicWall Site-To-Site VPN For IKEv2 And AES-GCM"
slug = "sonicwall-ikev2-aes-gcm-site-to-site-vpn"
date = "2026-08-19"
author = "RoninSec"
cover = "/img/sonicwall-ikev2-aes-gcm-site-to-site-vpn-banner.png"
tags = ["sonicwall", "ipsec-vpn", "ikev2", "aes-gcm", "networking"]
keywords = ["sonicwall vpn", "ikev2", "aes-256-gcm", "ipsec site-to-site", "perfect forward secrecy", "dh group 14", "vpn troubleshooting"]
description = "A practical walkthrough of validating a SonicWall site-to-site VPN against modern IKEv2, AES-GCM, PFS, and subnet requirements."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Troubleshooting A SonicWall Site-To-Site VPN For IKEv2 And AES-GCM

I recently needed to prepare a SonicWall for a new site-to-site IPsec VPN. At first glance, the job looked easy because a site-to-site policy already existed.

Then I compared the existing proposal against the requirements.

IKEv1. SHA-1. DH Group 2.

Yeah, this was not going to be a copy-and-paste job.

What followed was a useful exercise in reading VPN proposals, understanding SonicWall's terminology, determining what the firewall actually supported, and figuring out exactly which networks belonged in the tunnel before changing anything.

---

## The Symptom

The remote organization required approximately the following VPN parameters:

* IKEv2
* AES-256-GCM
* Diffie-Hellman Group 14
* Perfect Forward Secrecy using Group 14
* 28,800-second lifetimes
* Keep Alive or Dead Peer Detection
* Specific local and remote Phase 2 networks

An existing SonicWall site-to-site policy appeared to use:

```text
Exchange: Main Mode
Encryption: AES-256
Authentication: SHA-1
DH Group: Group 2
```

"Main Mode" was the first major clue. That indicated an IKEv1-style configuration rather than the requested IKEv2 proposal.

Even though both configurations contained the words "AES-256," they were not equivalent.

---

## The Investigation

### 1. I Compared The Existing Proposal To The Requirements

The existing tunnel was effectively using separate encryption and integrity algorithms:

```text
AES-256 + SHA-1
```

The requested configuration used:

```text
AES-256-GCM
```

Galois/Counter Mode, or GCM, is an authenticated encryption mode. It provides confidentiality and integrity together rather than pairing AES-CBC encryption with a separate hash such as SHA-1.

The existing DH Group 2 also failed the requirement for Group 14.

So rather than modifying values blindly, I needed to determine whether the firewall supported the requested configuration at all.

### 2. I Verified The Firewall Platform

The appliance turned out to be a modern SonicWall TZ-series Gen 7 firewall running SonicOS 7.

That was important because it ruled out my initial concern that the appliance might simply be too old for the requested cryptography.

This became the first troubleshooting roadblock: the interface initially made it look like AES-GCM was unavailable.

It was not unavailable. I was looking in the wrong context.

### 3. I Found SonicWall's GCM Naming

While reviewing the IKEv2 proposal options, I found entries similar to:

```text
AESGCM16-128
AESGCM16-192
AESGCM16-256
```

The required choice was:

```text
AESGCM16-256
```

The "16" initially looked suspicious. Was this some different variant than the vendor's generic "AES-256-GCM" requirement?

No.

The 16 refers to the 16-byte, or 128-bit, authentication tag. The 256 refers to the AES key size.

So:

```text
AESGCM16-256
```

is SonicWall's representation of AES-256-GCM using a 128-bit authentication tag.

That was the cipher I needed.

### 4. I Verified PFS

Another potential gotcha was Perfect Forward Secrecy.

I originally expected a completely separate PFS configuration area, but SonicWall exposes an "Enable Perfect Forward Secrecy" option as part of the IPsec proposal.

For this tunnel, the intended Phase 2 configuration would therefore use:

```text
Protocol: ESP
Encryption: AESGCM16-256
PFS: Enabled
PFS Group: DH Group 14
Lifetime: 28800 seconds
```

Phase 1 would similarly use IKEv2, AES-256-GCM, DH Group 14, and the required lifetime.

### 5. I Verified The Public Peer Address

The remote organization also needed our public IP.

Rather than assuming the externally visible address, I checked the SonicWall's WAN interface and confirmed that a public address was statically assigned directly to it.

For documentation purposes, I will represent it as:

```text
203.0.113.25
```

The important lesson is that "What is my public IP?" and "What address should the IPsec peer use?" are not always automatically the same question.

If a firewall sits behind another NAT device, the address configured on its WAN interface may be private. For this deployment, the WAN interface itself held the public address, so it was appropriate to provide as the VPN peer.

---

## What The Evidence Showed

At this point I knew the firewall could support the requested cryptography.

The expected configuration became:

```text
IKE Version: IKEv2
Phase 1 Encryption: AESGCM16-256
Phase 1 DH Group: 14
Phase 1 Lifetime: 28800

Phase 2 Protocol: ESP
Phase 2 Encryption: AESGCM16-256
PFS: Enabled
PFS Group: 14
Phase 2 Lifetime: 28800

Keep Alive / DPD: Enabled
```

But I intentionally did not configure the tunnel yet.

The remote side still needed information from us, and we needed their peer address, remote network, and pre-shared key before completing the build.

There was another question to resolve first: subnet scope.

---

## The Subnet Gotcha

The firewall had several networks behind it. I will use sanitized examples:

```text
Primary LAN:       10.50.10.0/24
Voice VLAN:        192.168.50.0/24
Remote VPN Pool:   10.60.20.0/24
```

The primary LAN was the obvious candidate for the site-to-site tunnel.

The voice VLAN probably was not. There was no reason to expose VoIP devices to the remote environment simply because that subnet existed.

The remote-access VPN pool was more interesting.

If a remote employee connects to the SonicWall and receives something like:

```text
10.60.20.3
```

that does not automatically mean `10.60.20.0/24` belongs in the site-to-site VPN.

The actual question is:

"Do remote-access VPN users need to reach resources across this site-to-site tunnel?"

If no, leave the pool out.

If yes, the VPN client network may need to participate in the Phase 2 selectors, routing, and access rules on both sides.

This distinction matters because VPN design should follow required traffic flows, not simply include every subnet visible on the firewall.

---

## The Root Cause

There was not a broken tunnel yet.

The real problem was a configuration mismatch between an existing legacy VPN policy and the security requirements for a new connection.

The existing policy used older parameters, while the new tunnel required IKEv2, AES-256-GCM, DH14, and PFS.

A secondary source of confusion was SonicWall's UI and terminology. AES-256-GCM appeared as `AESGCM16-256`, and the relevant algorithms became clearer while examining the IKEv2 proposal options.

The lesson was simple: never assume a firewall lacks a feature because it is missing from the first dropdown you open.

---

## Key Takeaways

* "AES-256" and "AES-256-GCM" are not interchangeable.
* SonicWall may display AES-256-GCM as `AESGCM16-256`.
* Main Mode is a strong clue that an existing policy is using IKEv1.
* DH Group must match between peers.
* PFS applies to the Phase 2/IPsec security association and must match the remote peer's expectations.
* Verify hardware and SonicOS capabilities before recommending upgrades or replacement.
* Confirm the actual WAN configuration before providing a VPN peer address.
* Do not automatically add every VLAN to Phase 2.
* Remote-access VPN pools only need inclusion when those clients must traverse the site-to-site tunnel.
* Gathering both sides' parameters before configuring anything avoids unnecessary troubleshooting later.

---

## Summary

**Symptom:**
An existing SonicWall site-to-site policy did not appear to meet a new partner's IKEv2 and AES-256-GCM requirements.

**Investigation:**
I compared the existing proposal, verified the firewall platform and firmware, located SonicWall's AES-GCM proposal naming, confirmed PFS support, checked the WAN peer address, and reviewed which internal networks actually needed access.

**Root Cause:**
The existing VPN used legacy IKEv1-era parameters and was not suitable as-is for the new tunnel. SonicWall's naming and UI also made the required AES-GCM capability less obvious initially.

**Resolution:**
I confirmed the firewall supported the required IKEv2, `AESGCM16-256`, DH14, PFS14, 28,800-second lifetime, and keep-alive configuration. Rather than prematurely changing the firewall, I provided the necessary peer and subnet information and waited for the remote side's public IP, network selectors, and PSK before completing the tunnel.

Sometimes the hardest part of building a VPN is not encrypting the traffic - it is decrypting the dropdown menus.
