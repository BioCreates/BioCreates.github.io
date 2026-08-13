+++
title = "Learning Nmap by Reading the Packets, Not Just Running the Commands"
slug = "learning-nmap-by-reading-the-packets"
date = "2026-08-13"
author = "RoninSec"
cover = "/img/learning-nmap-by-reading-the-packets-banner.png"
tags = ["nmap", "network-recon", "linux", "dns-enumeration", "packet-analysis"]
keywords = ["nmap scanning", "service enumeration", "dns version detection", "icmp ttl", "network reconnaissance", "nmap nse", "ids detection"]
description = "A practical Nmap study session covering host discovery, packet parsing, TTL clues, DNS enumeration, scan types, and IDS detection."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Learning Nmap by Reading the Packets, Not Just Running the Commands

Running Nmap is easy. Understanding what Nmap is actually doing on the wire is where the useful knowledge begins.

During one study session, I went from basic host discovery into shell pipelines, ICMP packet analysis, TTL interpretation, operating system fingerprinting, DNS version enumeration, UDP scanning, and finally an important lesson about IDS/IPS detection: slowing a scan down does not magically make it invisible.

---

## The Symptom

I understood basic commands such as:

```bash
nmap <TARGET-IP>
```

But I wanted to understand what each option meant instead of memorizing command strings.

The first command worth dissecting was a host discovery pipeline:

```bash
sudo nmap 10.20.30.0/24 -sn -oA tnet | grep for | cut -d" " -f5
```

At first glance, it looks like one Nmap command. It is actually three programs connected together.

The larger problem became clear as I continued studying: Nmap output contains clues, but those clues are not always definitive. A TTL value can suggest an operating system family. Nmap OS detection can estimate a kernel. A port number can suggest a service. None of those should automatically be treated as proof.

---

## The Investigation

### 1. Understanding Nmap host discovery

The first part was:

```bash
sudo nmap 10.20.30.0/24 -sn -oA tnet
```

`10.20.30.0/24` tells Nmap to examine the addresses in that subnet.

`-sn` performs host discovery without conducting the normal port scan.

`-oA tnet` stores the results in multiple Nmap output formats using `tnet` as the base filename.

The next character changes everything:

```bash
|
```

A Unix pipe takes the standard output from the command on the left and feeds it into the standard input of the command on the right.

Conceptually:

```text
Nmap output -> grep -> cut -> final output
```

The next stage was:

```bash
grep for
```

This keeps lines containing the text `for`, such as:

```text
Nmap scan report for 10.20.30.15
```

Then:

```bash
cut -d" " -f5
```

`cut` divides the line into fields.

`-d" "` says the delimiter is a space.

`-f5` says return field number five.

For this line:

```text
Nmap scan report for 10.20.30.15
```

the fields are:

```text
1 = Nmap
2 = scan
3 = report
4 = for
5 = 10.20.30.15
```

The result is a clean list of discovered addresses.

---

### 2. Reading ICMP traffic

Verbose packet output exposed another useful layer:

```text
SENT ICMP [10.20.40.5 > 10.30.40.20 Echo request (type=8/code=0)]
RCVD ICMP [10.30.40.20 > 10.20.40.5 Echo reply (type=0/code=0)]
```

ICMP type 8 is an Echo Request.

ICMP type 0 is an Echo Reply.

The matching identifier and sequence number allow the sender to associate the reply with the original request.

This is the packet-level version of what most people simply call "ping."

---

### 3. Understanding TTL without over-trusting it

A ping response might contain:

```text
TTL=64
```

Common operating systems frequently begin packets using values such as 64, 128, or 255.

A received TTL of 63 could therefore indicate a packet that began at 64 and crossed one Layer 3 hop.

That makes TTL useful for fingerprinting, but not definitive identification.

A router replying with TTL 64 does not prove that it runs Linux. It suggests a Linux, Unix-like, or otherwise similarly configured network stack.

That distinction matters.

---

### 4. Interpreting Nmap OS detection

One scan returned something similar to:

```text
Device type: general purpose
Running: Linux 5.X
OS details: Linux 5.0
Network Distance: 2 hops
```

The tempting conclusion is simply "Linux."

But Nmap is fingerprinting network-stack behavior. It may identify a kernel family without knowing the distribution, appliance platform, or product running on top of it.

In a lab question asking for the "operating system," the expected answer may therefore be more specific than the kernel family Nmap identified.

The lesson was not to blindly copy one line from the output. Enumeration means correlating evidence.

---

### 5. Enumerating DNS deliberately

DNS commonly uses UDP port 53 for ordinary queries, although TCP 53 is also part of DNS operation.

A focused UDP scan looks like:

```bash
sudo nmap -sU -Pn -p 53 -sV <TARGET-IP>
```

For DNS-specific information, Nmap's NSE can be more appropriate:

```bash
sudo nmap -sU -Pn -p 53 --script dns-nsid <TARGET-IP>
```

A direct DNS query can also ask for the traditional BIND version string:

```bash
dig @<TARGET-IP> version.bind chaos txt
```

A hardened server may refuse the request or suppress the version. That is a valid security configuration, not necessarily a failed scan.

One roadblock during testing was trying to invoke a nonexistent NSE script name. Nmap immediately reported that the requested script did not match a script, category, or directory.

The fix was to stop guessing script names and use the installed NSE script set or a direct DNS query.

---

### 6. Understanding TCP versus UDP enumeration

Service enumeration is not inherently "TCP" or "UDP."

It depends on the protocol being investigated.

Examples of services commonly associated with UDP include:

```text
DNS   53
NTP   123
SNMP  161
TFTP  69
```

Common TCP services include:

```text
SSH    22
HTTP   80
HTTPS  443
SMB    445
```

Nmap can explicitly mix both:

```bash
sudo nmap -sS -sU -sV -p U:53,161,T:22,80,443 <TARGET-IP>
```

UDP enumeration is often slower because silence is ambiguous. A missing response could mean the port is open, filtered, rate-limited, or the probe was simply dropped.

---

## What the Evidence Showed

The most important realization came while experimenting with IDS/IPS-aware scanning.

A scan containing options such as:

```bash
-sA -Pn -T1 --scan-delay 3s -f --data-length 42 --source-port 53
```

could still generate alerts.

That is expected.

Modern detection systems do not depend solely on one recognizable Nmap packet signature. They can correlate repeated probes, destination ports, unusual TCP flag combinations, fragmented traffic, source behavior, and service interrogation.

Another major source of traffic was:

```bash
-sV
```

Version detection does more than determine whether a port answers. Nmap actively communicates with the service and sends probes designed to identify what is listening.

That creates additional network activity.

Also, an ACK scan:

```bash
-sA
```

is primarily useful for understanding filtering behavior. It does not determine open versus closed ports the way a SYN scan does.

---

## The Root Cause

The main mistake was treating "stealth" as a collection of command-line switches.

It is not.

A slow scan is still a scan.

Fragmentation is still unusual traffic.

A forged-looking source port does not transform arbitrary probes into legitimate DNS.

Version detection still interrogates services.

The better approach in an authorized lab or assessment is precision: use information already discovered to reduce unnecessary probes, scan only what matters, and understand exactly what each additional Nmap feature causes on the network.

---

## Key Takeaways

* Nmap becomes much easier once I understand the packets instead of memorizing flags.
* Pipes connect programs by passing one program's output into another program's input.
* `grep` filters lines while `cut` extracts fields.
* `-sn` performs host discovery without the normal port scan.
* TTL can provide operating system and hop-count clues, but it is not proof.
* Nmap OS detection is fingerprinting, not omniscience.
* DNS uses both UDP and TCP port 53.
* `dns-nsid` and targeted DNS queries can reveal DNS implementation information when the server exposes it.
* UDP scans are slower because no response is inherently ambiguous.
* `-sV` adds active service probes and therefore creates more observable traffic.
* `-sA` tests filtering behavior rather than directly identifying open TCP ports.
* IDS/IPS evasion is not solved by stacking `-T1`, fragmentation, padding, and source-port options.
* Targeted enumeration is usually more useful than repeatedly scanning everything.

---

## Summary

**Symptom:** I could run Nmap commands, but I wanted to understand what the output, packet fields, shell pipeline, scan types, and enumeration options actually meant.

**Investigation:** I dissected host discovery, pipes, `grep`, `cut`, ICMP Echo traffic, TTL values, OS fingerprinting, DNS queries, TCP versus UDP scanning, and IDS-visible scan behavior.

**Root Cause:** Several assumptions were too absolute, especially treating TTL as definitive OS identification and treating Nmap "stealth" flags as a way to become invisible.

**Resolution:** I shifted toward evidence-based enumeration: understand each packet, target only the necessary protocol and port, correlate multiple clues, and treat Nmap results as evidence rather than unquestionable truth.

Nmap does not make me a ninja, but at least now I know exactly which packets are sticking out of the bushes.
