+++
title = "Troubleshooting UniFi Wi-Fi Roaming, Mesh, and Slow Performance"
slug = "unifi-wifi-roaming-mesh-troubleshooting"
date = "2026-09-20"
author = "RoninSec"
cover = "/img/unifi-wifi-roaming-mesh-troubleshooting-banner.png"
tags = ["unifi", "wifi", "troubleshooting", "networking", "wireless"]
keywords = ["unifi wifi", "wifi roaming", "minimum rssi", "roaming assistant", "mesh uplink", "slow wifi", "access point"]
description = "A practical UniFi troubleshooting walkthrough using roaming logs, RSSI data, mesh topology, and RF settings to investigate unstable Wi-Fi."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Troubleshooting UniFi Wi-Fi Roaming, Mesh, and Slow Performance

"Slow Wi-Fi" sounds simple until a speed test says 25 Mbps, another says nearly 500 Mbps, and the UniFi logs look like every phone in the building is playing musical chairs with the access points.

Rather than immediately blaming the ISP, I worked backward from the evidence: speed tests, UniFi event logs, client RSSI, AP topology, mesh behavior, channels, and roaming configuration.

The important lesson was not that one magic setting fixed everything. It was that Wi-Fi troubleshooting requires separating Internet bandwidth problems from RF and client roaming problems.

---

## The Symptom

The initial complaint was bad or slow Wi-Fi.

Two browser speed tests produced dramatically different results. One reported roughly 25 Mbps down and 21 Mbps up, while another reached approximately 476 Mbps down and 37 Mbps up.

That immediately raised a question: which result represented the connection?

The answer was "potentially both."

Different speed-test services use different servers, network paths, connection strategies, and test implementations. A fast result to one nearby server proves that substantial WAN bandwidth is available along that path, but it does not prove that every destination or Wi-Fi client will experience the same performance.

Instead of treating either test as definitive, I moved into UniFi.

---

## The Investigation

### 1. Review the UniFi Event Logs

The event log was much more interesting than the speed tests.

There were large numbers of:

* WiFi Client Roamed
* WiFi Client Connected
* WiFi Client Disconnected
* AP Channel Change

Several clients repeatedly moved between APs within minutes.

More importantly, UniFi exposed the RSSI associated with those decisions. Examples included clients around -70 dBm, -79 dBm, -84 dBm, and even -87 dBm.

That is useful evidence because a client associated at -84 dBm may technically be connected while still providing a terrible user experience.

The logs also showed clients bouncing between 2.4 GHz and 5 GHz radios and between multiple APs.

Roaming itself is normal. Excessive roaming is not automatically proof of a configuration problem, because the client normally makes the roaming decision and users may genuinely be moving around. However, repeated roaming combined with weak RSSI and actual complaints was enough to justify investigating the RF configuration.

### 2. Check the AP Topology

The deployment contained several APs. Most showed a GbE uplink, while one showed:

```text
AP-01    Uplink: GbE
AP-02    Uplink: GbE
AP-03    Uplink: GbE
AP-04    Uplink: Mesh
         Parent: AP-02
```

That mesh AP deserved attention.

UniFi also displayed:

```text
This AP is not broadcasting client-facing WiFi.
Please assign a WiFi network to make this AP active.
```

So the device had a wireless mesh uplink but currently had no client-facing WLAN assigned.

Conceptually, a mesh link can function as wireless backhaul:

```text
LAN
 |
Wired AP
 |
 |  Wireless mesh/backhaul
 |
Mesh AP
 |
 |  Optional downstream network path
 |
Remote network/AP
```

A mesh-only device can be useful as part of a wireless bridge or multi-hop topology, but only if it is actually carrying traffic somewhere useful. If it has no client WLAN and nothing downstream depends on it, there may be little reason for it to exist in that role.

There was also an interesting gotcha: historical events showed clients roaming to or from this AP even though its current configuration said it was not broadcasting client-facing Wi-Fi. That means I could not safely conclude that the AP had always been configured this way. Configuration changes, historical logs, or controller state needed to be considered before blaming it.

### 3. Examine the RF Settings

The 5 GHz radio configuration showed:

```text
Channel Width: 40 MHz
Channel: Auto
Transmit Power: Medium
Roaming Assistant: Enabled
Roaming Assistant Threshold: -75 dBm
Minimum RSSI: Enabled
Minimum RSSI Threshold: -75 dBm
```

The event log had also recorded an AP changing from one 5 GHz channel to another.

That made automatic channel selection another item worth watching.

For a multi-AP environment, my starting RF plan was:

```text
2.4 GHz
Channel Width: 20 MHz
Channels: 1, 6, or 11
Transmit Power: Lower than 5 GHz where appropriate

5 GHz
Channel Width: 40 MHz
Channels: Planned to minimize co-channel interference
Transmit Power: Medium as a starting point
```

These are starting points, not universal values. AP density, walls, interference, client types, and actual RF measurements should determine the final configuration.

---

## What the Evidence Showed

The strongest evidence was not the speed-test discrepancy. It was the combination of client behavior and RF information.

Clients were associating at weak signal levels, roaming frequently between multiple APs, and sometimes moving to an AP with an RSSI that was not clearly better.

That suggested several possibilities:

1. Excessive or poorly shaped AP coverage overlap.
2. Clients hanging onto distant APs.
3. Channel contention or interference.
4. Automatic RF changes affecting client stability.
5. AP placement or transmit power that needed tuning.

The mesh AP was also worth investigating, but its presence alone did not prove it caused the performance problem.

---

## The Root Cause

I would not call the root cause definitively proven from these screenshots alone.

The evidence strongly pointed toward an RF and roaming problem rather than a simple lack of Internet bandwidth. The connection demonstrated hundreds of megabits of available WAN throughput while UniFi simultaneously showed weak client RSSI and substantial roaming activity.

That shifts the investigation toward the wireless layer.

The likely contributors were AP coverage overlap, weak client associations, channel behavior, and roaming configuration.

The next step was therefore controlled RF tuning followed by measurement, not blindly changing every UniFi optimization switch.

---

## The Resolution

I used -75 dBm as an initial threshold for both Minimum RSSI and Roaming Assistant while evaluating behavior.

That requires an important warning: these features are not magic "make roaming better" switches.

Minimum RSSI can disconnect clients once their signal becomes too weak. Roaming Assistant can encourage clients to move away from poor associations. Setting thresholds too aggressively can actually create more disconnects, especially where AP coverage has gaps.

I therefore treated -75 dBm as a test value rather than a universal best practice.

I also standardized the basic RF configuration:

```text
2.4 GHz:
- 20 MHz channel width
- Non-overlapping 1, 6, 11 channel plan
- Lower transmit power where coverage permits

5 GHz:
- 40 MHz channel width
- Planned channels rather than uncontrolled channel movement
- Medium transmit power as a starting point

Roaming:
- Monitor Minimum RSSI around -75 dBm
- Monitor Roaming Assistant around -75 dBm
- Adjust from real client behavior
```

After making changes, the real test is the logs and user experience.

I want to see clients maintaining stable associations, fewer unnecessary roam events, fewer weak connections below roughly -75 to -80 dBm, and no increase in disconnects caused by thresholds that are too aggressive.

Change one group of variables, observe, then adjust.

---

## Gotchas and Roadblocks

The biggest gotcha was assuming that a large difference between speed tests automatically meant an ISP problem. It did not.

The second was assuming every roam event represented a failure. Roaming is an expected part of multi-AP Wi-Fi. Context matters.

The third was the mesh AP. Seeing "Mesh" and "not broadcasting client-facing WiFi" looked suspicious, but that configuration can be intentional. I needed topology and historical context before calling it broken.

Finally, Minimum RSSI deserves respect. If I configure -75 dBm but there is no stronger AP available when a client crosses that threshold, I have not improved roaming. I have simply kicked a client off the network.

---

## Key Takeaways

* Do not diagnose Wi-Fi solely from Internet speed tests.
* Different speed-test servers can produce dramatically different results.
* UniFi roaming events need RSSI, frequency, AP, and timing context.
* A connected client can still have terrible RF conditions.
* Frequent roaming is a symptom to investigate, not a root cause by itself.
* 20 MHz is a sensible starting width for 2.4 GHz in multi-AP environments.
* Plan 2.4 GHz around channels 1, 6, and 11.
* Mesh uplinks are legitimate, but understand what traffic the mesh AP is actually carrying.
* Minimum RSSI and Roaming Assistant should be tuned carefully rather than enabled blindly.
* Change RF settings methodically and verify the result afterward.

---

## Summary

> **Symptom:** Users reported slow or unstable Wi-Fi while different speed tests produced wildly different throughput results.
>
> **Investigation:** I compared speed tests, reviewed UniFi roaming and disconnect logs, inspected RSSI values, checked AP uplinks, identified a mesh-connected AP, and reviewed radio settings.
>
> **Root Cause:** The available evidence pointed toward RF coverage and roaming behavior rather than insufficient WAN bandwidth, although the exact contributing RF condition still required validation.
>
> **Resolution:** I began controlled RF tuning with sensible channel widths, planned channels, transmit-power adjustments, and carefully monitored -75 dBm roaming and Minimum RSSI thresholds.

When the Wi-Fi starts playing musical chairs, do not blame the Internet until you figure out who keeps moving the APs.
