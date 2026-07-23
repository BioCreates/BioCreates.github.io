+++
title = "Troubleshooting One-Way Site-to-Site OpenVPN Routing"
slug = "troubleshooting-one-way-openvpn-routing"
date = "2026-07-22"
author = "RoninSec"
cover = "/img/troubleshooting-one-way-openvpn-routing-banner.png"
tags = ["openvpn", "network-routing", "packet-analysis", "linux", "windows-networking"]
keywords = ["site-to-site openvpn", "asymmetric routing", "tcpdump", "wireshark", "data channel offload", "static routes", "vpn troubleshooting"]
description = "A practical investigation into one-way OpenVPN routing using static routes, packet captures, firewall testing, and data channel offload."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Troubleshooting One-Way Site-to-Site OpenVPN Routing

The VPN connected successfully. The remote gateway could reach headquarters. Packets clearly crossed the tunnel.

Headquarters still could not reach the remote network.

This was one of those networking problems where almost everything looked correct. Routes existed, forwarding was enabled, and the tunnel showed as connected. The trick was proving exactly where packets stopped instead of continuing to add routes and hoping for the best.

---

## The Symptom

The environment consisted of:

* An HQ LAN using `192.168.10.0/24`
* A remote LAN using `192.168.20.0/24`
* A Linux VM running OpenVPN Access Server at HQ
* A Windows workstation acting as the remote VPN gateway
* Routers at both sites with static routes to the opposite LAN
* A routed VPN design rather than VPN-side NAT

The remote Windows gateway had two relevant addresses:

* LAN address: `192.168.20.16`
* VPN address: `192.168.200.130`

The symptoms were inconsistent:

* The remote VPN gateway could ping devices at HQ.
* The remote gateway could receive replies from the HQ router.
* HQ could sometimes ping the remote VPN address.
* HQ could not ping the remote gateway's LAN address.
* HQ could not reach other devices on the remote LAN.
* The OpenVPN server sent packets into the tunnel but received no replies.

That pattern immediately suggested asymmetric routing, local firewall filtering, or a VPN data-channel problem.

---

## The Investigation

### 1. Confirm the OpenVPN service

I started by verifying that OpenVPN Access Server was running:

```bash
sudo systemctl status openvpnas
```

If the service needed to be restarted:

```bash
sudo systemctl restart openvpnas
```

I also confirmed the Linux VM still had its expected LAN address and default route:

```bash
ip address
ip route
```

The VM used bridged networking, so it appeared as an independent host on the HQ LAN. The Windows host did not need to route traffic into the VM because the VM had its own Layer 2 presence on the network.

---

### 2. Confirm Linux IP forwarding

The OpenVPN server needed to route packets between its LAN interface and VPN tunnel interfaces.

I checked forwarding with:

```bash
sysctl net.ipv4.ip_forward
```

The expected result was:

```text
net.ipv4.ip_forward = 1
```

To enable forwarding temporarily:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

To load the persistent configuration:

```bash
sudo sysctl -p /etc/sysctl.conf
```

Seeing the setting printed twice did not mean two forwarding services were active. One command set the value immediately, and the second reloaded the configured value.

---

### 3. Review the routing tables

The OpenVPN server divided its virtual address pool across several `/27` tunnel interfaces. The remote client's VPN address belonged to one specific interface.

The important routes resembled:

```text
192.168.200.128/27 dev as0t4
192.168.20.0/24 dev as0t4
192.168.20.0/24 via 192.168.200.130 dev as0t4
192.168.10.0/24 dev ens33
```

At one point, two routes existed for the remote LAN:

* A direct route through the OpenVPN tunnel interface
* A route through the remote client's VPN address

I tested removing the duplicate route:

```bash
sudo ip route del 192.168.20.0/24 via 192.168.200.130 dev as0t4
```

Cleaning up the route table reduced ambiguity, but it did not restore connectivity.

The remote Windows gateway also had overlapping routes to the HQ LAN. Any route using an unreachable gateway from the opposite physical LAN was removed.

For example:

```cmd
route delete 192.168.10.0 mask 255.255.255.0 <INVALID-GATEWAY>
```

---

### 4. Validate the router next hops

The HQ router needed to send remote-LAN traffic to the OpenVPN server's HQ address:

```text
ip route 192.168.20.0 255.255.255.0 192.168.10.41
```

The remote router needed to send HQ traffic to the Windows VPN gateway's remote-LAN address:

```text
ip route 192.168.10.0 255.255.255.0 192.168.20.16
```

This distinction mattered. A router normally needs a directly reachable next hop. Pointing a static route at a VPN address does not work unless the router already has a valid path to that VPN address.

A route can appear configured while still being unusable because its next hop cannot be resolved.

---

### 5. Follow the packet with tcpdump

The most valuable test was capturing traffic on every Linux interface while pinging the remote gateway from an HQ workstation:

```bash
sudo tcpdump -i any -n -e icmp and host 192.168.20.16
```

The capture showed:

```text
ens33 In  192.168.10.32 > 192.168.20.16: ICMP echo request
as0t4 Out 192.168.10.32 > 192.168.20.16: ICMP echo request
```

This proved that:

1. The HQ workstation generated the packet.
2. The packet reached the OpenVPN server.
3. Linux selected the expected VPN interface.
4. The packet left through the tunnel.
5. No reply returned.

That was the turning point. The HQ router, Linux LAN interface, and Linux routing decision were all doing their jobs.

---

### 6. Test the remote Windows gateway

The remote Windows system needed to act as a router between its OpenVPN adapter and physical LAN adapter.

I verified:

* Windows IP forwarding was enabled.
* The Windows firewall was temporarily disabled for testing.
* The inbound ICMPv4 echo-request rule was enabled for normal operation.
* Routes to the HQ LAN used the OpenVPN adapter.
* Invalid or duplicate routes were removed.

Wireshark on the remote gateway confirmed that the system could originate ICMP traffic through the VPN and receive replies from HQ.

However, the missing HQ-initiated replies showed that the problem was not ordinary DNS resolution or simple Internet NAT.

---

## What the Evidence Showed

The captures established several important facts:

* HQ traffic reached the OpenVPN server.
* Linux forwarded the traffic into the correct tunnel.
* The remote VPN gateway could initiate traffic toward HQ.
* HQ replies returned successfully to the remote VPN address.
* HQ-initiated traffic did not receive responses from the remote side.
* DNS settings were unrelated to the IP-level failure.
* VMware host-only and NAT adapters created capture noise but were not the actual path.
* Internet NAT rules on the routers were not translating the site-to-site traffic.
* Adding more static routes did not solve the underlying data-path problem.

The VPN control connection was up, but the routed data channel was not behaving bidirectionally.

---

## The Root Cause

The breakthrough came from enabling Data Channel Offload, or DCO, in the OpenVPN Access Server management portal.

After DCO was enabled, bidirectional traffic began working.

DCO moves OpenVPN data-channel processing into the operating system kernel. It is often discussed as a performance feature, but in this environment it also changed how routed traffic between the server and Windows gateway was handled.

I cannot claim that every internal failure mechanism was proven. What I could prove was:

* The routes selected the correct tunnel.
* Linux forwarding worked.
* Packets entered and exited the expected interfaces.
* Replies were missing until DCO was enabled.

That made the OpenVPN data path, rather than the basic static routing configuration, the strongest supported root cause.

When the VPN later failed again, the client log showed:

```text
Server poll timeout, restarting
SIGUSR1[soft,server_poll] received, process restarting
```

That represented a different failure stage. The client was no longer maintaining the control connection, so the next checks became service status, UDP port forwarding, firewall policy, public reachability, VM address stability, and DCO availability.

---

## Key Takeaways

* A connected VPN does not prove that routed traffic works both ways.
* Use packet captures before adding more static routes.
* Capture on `any` when multiple OpenVPN tunnel interfaces exist.
* If traffic enters the LAN interface and exits the tunnel interface, Linux routing is probably working.
* A static route is only useful when its next hop is actually reachable.
* Remove duplicate and invalid routes during troubleshooting.
* DNS does not control the path of an ICMP packet sent directly to an IP address.
* A Windows workstation acting as a gateway needs forwarding, correct routes, and appropriate firewall rules.
* VMware virtual adapters may appear in captures without being involved in the real traffic path.
* DCO can affect functional VPN data-channel behavior, not only throughput.
* Keep a rollback list for temporary routes, firewall rules, and interface changes.

---

## Summary

> **Symptom:** The remote VPN gateway could reach HQ, but HQ could not reach the gateway's LAN address or other remote devices.
>
> **Investigation:** I validated router next hops, Linux forwarding, Windows routes, firewall behavior, OpenVPN interfaces, and packet flow with tcpdump and Wireshark.
>
> **Root Cause:** The OpenVPN routed data channel was not handling bidirectional gateway traffic correctly with DCO disabled.
>
> **Resolution:** I enabled DCO, cleaned up conflicting routes, retained directly reachable router next hops, and verified packet flow across both LAN and VPN interfaces.

Have you ever seen a VPN report a healthy connection while its data channel quietly failed in only one direction?
