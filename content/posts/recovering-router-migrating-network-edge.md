+++
title = "Recovering a Branch Router and Migrating the Network Edge"
slug = "recovering-router-migrating-network-edge"
date = "2026-08-16"
author = "RoninSec"
cover = "/img/recovering-router-migrating-network-edge-banner.png"
tags = ["router-recovery", "network-migration", "vpn-routing", "boot-failure", "network-troubleshooting"]
keywords = ["router boot recovery", "corrupt firmware image", "USB boot", "TFTP troubleshooting", "client initiated VPN", "edge gateway migration"]
description = "A practical account of recovering a failed branch router, navigating ISP and transfer problems, and discovering why the VPN survived."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Recovering a Branch Router and Migrating the Network Edge

What began as a branch router that refused to boot turned into a much broader troubleshooting exercise involving corrupted firmware, USB recovery, TFTP problems, ISP topology confusion, and a full replacement of the network edge.

The biggest surprise came after the replacement. An existing VPN connection continued working through the new firewall even though I had not configured the firewall for that VPN.

This is the full story of what failed, how I investigated it, where I went down the wrong path, and why the final result made more sense once I identified the real VPN endpoint.

---

## The Symptom

The remote-site router repeatedly entered its boot monitor instead of loading the network operating system.

The startup configuration contained boot statements referencing a firmware image, so the first assumption was that the router might be ignoring its boot configuration or using an incorrect configuration register.

The first useful command was simply listing the contents of internal storage:

```text
dir bootflash:
```

The expected firmware filename was present, but the file was only a few kilobytes.

A legitimate image for this class of router should have been hundreds of megabytes.

That changed the direction of the investigation. The router was not necessarily ignoring the configured image. It was finding the file and attempting to load it, but the file was truncated or corrupt.

The boot errors were consistent with that conclusion:

```text
Unsupported package header
Unable to locate a bootable image
Failed to load image from internal storage
```

The filename looked correct, but the contents were not.

---

## The Investigation

### 1. Booting From Removable Media

I placed a known-good firmware image on a FAT32-formatted USB drive and connected it to the router.

From the boot monitor, I confirmed that the USB drive was detected:

```text
dir usb0:
```

I then manually booted the firmware from USB:

```text
boot usb0:<ROUTER-IMAGE>.bin
```

The image passed its integrity and signature checks, and the router loaded successfully.

Once the operating system was running, I verified where it had booted from:

```text
show version
```

The output confirmed that the active system image was located on the USB drive.

This was an important distinction. The router was temporarily operational, but it had not been permanently repaired. A reboot without the USB drive would likely return it to the boot monitor.

### 2. Obtaining a Known-Good Image

A second router of the same model and software generation had a functioning copy of the required image.

The recovery plan was:

1. Copy the image from the working router to a temporary workstation.
2. Transfer it to the affected site.
3. Copy it into the failed router's internal storage.
4. Verify the resulting file.
5. Correct the boot configuration.

The working router used a command similar to:

```text
copy bootflash:<ROUTER-IMAGE>.bin tftp:
```

The TFTP transfer initially failed.

The router could not ping the temporary workstation, even though the workstation could ping the router.

That seemed contradictory until I considered the host firewall.

The workstation was allowed to initiate outbound ping requests, and the firewall permitted the corresponding replies. However, the router's ping toward the workstation was a new inbound connection and was blocked.

TFTP also required an inbound UDP rule.

A narrow temporary firewall rule could be used during the transfer:

```cmd
netsh advfirewall firewall add rule name="Temporary TFTP" dir=in action=allow protocol=UDP localport=69
```

The rule should be removed after the transfer:

```cmd
netsh advfirewall firewall delete rule name="Temporary TFTP"
```

Temporarily disabling the firewall also confirmed the diagnosis, but that was a troubleshooting step rather than the preferred long-term solution.

### 3. The TFTP Exposure Gotcha

During one stage of recovery, the TFTP workstation was connected too directly to an internet-facing network.

Almost immediately, the TFTP application began receiving unsolicited traffic.

That was a useful reminder that TFTP has no authentication and should never be exposed to the public internet. It should only be used on a controlled management network and shut down when the transfer is complete.

The safer workflow is:

* Use an isolated LAN or direct management connection.
* Allow only the expected source address.
* Run the TFTP service only during the transfer.
* Remove temporary firewall rules afterward.
* Verify the transferred file before using it.

### 4. Copying the Image to Internal Storage

After booting from USB, I copied the valid image into persistent internal storage:

```text
copy usb0:<ROUTER-IMAGE>.bin bootflash:
```

I then confirmed the file size:

```text
dir bootflash:
```

The recovered file was now hundreds of megabytes instead of a few kilobytes.

I also verified the checksum:

```text
verify /md5 bootflash:<ROUTER-IMAGE>.bin
```

A successful checksum comparison confirmed that the copy matched the known-good source file.

### 5. Cleaning the Boot Configuration

The original configuration contained multiple boot statements, including a line that treated the firmware image as though it were a configuration file.

That was incorrect. The operating system image should be referenced by the system boot command, not the configuration boot command.

I cleaned the boot entries and restored normal boot behavior:

```text
configure terminal
no boot system
no boot config bootflash:<ROUTER-IMAGE>.bin
boot system bootflash:<ROUTER-IMAGE>.bin
config-register 0x2102
end
write memory
```

I then verified the settings:

```text
show boot
show version
```

The router could now locate a valid internal image and use the saved startup configuration.

---

## The ISP Roadblock

The remote site used a provider-assigned static WAN block.

To protect the client, the exact addresses are omitted. The configuration followed the normal pattern:

```text
WAN address: <STATIC-WAN-IP>
Subnet mask: <STATIC-MASK>
Default gateway: <STATIC-GATEWAY>
```

The router interface used the static assignment:

```text
interface <WAN-INTERFACE>
 description WAN
 ip address <STATIC-WAN-IP> <STATIC-MASK>
 ip nat outside
 no shutdown
```

The default route pointed toward the provider gateway:

```text
ip route 0.0.0.0 0.0.0.0 <STATIC-GATEWAY>
```

Troubleshooting became confusing because the provider had supplied both a modem and a separate gateway device.

A workstation connected directly to the modem received a dynamic public address, while the documented static block appeared to rely on the provider gateway remaining in the path.

At first, this looked like a modem MAC-address lock or stale lease. That was possible, but it was not definitively proven.

The larger lesson was that a provider's "static IP service" may be routed through its managed gateway rather than assigned directly by the modem. Rebooting equipment will not fix an incorrect physical topology or an upstream provisioning dependency.

---

## Replacing the Network Edge

Even after recovering the router, its repeated boot problems reduced confidence in using it as the long-term edge device.

The remote router and switch were replaced with a modern security gateway and managed switch.

The new configuration preserved the operational requirements while replacing all identifying addresses with documentation-safe examples:

* Remote LAN: `10.44.20.0/24`
* Remote gateway: `10.44.20.1`
* Main-site LAN: `10.44.10.0/24`
* Main-site gateway: `10.44.10.1`
* Main-site VPN server: `10.44.10.40`
* Remote application endpoint: `10.44.20.30`

The migration also recreated:

* The static WAN configuration
* The DHCP range and exclusions
* Required application port forwards
* Switch management access
* Default untagged LAN connectivity
* Remote administration through the new management platform

The expectation was that the VPN would need to be rebuilt on the new security gateway.

That assumption turned out to be wrong.

---

## The VPN That Kept Working

A machine at the remote site already ran a VPN client using a saved configuration file.

The VPN server remained on a virtual machine at the main site.

After the legacy router was removed and the new gateway was installed, I connected the VPN client and tested access to the main-site gateway:

```cmd
ping 10.44.10.1
```

The ping succeeded.

I had not configured a site-to-site VPN, static route, or special VPN firewall rule on the new gateway.

The reason was that the new gateway was not the VPN endpoint.

The remote machine initiated an outbound encrypted connection to the main-site VPN server. The gateway treated it like any other outbound internet session:

1. The remote machine opened the VPN connection.
2. The gateway translated and forwarded the outbound traffic.
3. The stateful firewall tracked the session.
4. Return traffic was allowed because it belonged to an established connection.
5. The VPN client created a virtual network adapter.
6. The client installed a route for the main-site subnet through that adapter.

The new gateway did not need to understand the tunnel's internal routes. It only needed to allow the remote machine to reach the VPN server over the internet.

The old router configuration also contained legacy IPsec settings and static routes. Those entries initially made the environment look like a router-to-router VPN.

However, the connection that survived the migration was the client-based tunnel running directly between the remote machine and the main-site VPN server.

The legacy VPN configuration and the functioning VPN path were not the same thing.

---

## What the Evidence Showed

The successful ping proved several things:

* The remote VPN client was connected.
* A route to the main-site LAN existed on the remote machine.
* The VPN server could pass traffic into the main-site network.
* The main-site gateway or VPN server could return the response.
* The new remote gateway was allowing the outbound VPN session.

It did not prove that every device on the remote LAN could reach every device at the main site.

Without a static route on the new gateway and IP forwarding on the VPN client machine, the tunnel may only serve that one endpoint.

That distinction matters when describing the connection as "site-to-site." Functionally, the application could communicate across locations, but the VPN endpoint was still an individual machine acting as a client.

---

## Root Cause

The primary router failure was caused by an incomplete or corrupted firmware image stored in internal flash.

The later VPN confusion came from an architectural misunderstanding. I initially treated the legacy router as the active VPN endpoint because its configuration contained VPN-related commands.

In reality, the working tunnel was initiated by a machine behind the router.

The router replacement did not break the VPN because the router had only been transporting the encrypted outbound session.

---

## Key Takeaways

* A correct filename does not mean a firmware image is valid.
* Always inspect file size before assuming an image is usable.
* Booting from USB is a recovery mechanism, not a permanent resolution.
* Verify transferred firmware before changing boot variables.
* A host firewall can allow outbound ping while blocking inbound ping.
* Never expose TFTP directly to an untrusted network.
* Provider-assigned static addresses may depend on managed gateway hardware.
* Configuration remnants do not prove which VPN path is actually active.
* Identify the true VPN endpoints before rebuilding a tunnel.
* A client-initiated VPN can survive an edge-router replacement without special firewall changes.
* Replace all real addressing with unrelated documentation ranges before publishing.

---

## Summary

> **Symptom:** A remote router repeatedly entered its boot monitor, and the existing VPN design appeared likely to break during an edge replacement.
>
> **Investigation:** I inspected internal storage, identified a truncated firmware image, booted from USB, transferred a known-good image, corrected host firewall issues, verified the checksum, cleaned the boot configuration, and reviewed the actual VPN traffic path.
>
> **Root Cause:** The router contained a corrupted firmware image. Separately, the VPN was misunderstood as router-terminated when the working connection was actually initiated by a machine behind the router.
>
> **Resolution:** I restored a valid firmware image, corrected the boot configuration, replaced the unreliable edge hardware, and confirmed that the endpoint-based VPN continued operating through the new stateful firewall.

The router changed, the tunnel stayed up, and the real upgrade was finally understanding who was doing the routing.
