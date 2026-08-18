+++
title = "Recovering a Cisco ISR Router Stuck in ROMMON"
slug = "cisco-isr-rommon-recovery"
date = "2026-07-23"
author = "RoninSec"
cover = "/img/cisco-isr-rommon-recovery-banner.png"
tags = ["cisco", "rommon", "router-recovery", "tftp", "network-troubleshooting"]
keywords = ["Cisco ISR ROMMON recovery", "boot IOS from TFTP", "unsupported package header", "Cisco router boot failure", "ROMMON troubleshooting", "ISR firmware recovery"]
description = "A practical Cisco ISR ROMMON recovery walkthrough covering corrupted boot images, failed TFTP attempts, and the physical connection gotcha."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Recovering a Cisco ISR Router Stuck in ROMMON

A Cisco ISR router rebooted and landed at a `rommon` prompt instead of loading IOS XE. What looked like a corrupt image problem quickly became a long lesson in boot variables, TFTP servers, interface binding, and one painfully simple physical-layer oversight.

The most important lesson was not a command. It was remembering that console access and network access are two completely different things.

---

## The Symptom

After rebooting the router, the console displayed:

```text
rommon 1 >
```

Normal IOS commands did not work:

```text
en
show run
```

ROMMON responded that those commands were not found. That was expected because ROMMON is a minimal recovery environment, not the Cisco IOS command-line interface.

I listed the internal flash contents:

```text
dir bootflash:
```

The router contained an IOS XE image similar to:

```text
isr4200-universalk9_ias.17.03.04a.SPA.bin
```

I attempted to boot it manually:

```text
boot bootflash:isr4200-universalk9_ias.17.03.04a.SPA.bin
```

The boot failed with:

```text
Unsupported package header version
Failed to boot file bootflash:isr4200-universalk9_ias.17.03.04a.SPA.bin
```

The file shown in flash was only a few kilobytes, while the known-good image on the recovery workstation was hundreds of megabytes. That strongly indicated that the flash copy was truncated or otherwise corrupt.

---

## The Investigation

### 1. Inspecting ROMMON and available devices

I used the following commands to inspect the environment:

```text
set
dev
dir bootflash:
```

The `set` output showed several problematic variables, including boot and configuration references pointing at the damaged image.

The `dev` command listed supported storage devices:

```text
bootflash: Internal flash drive
flash: Alias for bootflash:
usb0: External USB drive 0
```

This did not mean a USB drive was connected. It only meant the platform supported one.

I confirmed that no readable USB storage was present:

```text
dir usb0:
```

The result was:

```text
unable to open usb0 (14)
```

### 2. Trying to boot from TFTP

The previous successful recovery used TFTP, so I configured ROMMON with example recovery addresses:

```text
IP_ADDRESS=192.168.50.10
IP_SUBNET_MASK=255.255.255.0
DEFAULT_GATEWAY=192.168.50.1
TFTP_SERVER=192.168.50.20
TFTP_FILE=isr4200-universalk9_ias.17.03.04a.SPA.bin
```

A useful clarification is that `IP_ADDRESS` belongs to the router itself. `TFTP_SERVER` is the workstation hosting the image.

I verified the settings:

```text
set
```

Then I attempted the network boot:

```text
boot tftp://192.168.50.20/isr4200-universalk9_ias.17.03.04a.SPA.bin
```

ROMMON repeatedly returned:

```text
Unable to get TFTP file size
Failed to download specified file
```

### 3. Troubleshooting the TFTP applications

I tried multiple TFTP servers and checked the usual failure points:

1. Confirmed the image existed in the configured TFTP root.
2. Verified the filename matched exactly.
3. Bound the TFTP service to the correct Ethernet adapter.
4. Disabled Windows Firewall temporarily.
5. Ran the TFTP server as administrator.
6. Tested both the 32-bit and 64-bit variants.
7. Tried a short filename such as `ios.bin`.
8. Changed the root directory to a simple path such as:

```text
C:\TFTP
```

One TFTP application repeatedly reverted its visible interface to `127.0.0.1`. I explicitly enabled its setting to bind TFTP to the workstation's Ethernet address.

Another TFTP application timed out when manually sending the file. That was also a clue: the router is supposed to request the file. The TFTP server should wait for the ROMMON read request rather than push the image with a "Put File" action.

Despite all of this, the server logs showed no inbound TFTP request.

### 4. Checking ROMMON limitations

This ISR's ROMMON did not support several commands commonly found on other Cisco platforms:

```text
ping
tftpdnld
xmodem
```

Each returned a command-not-found message.

That mattered because it eliminated several assumed recovery paths. ROMMON command availability varies by platform and release. A command that works on an older ISR, switch, or different boot monitor should not be assumed to exist everywhere.

---

## What the Evidence Showed

The clues eventually aligned:

* The internal IOS image was severely truncated and could not boot.
* ROMMON recognized the Ethernet boot syntax.
* The TFTP application received no request.
* The workstation could communicate with other systems on its network.
* The router was accessible only through a USB console connection.
* No Ethernet cable connected the router to the workstation, modem, or switch.

The console cable provided serial management access only. It did not place the router on the workstation's IP network.

The IP variables could be perfectly formatted and the TFTP server perfectly configured, but there was no physical Ethernet path between them.

---

## The Root Cause

There were two separate problems:

1. The IOS XE image stored in `bootflash:` was corrupt or incomplete.
2. The attempted TFTP recovery could not work because the router had no Ethernet connection to the TFTP server.

The second problem consumed most of the troubleshooting time because the console session created the impression that the router and workstation were connected. They were connected for serial management, but not for IP traffic.

That distinction explained the empty TFTP logs, the repeated timeouts, and why changing applications, firewall rules, file paths, and interface bindings made no difference.

---

## Resolution Options

Because the recovery was being performed remotely, the remaining options required physical assistance.

### Option 1: Direct Ethernet connection

Have someone connect an Ethernet cable between the router and the recovery workstation or connect both devices to the same switch.

A direct recovery network could use:

```text
Workstation: 192.168.50.20/24
Router ROMMON: 192.168.50.10/24
TFTP server: 192.168.50.20
```

Then run:

```text
boot tftp://192.168.50.20/isr4200-universalk9_ias.17.03.04a.SPA.bin
```

### Option 2: USB recovery

Prepare a FAT32-formatted USB drive with the IOS image in its root directory. Have someone insert it into the router, then verify and boot it:

```text
dir usb0:
boot usb0:isr4200-universalk9_ias.17.03.04a.SPA.bin
```

The exact USB path syntax can vary, so the output of `dir usb0:` should guide the final command.

### Option 3: Replace the router

For a critical site where no qualified person can provide local assistance, the practical solution may be a preconfigured replacement router followed by bench recovery of the failed unit.

---

## Key Takeaways

* ROMMON is not IOS, so normal commands such as `enable` and `show run` will not work.
* Check the image size before blaming ROMMON compatibility. A multi-hundred-megabyte IOS image represented by a few kilobytes is almost certainly incomplete.
* `IP_ADDRESS` is the router's recovery address, not the TFTP server's address.
* TFTP requires an actual Ethernet path. A USB console cable carries serial data, not IP traffic.
* Empty TFTP logs usually mean the request never reached the server.
* Device names shown by `dev` indicate supported devices, not necessarily connected devices.
* ROMMON capabilities vary. Verify commands with `help` instead of assuming `ping`, `tftpdnld`, or XMODEM support.
* Before changing applications, firewall rules, and filenames, confirm Layer 1 connectivity.

---

> **Summary**
>
> **Symptom:** The Cisco ISR rebooted into ROMMON and rejected the IOS XE image with an unsupported package header error.
>
> **Investigation:** I inspected flash, reviewed ROMMON variables, attempted TFTP recovery, changed TFTP servers, checked bindings, and verified available ROMMON commands.
>
> **Root Cause:** The flash image was truncated, and the router had no Ethernet connection to the TFTP workstation. The only connection was a USB console cable.
>
> **Resolution:** Provide an Ethernet connection for TFTP, insert a FAT32 USB drive containing the image, or deploy a replacement router.

When Layer 1 is missing, Layer 8 can spend hours configuring a TFTP server that never had a chance.
