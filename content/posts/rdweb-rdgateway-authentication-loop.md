+++
title = "When RD Gateway Wasn't The Problem: Solving an RDWeb Authentication Loop"
slug = "rdweb-rdgateway-authentication-loop"
date = "2026-08-15"
author = "RoninSec"
cover = "/img/rdweb-rdgateway-authentication-loop-banner.png"
tags = ["windows-server", "remote-desktop", "rd-gateway", "troubleshooting", "rdweb"]
keywords = ["rd gateway", "rdweb", "remote desktop", "authentication loop", "rdp troubleshooting", "windows server", "remoteapp"]
description = "A persistent RD Gateway credential prompt turned out to be a published RDP configuration issue rather than an authentication or policy problem."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# When RD Gateway Wasn't The Problem: Solving an RDWeb Authentication Loop

Sometimes the hardest troubleshooting sessions end with changing a single line in a configuration file.

I recently chased what looked like an RD Gateway authentication problem. Credentials were correct, policies looked good, Active Directory was healthy, and Remote Desktop Services appeared to be functioning normally. The answer ended up being hidden inside the published `.rdp` file itself.

This is a good reminder that if every piece of infrastructure looks healthy, it may be worth questioning the assumptions behind the workflow instead of the components.

---

## The Symptom

Users could successfully:

* Log into RDWeb.
* See the published applications and desktops.
* Download the Remote Desktop shortcut.

However, launching the downloaded shortcut resulted in an endless credential prompt. Entering valid credentials simply brought the prompt back again.

The strange part was that the exact same credentials worked perfectly when:

* Logging into RDWeb.
* Logging directly onto the destination server through another remote management solution.
* Connecting locally using Remote Desktop.

Everything pointed toward the RD Gateway, but the evidence didn't completely agree.

---

## The Investigation

Rather than assuming authentication was broken, I started validating each layer.

### 1. Verify Remote Desktop services

```powershell
Get-Service TermService, SessionEnv, WinRM | Select Name, Status
```

Everything was running normally.

---

### 2. Verify the server's secure channel

```powershell
Test-ComputerSecureChannel -Verbose
```

Output:

```text
VERBOSE: The secure channel between the local computer and the domain is in good condition.
True
```

That ruled out domain trust issues.

---

### 3. Verify local Remote Desktop permissions

```powershell
Get-LocalGroupMember "Remote Desktop Users"
```

The expected groups were present, and Group Policy allowed logon through Remote Desktop Services.

---

### 4. Verify RD Gateway policies

I reviewed both:

* Connection Authorization Policies (CAP)
* Resource Authorization Policies (RAP)

Everything checked out.

The users belonged to the appropriate authorization groups.

The destination server existed in Active Directory.

The server belonged to the resources permitted by the RAP.

At this point I had verified:

* Authentication
* Authorization
* Domain membership
* Secure channel
* Remote Desktop Services
* Group membership
* RD Gateway policy

Yet the login loop remained.

---

### 5. Read the RDP file

Instead of assuming the downloaded shortcut was correct, I opened it in Notepad.

Among the configuration settings were entries similar to:

```text
gatewayhostname:s:<gateway>
gatewayusagemethod:i:2
gatewaycredentialssource:i:0
promptcredentialonce:i:1
```

This became the turning point of the investigation.

---

## What The Evidence Showed

Initially I assumed the published shortcut required the RD Gateway because it had been downloaded from RDWeb.

That assumption turned out to be wrong.

The workflow actually looked like this:

1. User authenticates to RDWeb.
2. RDWeb delivers the published RDP shortcut.
3. The shortcut attempts to use the RD Gateway again because the gateway is explicitly configured inside the RDP file.

Instead of continuing the existing connection flow, the client attempted another Gateway authentication.

The result was an authentication loop.

Whether this technically exits and re-enters the network depends on the deployment architecture, so I cannot say that is exactly what happened internally. What I can say with confidence is that the client attempted an unnecessary second Gateway authentication, and removing it resolved the issue immediately.

---

## The Root Cause

The published `.rdp` shortcut contained RD Gateway settings that were unnecessary for this deployment.

After removing the Gateway configuration from the shortcut and specifying the appropriate username, the connection succeeded immediately.

The changes were essentially:

* Remove the RD Gateway configuration.
* Specify the correct username.
* Leave the remaining settings unchanged.

Nothing else in the environment required modification.

No policy changes.

No Active Directory fixes.

No Remote Desktop Services changes.

No firewall adjustments.

The infrastructure had been configured correctly all along.

The published shortcut had not.

---

## Gotchas That Cost Time

Several things looked suspicious but ultimately were not the problem.

### The server name

The server appeared under a longer hostname in Active Directory than I had initially searched for.

This briefly suggested an Active Directory issue, but the computer object was present all along.

Lesson learned: search using partial names before assuming an object is missing.

---

### RAP policy

Because the RAP referenced domain computers, I briefly suspected the destination server was not being matched correctly.

After verifying the computer object and group membership, that theory was ruled out.

---

### Authentication

The repeated credential prompt naturally suggested invalid credentials.

In reality, the credentials were perfectly valid.

A repeated login prompt does not automatically mean authentication is failing.

Sometimes the authentication process itself is being invoked more than once.

---

## Key Takeaways

* Verify every layer before changing configuration.
* Do not assume a published RDP file is correct simply because it came from RDWeb.
* Opening an RDP file in Notepad can reveal configuration problems that are invisible in the GUI.
* A healthy secure channel eliminates many Active Directory troubleshooting paths.
* If credentials work everywhere except through a published shortcut, inspect the shortcut before rebuilding infrastructure.
* Login loops are not always authentication failures. Sometimes they are workflow failures.

---

## Summary

**Symptom**

RDWeb users could authenticate successfully but were stuck in an endless credential prompt when launching a published Remote Desktop shortcut.

**Investigation**

Verified services, secure channel, local permissions, CAP and RAP policies, Active Directory computer object, and finally inspected the published RDP configuration.

**Root Cause**

The published RDP shortcut unnecessarily specified the RD Gateway, causing the client to perform another Gateway authentication during the connection process.

**Resolution**

Removed the RD Gateway configuration from the published RDP shortcut, specified the correct username, and verified successful connectivity without changing any server-side infrastructure.

Sometimes the best debugger is Notepad, and sometimes the bug is only one line long.
