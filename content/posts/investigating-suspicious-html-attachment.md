+++
title = "Investigating A Suspicious HTML Attachment Without Chasing False Positives"
slug = "investigating-suspicious-html-attachment"
date = "2026-08-04"
author = "RoninSec"
cover = "/img/investigating-suspicious-html-attachment-banner.png"
tags = ["phishing", "incident-response", "malware-analysis", "windows-security", "threat-hunting"]
keywords = ["html phishing attachment", "credential harvesting", "windows persistence", "scheduled task analysis", "sandbox investigation", "tls certificate inspection"]
description = "A practical investigation of a suspicious HTML attachment, including sandbox review, persistence checks, network attribution, and false positives."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Investigating A Suspicious HTML Attachment Without Chasing False Positives

A suspicious remittance-themed HTML file triggered an alert on a managed workstation. The initial sandbox output looked ominous: unusual network activity, browser subprocesses, and several public IP addresses.

It would have been easy to call it active malware and start deleting scheduled tasks.

Instead, I slowed down, verified each finding, and discovered a much more accurate story: this was most consistent with a credential-harvesting phishing page, not a persistent malware infection.

---

## The Symptom

The alert involved an HTML attachment with a financial lure. Dynamic analysis reported:

* Browser processes launching
* Outbound DNS and HTTPS traffic
* A suspicious HTML filename
* An empty HTML title
* No obvious payloads or dropped executables

The workstation, which I will call `WKSTN-01`, also had several established outbound connections to cloud and content delivery network infrastructure.

At first glance, the combination of browser activity, public IP addresses, and a strangely named scheduled task made the incident look like a possible loader or persistence mechanism.

That assumption needed proof.

---

## The Investigation

### 1. Review the sandbox behavior

The first important finding was what the sandbox did not observe:

* No malicious executable was dropped
* No new service was created
* No payload was extracted
* No obvious persistence mechanism was installed

The file opened in a browser and generated web traffic. A second sandbox report identified a password form embedded in the HTML.

That shifted the working theory from "malware loader" to "credential harvesting page."

The likely attack flow was:

1. A user receives a finance-themed HTML attachment.
2. The user opens the file.
3. The HTML renders a fake sign-in page.
4. The user enters credentials.
5. The page submits those credentials to attacker-controlled infrastructure.

This is still malicious, but the response priorities are different. Instead of focusing only on endpoint cleanup, I also needed to determine whether credentials were entered and whether active sessions required revocation.

---

### 2. Review live network connections

I collected established TCP connections:

```cmd
netstat -ano | findstr ESTABLISHED
```

This provided the owning process ID for each connection.

A better PowerShell view is:

```powershell
Get-NetTCPConnection -State Established |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
```

To resolve each connection to a process:

```powershell
Get-NetTCPConnection -State Established |
    ForEach-Object {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($_.OwningProcess)" -ErrorAction SilentlyContinue

        [PSCustomObject]@{
            PID            = $_.OwningProcess
            ProcessName    = $process.Name
            ExecutablePath = $process.ExecutablePath
            CommandLine    = $process.CommandLine
            RemoteAddress  = $_.RemoteAddress
            RemotePort     = $_.RemotePort
        }
    }
```

Most connections belonged to expected browser, productivity, remote-management, security, and operating system processes.

One major gotcha was treating nearby IP addresses as the same indicator. A sandbox might contact one address while the workstation connects to another address in the same provider range. That does not prove malicious activity.

Cloud services frequently rotate across neighboring addresses.

The process, command line, domain, certificate, and event timing matter more than visual similarity between IP addresses.

---

### 3. Inspect common persistence locations

I checked the user and machine startup keys:

```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
```

The entries pointed to expected productivity, cloud-sync, audio-driver, and Windows security components.

Nothing referenced a temporary directory, random executable, script interpreter, or unusual user profile location.

I also checked WMI event consumers:

```powershell
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer
```

Only a standard Service Control Manager event consumer appeared.

That did not prove the system was clean, but it ruled out two common persistence locations.

---

### 4. Review scheduled tasks

I exported the full scheduled task inventory:

```cmd
schtasks /query /fo LIST /v
```

One task under the Windows Application Experience path looked suspicious because it had:

* An unusual name
* Oddly rendered description strings
* A placeholder-looking last-run date
* Multiple actions
* System-level execution

This was the biggest roadblock in the investigation.

The task looked bad in the text listing, but appearances are not evidence.

I exported its XML:

```cmd
schtasks /query /TN "\Microsoft\Windows\Application Experience\<TASK-NAME>" /XML > task.xml
```

The XML showed that it launched the legitimate Windows compatibility telemetry executable with built-in application inventory and appraiser modules.

The strange metadata came from localized resource references, and the old date was a Task Scheduler placeholder artifact.

The task was legitimate.

This was an important correction. Deleting it based only on its name and summary output would have created unnecessary system changes while contributing nothing to containment.

---

### 5. Inspect the TLS certificate

When a suspicious hostname resolves to a shared hosting IP, inspecting the certificate requires Server Name Indication. Connecting to the IP alone may return the wrong certificate.

Using curl:

```cmd
curl -vk --resolve suspicious.example:443:<SERVER-IP> https://suspicious.example/
```

Using OpenSSL:

```bash
openssl s_client -connect <SERVER-IP>:443 -servername suspicious.example -showcerts
```

I looked for:

* Subject and Subject Alternative Name
* Certificate issuer
* Validity period
* Hostname match
* Whether the server used a shared hosting certificate

A valid certificate does not make a site safe. Automated certificate authorities issue certificates to both legitimate and malicious sites.

TLS inspection is attribution evidence, not a malware verdict.

---

## What The Evidence Showed

The combined evidence supported the following conclusions:

* The HTML file was most consistent with credential phishing.
* The sandbox did not demonstrate a dropped executable or secondary payload.
* The Run keys did not contain suspicious entries.
* No malicious WMI persistence was identified.
* The concerning scheduled task was a legitimate Windows component.
* Most endpoint network connections mapped to expected software and cloud infrastructure.
* No confirmed endpoint persistence was found during this review.

What was not definitively proven was whether a user entered credentials into the phishing page. That question required email, browser, identity, proxy, and authentication-log review.

---

## The Root Cause

The root cause was a malicious HTML attachment designed to present a fake authentication form and send submitted information to attacker-controlled web infrastructure.

The endpoint alert was valid, but the incident was initially at risk of being misclassified as persistent malware because normal browser, cloud, and Windows telemetry behavior created noisy sandbox results.

---

## Key Takeaways

* A suspicious IP address is not enough. Tie it to a process, command line, hostname, and timestamp.
* No dropped payload does not mean harmless. Credential theft may happen entirely inside the browser.
* Shared cloud and content delivery infrastructure generates false leads during sandbox analysis.
* Export suspicious scheduled tasks to XML before disabling or deleting them.
* Strange Windows task names, resource strings, and placeholder dates are not automatic indicators of compromise.
* A valid TLS certificate proves encryption and hostname control, not legitimacy.
* Credential phishing requires identity containment, not just endpoint scanning.

---

## Summary

> **Symptom:** A remittance-themed HTML attachment triggered an alert and produced browser and network activity.
>
> **Investigation:** I reviewed two sandbox reports, mapped live connections to processes, checked Run keys, inspected WMI consumers, exported scheduled task XML, and reviewed TLS certificate behavior.
>
> **Root Cause:** The attachment was most consistent with a browser-based credential-harvesting page.
>
> **Resolution:** The phishing indicators were blocked and hunted, persistence checks found no confirmed malicious entries, and the suspicious scheduled task was verified as legitimate Windows functionality.

The phish wanted credentials, but the noisiest suspect turned out to be Windows wearing a trench coat.
