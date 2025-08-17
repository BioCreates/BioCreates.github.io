+++
title = "RDP Brute Force — Sigma Rule and Walkthrough"
slug = "rdp-bruteforce-sigma"
date = "2025-08-17T16:50:10-04:00"
author = "RoninSec"
cover = "/img/rdp-bruteforce-banner.png"
tags = ["sigma", "windows-logs", "event-4625", "rdp", "blue-team"]
keywords = ["sigma", "RDP brute force", "Event ID 4625", "Logon Type 10"]
description = "Detect RDP brute-force attempts using Windows Event ID 4625 (Logon Type 10) and a Sigma rule, with testing notes."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

Goal: Write a Sigma rule to detect RDP brute force attempts (Event ID 4625, Logon Type 10), test it locally, and document gotchas.

<!--more-->

## Overview

This lab demonstrates how to detect RDP brute-force attacks by combining **Sysmon event logging**, **manual event analysis**, and a **Sigma rule**.  
We simulate an attack using Hydra from a Linux environment, verify detection with Windows Event Viewer and PowerShell, and finally formalize the detection logic in Sigma for SIEM use.

---

## Part 0 – Lab Setup

Before diving into the attack and detection, we built a lightweight lab to safely simulate brute-force attempts and capture logs.

### Windows 10 VM (Target)

- Provisioned a **Windows 10 VM** with RDP enabled.  
- Installed **Sysmon** with the *SwiftOnSecurity* configuration for detailed event logging.  
- This VM acted as the victim where brute-force attempts were directed.  

### Attacker Environment

- Used **WSL (Ubuntu on Windows Subsystem for Linux)** to run Linux-native tools.  
- Chose **Hydra** to simulate repeated RDP login attempts against the Windows VM.  

### Monitoring Tools

- Relied on **Windows Event Viewer** as the primary log source.  
- No SIEM was deployed — instead, detections were validated with **manual log review, PowerShell scripts, and Sigma rules**.  

### Repo & Documentation

Created a GitHub repo: [cybersecsim/threat-hunting-rdp](https://github.com/BioCreates/CyberSecSim/tree/main/Threat-hunting-rdp) to store:

- `/artifacts` → Sigma rules  
- `detection.md` → Detection steps  
- `attack.md` → Attack details  
- `/logs` → Logs and screenshots  

This setup provided just enough realism for detection engineering practice **without requiring a full enterprise SIEM or multi-VM infrastructure**.

---

## Part 1 – Visibility First (Sysmon Config + Manual Detection)

Before diving into detection rules, we needed a reliable way to capture the right telemetry.

### Sysmon Installation

- Installed **Sysmon** on a Windows 10 VM.
- Applied the **SwiftOnSecurity Sysmon configuration**, which provides extensive process/network coverage with reduced noise.
- Confirmed capture of:
  - Event ID `4625` — Failed logon attempts
  - Network connections (Sysmon events)
  - Process creations for brute-force tooling

### Manual Detection

1. Opened **Event Viewer** → Windows Logs → Security.
2. Filtered for:
   - `Event ID 4625` (failed logon)
   - `Logon Type 10` (RDP/Terminal Services)
3. Looked for multiple failures from the same IP in a short time window.
4. This confirmed the detection concept **before** formalizing it in Sigma.

{{< image src="WindowsSecurityRDPLog.png" alt="Windows Security log – 4625/LogonType 10" caption="Windows Security log showing repeated 4625 failures (Logon Type 10)" >}}

{{< image src="SysmonRDPLog.png" alt="Sysmon network/process context" caption="Sysmon adds process and network context to the failed RDP attempts" >}}

---

## Part 2 – Attack Simulation (Hydra in WSL)

To simulate brute-force attempts:

- Used **WSL (Ubuntu)** to run `hydra` because RDP brute-forcing isn’t practical in native PowerShell.
- Command example:

```bash
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -t1 rdp://192.168.1.73
````
{{< image src="HydraLogSS.png" alt="Hydra output" caption="Hydra brute-force simulation output from WSL" >}}

* Verified Event Viewer captured multiple 4625 failures tied to the test IP.
---

## WSL-Specific Notes & Gotchas

Using WSL introduced a few extra steps:

* **File Paths** – WSL files live in `/home/king/...`, separate from Windows’ `Documents`.
* **Python/Sigma CLI** – Installed and ran inside a **WSL virtual environment**, not Windows Python.
* **Workflow Choice**:

  * WSL for Linux-native attack tools (Hydra, some Sigma testing).
  * Windows for Event Viewer, PowerShell, Hugo blog editing, and final file storage.
* **Lesson Learned** – Keep repos and docs in one main environment (likely Windows for me) and only use WSL for the pieces that truly require it.

---

## Part 3 – Sigma Rule Creation

Sigma is a **vendor-neutral detection rule format**.
Think of it as a *template* you can convert into Splunk, Elastic, Sentinel, or other SIEM query languages.

**Final Sigma Rule:**

```yaml
title: Possible RDP Brute Force - Multiple 4625 From Single IP
id: rdp-bruteforce-agg-roninsec-v1
status: experimental
description: Flags potential RDP brute force based on repeated failed logons (Event ID 4625) from the same source IP within a short timeframe.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType: 10
  timeframe: 10m
  condition: selection | count(IpAddress) by IpAddress >= 5
fields:
  - IpAddress
  - TargetUserName
  - WorkstationName
falsepositives:
  - User mistyping password repeatedly
level: medium
tags:
  - attack.t1110
```

> Note: Some Sigma backends handle aggregation slightly differently. If your converter complains, we’ll adjust to its expected syntax.

---

## Part 4 – Local Validation (Without a SIEM)

Since we didn’t have a SIEM hooked up, we validated the Sigma logic with PowerShell:

```powershell
$since = (Get-Date).AddMinutes(-10)
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$since}

$parsed = $events | ForEach-Object {
  $x = [xml]$_.ToXml()
  [pscustomobject]@{
    TimeCreated = $_.TimeCreated
    IpAddress   = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
    LogonType   = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'}).'#text'
    Account     = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
  }
}

$parsed |
  Where-Object { $_.LogonType -eq '10' } |
  Group-Object IpAddress |
  Where-Object { $_.Name -and $_.Count -ge 5 } |
  Select-Object Name, Count
```

If the output shows any IP with `Count over 5`, that’s the brute-force activity we simulated.

{{< image src="PSOutputExample.png" alt="PowerShell output" caption="PowerShell grouped results: 5+ failed logons from same IP" >}}

---

## Part 5 – Converting the Sigma Rule

Using **Uncoder.io** or `sigma-cli`, the YAML rule can be translated into:

* **Splunk SPL**
* **Elastic Query DSL**
* **Azure Sentinel KQL**

**Example Splunk Query:**

```spl
index=winlogs EventCode=4625 LogonType=10
| stats count by IpAddress
| where count >= 5
```

---

## Conclusion

This lab walked through the **full lifecycle of detecting RDP brute-force attempts**:

- Building visibility with **Sysmon**  
- Simulating an attack using **Hydra**  
- Validating detection manually in **Event Viewer** and **PowerShell**  
- Converting the logic into a portable **Sigma rule**  

---

**Key takeaway:**  
👉 Always validate your detection ideas manually before writing rules. Doing so ensures that the logs you rely on are actually being collected and that your rule logic aligns with real-world attack patterns.

---

While this lab focused on **RDP brute force**, the same workflow can be applied to almost any attack technique:

1. **Visibility first**  
2. **Manual confirmation**  
3. **Sigma (or equivalent) codification**  
4. **SIEM translation**  

---

In future labs, I’ll expand this into **automated alerting with Wazuh** and show how Sigma rules can power **proactive detection pipelines**.
