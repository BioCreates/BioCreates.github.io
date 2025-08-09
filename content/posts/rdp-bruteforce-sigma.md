+++
title = "RDP Brute Force — Sigma Rule and Walkthrough"
slug = "rdp-bruteforce-sigma"
date = "2025-08-09T08:16:10-04:00"
#dateFormat = "2006-01-02" # This value can be configured for per-post date formatting
author = "RoninSec"
#authorTwitter = "" #do not include @
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

## Events to watch
- **4625** (failed logon), **Logon Type = 10** (remote/Terminal Services)
- Optional context: multiple failures from the same source IP/username in a short window.

## Sigma (draft v1)
```yaml
title: RDP Brute Force - Failed Logons Type 10
id: rdp-bruteforce-4625-type10-roninsec-v1
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType: 10
  condition: selection
level: medium
tags:
  - attack.t1110
