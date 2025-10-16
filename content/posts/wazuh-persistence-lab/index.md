+++  
title = "Detecting Persistence with Wazuh + Sysmon"  
slug = "detecting-persistence-wazuh-sysmon"  
date = "2025-10-15T21:00:00-04:00"  
author = "RoninSec"  
cover = "persistence-wazuh-banner.png"  
tags = ["wazuh","sysmon","persistence","windows","blue-team","detection"]  
keywords = ["Wazuh","Sysmon","persistence detection","scheduled task","run key","custom rule"]  
description = "Simulate Windows persistence (schtasks / Run key), verify Sysmon logs, confirm Wazuh ingestion, and write a custom Wazuh rule to generate alerts."  
showFullContent = false  
readingTime = true  
hideComments = false  
draft = false  
+++

In this lab, I explored how Wazuh detects Windows persistence techniques using Sysmon logs and custom rules. While Sysmon recorded every event perfectly, I learned that Wazuh doesn’t automatically alert unless a rule tells it to. Here’s how I found, fixed, and confirmed a missing detection.

I started by creating a scheduled task that launches calc.exe every few minutes to simulate persistence.
{{< image src="powershell1.png" alt="powershell1" >}}


Confirmed they were seen by Sysmon
{{< image src="powershell2.png" alt="powershell2" >}}


By searching "sysmon" I was able to narrow down the logs and then I narrowed it further between 10:30PM & 11PM and was able to find the event below.
{{< image src="regdetection.png" alt="regdetection" >}}

But in a real environment manually going through alerts is a nightmare so I used this query to find Sysmon alerts with Event ID 1 (Process creation):
	data.win.system.providerName:"Microsoft-Windows-Sysmon" AND data.win.system.eventID:1

Then I quickly found this entry 
Oct 14, 2025 @ 22:56:59.067
{{< image src="regdetection2.png" alt="regdetection2" >}}

Expanding it shows more details like the exact cmd line
{{< image src="regdetectioncmd.png" alt="regdetectioncmd" >}}

side note, something I learned was that when setting creds via net user (which I did to set up RDP on the target machine) will show the password in cleartext in the sysmon event logs
{{< image src="netuser.png" alt="netuser" >}}

It does not show up in built in WindowsEventLogs unless you enable Advanced auditing by doing the following:

1. `Win + R` → `secpol.msc`
2. Advanced Audit Policy Configuration → **System Audit Policies** → **Detailed Tracking**
3. Double-click **Audit Process Creation** → check **Success** (and **Failure** if you want) → **OK**.

I did not do the above, it was not in the scope of this particular post but we can circle back to it at a later date if needed.

Moving on...
## Detecting the schtasks task creation command

Went through the ringer a bit on this one.

So first I created the schtask
```cmd
schtasks /create /sc minute /mo 50 /tn "TestTask" /tr "calc.exe"
```

Can confirm that the task was created and ID'd by Sysmon logs Event ID 1

{{< image src="sysmoneventid.png" alt="sysmoneventid" >}}


But it was not showing up in Wazuh AT ALL... I went through a ton of research to find out why but ... the TLDR version of it is below
### 🧩 Gotcha Moment — When Sysmon Events Go Missing in Wazuh

This one had me chasing ghosts. I could see the Sysmon event for `schtasks.exe` in Windows Event Viewer, but it never showed up in Wazuh. At first, I suspected a bad query — but the real issue was deeper: **Wazuh doesn’t alert on events unless a rule explicitly tells it to.**

By default, Wazuh receives the raw Sysmon data but ignores anything without a matching rule. Since there was no rule for `schtasks.exe` process creation (Event ID 1), those events never made it into the Wazuh alerts index.

The fix was to add a **custom rule** inside the Wazuh Manager container at: 
`/var/ossec/etc/rules/local_rules.xml`

```xml
<group name="windows,sysmon,persistence,">
  <rule id="100502" level="10">
    <description>Sysmon ProcessCreate: schtasks.exe observed</description>
    <if_group>sysmon_event1</if_group>
    <match>\\schtasks.exe</match>
  </rule>
</group>
```

After saving the file and restarting Wazuh with:
```bash
sudo docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

Then I ran the scheduled task creation command again

```cmd
schtasks /create /sc minute /mo 50 /tn "TestTask" /tr "calc.exe"
```

Then...

BOOM!
{{< image src="success.png" alt="success" >}}

{{< image src="success1.png" alt="success1" >}}

I can now see it in Wazuh.

## 🧩 Wrapping It Up

This lab was a good reminder that **detection isn’t just about data collection — it’s about interpretation.** Sysmon saw the event immediately, but Wazuh didn’t raise its hand until I told it what to look for. Once that rule was in place, everything clicked.

The takeaway is simple but critical:

> Wazuh won’t alert on what it doesn’t understand — if you want visibility, you have to teach it what matters. I guess that's why people LOVE tuning SIEMs and alert tools.

So if you’re building detections, don’t stop at collecting logs. Always verify that your rules actually _fire_ the way you expect. Even the best telemetry means nothing without context.

“With custom rules firing properly, Wazuh is now ready for deeper endpoint detection tests — next, I’ll simulate privilege escalation and lateral movement to see how Wazuh responds.”