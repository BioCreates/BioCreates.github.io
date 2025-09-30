+++
title = "DFIR Journey: DC Forensics — Case of the Szechuan Sauce"
slug = "stolen-szechuan-sauce-journey"
date = "2025-09-29T12:00:00-04:00"
cover = "cover.png"
author = "RoninSec"
tags = ["dfir", "windows-forensics", "memory-forensics", "timeline", "malware", "network"]
keywords = ["DFIRMadness", "Szechuan Sauce", "coreupdater", "Meterpreter", "spoolsv", "mactime"]
description = "Hands-on write-up of DFIRMadness Case 001 — exploring memory, disk and network evidence for coreupdater / Meterpreter on a domain controller."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# DFIR: DC Forensics — Case of the Szechuan Sauce
A hands-on memory, network, and disk analysis reproducing DFIRMadness Case 001; RDP intrusion → Meterpreter → timeline & IOCs.

This is my experience following the [DFIRMadness Case 001 - The Stolen Szechuan Sauce](https://dfirmadness.com/the-stolen-szechuan-sauce/) 

I learned a lot about DFIR, the tools used to do this such as Volatility2 and plugins, Plaso Log2Timeline, Floss, Cape, Clamscan, ewfmount, FTK Imager, mmls, Registry explorer and a few other things along with some hiccups along the way due to the age of the post some things would not work. I analyzed memory dumps, PCAP and Disk Images. As well as worked with Plaso's Log2Timeline and used Mark Zimmerman's Timeliner tool to parse through the log and using relevant Event IDs and IOC's found during the various posts 

At the start In order to keep with the Author "James" suggestions I decided to follow the guide [here](https://dfirmadness.com/building-a-dfir-analysis-fort/) to set up a DFIR Station using SANS SIFT Workstation. Unfortunately I could not get to integrate it with the Remnux image but I will continue my attempts on that on another day. Instead what I did was create the SIFT workstation and was able to run all of the needed commands and tests there.. with some minor hiccups and gotchas. I will elaborate more on that  throughout this post as necessary.

I learned A LOT during this, but I also realized how much more there is out there. As Socrates stated "The more you learn the more you realize how little you know"

## The Beginning

I started by setting up the SIFT workstation VM, when launching it, I would keep freezing up, if you look towards the right of the screenshot below it was blurred and froze there
{{< image src="SIFTWorkstationFreeze.png" alt="SIFTWorkstationFreeze" caption="SIFTWorkstationFreeze" >}}

After some troubleshooting I noticed the following was the fix:
Had to change Graphic Controller to VMSVGA
{{< image src="VMGraphic.png" alt="VMGraphic" caption="VMGraphic" >}}
## SIFT Workstation Online

Once the SIFT VM was operational I took a snapshot in VirtualBox as I believe you should do with any fresh VM in case something goes wrong and you need to go back to a stable edition

For some reason despite the VM having bridged mode enabled, I could not get it to get an IP. Ran sudo dhclient enp0s17 to get an IP 
{{< image src="dhclient.png" alt="dhclient" caption="dhclient" >}}

After it had an IP I ran the basic sudo apt update then upgrade. once that was done I took another snapshot

> **Time note:** All times shown are **UTC** unless noted; some screenshots reflect **local time** based on the tool’s default.
## Memory Analysis

Each artifact was available for download on the main case 001 page [here](https://dfirmadness.com/the-stolen-szechuan-sauce/)

I downloaded the memory zip file "DC01-memory.zip"

Sha256sum for that file is 

86658d85d8254e8d30dccc4f50d9c2a8b550a101d2e78a6d932316849e37ad80  DC01-memory.zip

There is plenty covered in the actual post over at DFIRMadness so I won't go into that much detail. This is just a record of my efforts to understand, learn and experience the case of the Szechuan sauce.

Moving on..I don

I ran the following volatility commands/plugins

```
$ vol.py -f citadeldc01.mem pstree|tee pstree.out
```

{{< image src="pstree.png" alt="pstree" caption="pstree" >}}

```
$ vol.py -f citadeldc01.mem pslist|tee pslist.out
```

{{< image src="pslist.png" alt="pslist" caption="pslist" >}}

```
$ vol.py -f citadeldc01.mem malfind|tee malfind.out
```

{{< image src="malfind.png" alt="malfind" caption="malfind" >}}

```
$ vol.py -f citadeldc01.mem netscan|tee netscan.out
```

{{< image src="netscan.png" alt="netscan" caption="netscan" >}}

The explanations and findings are thoroughly explained on the DFIR Madness site so I'll try to just keep it short so it's not too much to read. This case took me 2 weeks to complete so condensing it without omitting critical details will be a challenge.

Continuing...

As you can see above I created a few output files
{{< image src="memoryls.png" alt="memoryls" caption="memoryls" >}}

While looking through netscan.out I used less to easily search for keywords

command  I used is below
```
less -N -S netscan.out
```

Once in less I used "/ESTABLISHED" to parse for established connections in the logs
{{< image src="lessestablishedfilter.png" alt="lessestablishedfilter" caption="lessestablishedfilter" >}}

{{< image src="establishednentscan.png" alt="establishednentscan" caption="establishednentscan" >}}

Used the following command to find all of the services in question with Established connections

```bash
$ grep -Ei '(ismserv\.exe|lsass\.exe|coreupdater\.ex|dfssvc\.exe|dfsrs\.exe)' netscan.out | grep -E 'ESTABLISHED' | less -N -S
```

{{< image src="lessgrepnetscan.png" alt="lessgrepnetscan" caption="lessgrepnetscan" >}}

There were a few services with established connections. So I researched them and found the following

### `ismserv.exe`

- **Name/role:** _Intersite Messaging_ service (AD inter-site replication over SMTP).
- **Path:** `C:\Windows\System32\ismserv.exe` (Service name: `IsmServ`).
- **Is it common?** Rare today. Most AD sites use RPC, not SMTP. Often **Disabled/Manual**.
- **Network behavior:** Usually **no connections** unless SMTP-based replication is explicitly configured. No reason to talk to the public Internet.
- **Proc count:** **1** if running at all.
- **Red flags:** Running on a DC without a reason, unexpected outbound, wrong path, or odd parent.

### `lsass.exe`

- **Name/role:** _Local Security Authority Subsystem Service_ (auth, tokens, on DC it also hosts KDC/LDAP).
- **Path:** `C:\Windows\System32\lsass.exe` (protected; parent should be `wininit.exe`).
- **Network behavior (DC):** **LISTENING** on LDAP/LDAPS (389/636), Kerberos (88), kpasswd (464), RPC endpoint mapper (135) + dynamic RPC; **ESTABLISHED** to **other DCs/clients**. **Not** to random Internet IPs.
- **Proc count:** **exactly 1** legit instance.
- **Red flags:** >1 instance, wrong path (e.g., `C:\Users\...\lsass.exe`), Internet egress, suspicious parent, unsigned.

### `coreupdater.exe` _(3rd-party updater name; varies)_ -- Main Suspect

- **Name/role:** generic “updater” name used by legit apps (Corel/Adobe/etc.) **and** by malware.
- **Path/company:** depends—**must check** file path, signer, hash.
- **Network behavior:** Legit updaters often do **HTTPS (443) to vendor domains**. On a **Domain Controller**, any consumer-style updater is **odd**.
- **Proc count:** usually **1** on demand or via a scheduled task.
- **Red flags:** runs as `SYSTEM`, lives in temp/odd folders, unsigned, arbitrary cloud IPs, runs on a DC, strange parent (`svchost.exe` rarely launches updaters).

### `dfssvc.exe` DFS (Distributed File System)

- **Name/role:** _DFS Namespace_ service (DFSn—manages DFS namespace referrals).
- **Path:** `C:\Windows\System32\dfssvc.exe` (Service: `Dfs`).
- **Network behavior:** RPC (135 + high ports) with **domain members and other namespace servers**. **LAN only**; Internet egress uncommon.
- **Proc count:** **1**.
- **Red flags:** outbound to Internet, non-system path.

### `dfsrs.exe`

- **Name/role:** _DFS Replication_ service (replicates DFS folders and SYSVOL between DCs).
- **Path:** `C:\Windows\System32\dfsrs.exe` (Service: `DFSR`).
- **Network behavior:** RPC to **partner DCs/servers**, traffic stays inside the domain/site (or site-to-site over private links). No need for Internet peers.
- **Proc count:** **1**.
- **Red flags:** connections to public IPs, wrong path, odd user, unexpected create time.

> heuristic: **DC system processes talk to DCs/clients**; **updaters talk to vendors**; **nothing core should be chatting with random public IPs**.

Funnily enough while I was taking a look at the coreupdater.ex process instance in netscan I noticed that the process extension was cut short to .ex instead of .exe, I later found out that it isn't unheard of for that to happen, couldn't get a straight answer why other than terminal formatting and other reasons but it still caught my eye and so I believed it to be the prime suspect as well as it had an unknown IP that was outside of the LAN.
{{< image src="coreupdaterinNetscan.png" alt="coreupdaterinNetscan" caption="coreupdaterinNetscan" >}}

However I found out that truncated names in netscan/text output often happen because columns get clipped or fixed-width formatting so, not something to look for going forward.

# IoC Check
Host IP & Port: 10.42.85[.]10:62613
Potentially Malicious process: coreupdater.ex Time: 2020-09-19 03:56:52 UTC
Potential Attacker, Remote IP: 203.78.103.109:443
PID: 3644

Cross-checked that IP with virus total and got some interesting results stating the IP is malicious.
{{< image src="VTIoC.png" alt="VTIoC" caption="VTIoC" >}}

Given the age of the DFIRMadness writeup there have been many others that have submitted files to virus total by now and the threat we are working with is now very well known so it's no surprise that we are getting immediate hits when looking it up. In a more modern setting many malicious links are new and are not usually reported during investigation (unless you're lucky) so searching it up in VT might not always yield results, something to keep in mind during real-word triaging.
## PSTree
{{< image src="coreupdaterinpstree.png" alt="coreupdaterinpstree" caption="coreupdaterinpstree" >}}
PID:3644
Date 2020-09-19 03:56:37 UTC

## Malfindings
	Using the malfind volatility plugin

In the article he mentions looking for code sandwiches, examples can be found below
{{< image src="malfindsandwiches.png" alt="malfindsandwiches" caption="malfindsandwiches" >}}
# IoC Check 
Above I also highlighted the potentially malicious process. spoolsv.exe

Another thing to look for is MZ in the memory Hex and or DOS Mode

MZ = Portable Executable
READ_WRITE_EXECUTE = No executable can be found on disk, running off of memory, what was in the article read 'There is no file on disk for this executable code in memory.'

Pro Tip: XOR is a common obfuscation technique and can be seen in the assembly above
{{< image src="pedetected.png" alt="malfipedetectedndsandwiches" caption="pedetected" >}}


## Malfind Dump 

We can use malfind to dump processes into a new dir so we can examine the file and run Clam Scan AV against them as well, Clam Scan will help us locate malicious processes. ClamAV is a free and open source antivirus software toolkit. It is really cool and you can learn more about it here https://www.clamav.net/

```
vol.py -f citadeldc01.mem --profile=Win2012R2x64 malfind -D /maldump
```
The command above yielded the dmp files below
{{< image src="maldump.png" alt="maldump" caption="maldump" >}}
## Gotcha #1 
When running the update command 
```bash
sudo freshclam
```
I got an error the log file was locked, meaning the service was running and could not be written while that was the case, hence it could not update, the rest of the commands are shown below
{{< image src="clamerrorandfix.png" alt="clamerrorandfix" caption="clamerrorandfix" >}}

## ClamScan Findings
Ran Clamscan on the maldump dir I created to store the malfind process dump
```
clamfind -o *
```
## Findings
{{< image src="calmfindings.png" alt="calmfindings" caption="calmfindings" >}}

# Meterpreter

Appears clamscan found Meterpreter using its scan engine, Meterpreter is a stealthy, in-memory payload used in penetration testing that lets an attacker remotely control a compromised system—running commands, uploading/downloading files, and pivoting—without writing files to disk.

Created a folder named meterpreter because the infected files appear to have been meterpreter exploits and copied the dump files into that folder
{{< image src="clammeterpreter.png" alt="clammeterpreter" caption="clammeterpreter" >}}

### Next Step is to use FireEye's FLOSS FireEye Labs Obfuscated String Solver

FLOSS is an open-source tool that automatically detects, extracts, and decodes obfuscated strings from Windows PE files to speed malware analysis and incident response.  
It uses advanced static-analysis techniques (including emulation) to recover strings that simple tools miss.  
Those recovered strings often contain high-value indicators of compromise—malicious domains, IPs, file paths, and configuration data—but analysts still need domain knowledge to interpret the results.

# Gotcha #2

Given the age of the DFIRMadness post I was following there have been some changes to some of the tools. Floss is now actually "flare-floss"

So in order to get it to work I had to do the following:

Installed it using 
```
sudo pip install flare-floss
```

added it to PATH
```
'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
```

in the .local... part ensure the proper path for the file is there
	Ran into a few issues when running, at first I Thought it just wouldn't accept a .dmp file because in the GitHub Repo and in the help menu it referenced examples using .exe's
	- The reason it was failing was because FLOSS requires the starting bytes to be MZ 0x4d 0x5a? I think, error I got is below
{{< image src="flosserror.png" alt="flosserror" caption="flosserror" >}}

At the time of this writing however I went back to grab the exact command I ran floss again and did not get the error above instead I got this error
{{< image src="flosserror2.png" alt="flosserror2" caption="flosserror2" >}}
Thank the mighty penguin for it's easy to read debugger, I re-ran the command using the --format s64 option and option argument
{{< image src="flosssuccess.png" alt="flosssuccess" caption="flosssuccess" >}}

At the end of the output we can find the tcp callback address for the questionable IP we found earlier 
flossfindings

Memory artifacts (malfind dumps + FLOSS strings) indicate shellcode injected into `spoolsv.exe`

Ran Volatility pstree plugin with the -v argument to get file paths and got the file path for the coreupdater process

```
vol.py -f citadeldc01.mem --profile=Win2012R2x64 pstree -v > pstreewpath.out
# -v displays process path 

from DFIR: 'It will reveal the full path to the image that loaded the process into memory.'
```

{{< image src="coreupdaterpathviavol.png" alt="coreupdaterpathviavol" caption="coreupdaterpathviavol" >}}

# IoC Check
Host IP & Port: 10.42.85.10:62613
Malici0ous process: spoolsv.exe
Potentially Malicious process: coreupdater.ex Time: 2020-09-19 03:56:52 UTC
Potential Attacker, Remote IP: 203.78.103.109:443
PID: 3644

## Progress So far

- Used Volatility on the memdump and created output files for various plugins, pstree, pslist, netscan, etc.
- Reviewed netscan for established connections, located a few services, noticed only one reaching out to an external IP that when searched up returned a plethora of malicious indicators.
- Malfind was used to flag _and_ dump memory sections from the processes that it flagged. We dumped these into a directory called maldump.
- From the maldump directory, we used Clam Scan against those objects to find malicious code/infected files and we found Meterpreter
- We made a note of which process was the guilty one by matching the address found in the name with the PID/Address output of malfind
- Then we ran FLOSS against the known infected data objects to find IOC’s like domain names or IP addresses. We found an IP Address.
- We now have a suspicious process that is not normally present on Windows servers communicating with **203.78.103.109** which lived in Thailand around the time of the potential incident.
- We know that process 3724 Spoolsv.exe has Meterpreter injected into it and is now set up to communicate back to the suspicious IP Address, the same address that coreupdater.exe is communicating with.
- Meterpreter can migrate itself from one process to another.
- By looking at the thread count we can tell that one process is inactive and the other is not.

In the write up James writes:

```
Knowing that times recorded in Memory are not absolutes the following hypothesis emerges: Somehow this coreupdater.exe landed on the system and was communicating to a remote system and is tied to malware on the system. At some point, it injected its malicious code into Spoolsv.exe where it is living now- or was at collection time. This also tells us something else. The original malware had to be at the SYSTEM level. Which on a DC means the attacker likely has the Domains entire list of credentials. This just got ugly.
```

The reason I think he said that is because it appears that Malicious code was injected into spoolsv.exe (Windows Print Spooler Service) which normally runs as the SYSTEM account and code injected into a process inherits that process' security token. If `spoolsv.exe` really was running as `NT AUTHORITY\SYSTEM`, the injected code would execute with SYSTEM privileges. This is strong circumstantial evidence.

# Next: Disk Analysis

EWF = Expert Witness File Format, A legally admissible bit for bit copy of target hard drive.
### Step 1: Mount EWF Compressed Image

From within ../disk/E01-DC01 directory run the following command ewfmount E01File.E01 /mnt/ewf
{{< image src="ewfmount.png" alt="ewfmount" caption="ewfmount" >}}


### Step 2: List Partition Layout

Use mmls to view the layout of the EWF image

```
mmls E01File.E01
```
{{< image src="mmls.png" alt="mmls" caption="mmls" >}}

### Step 3: Mount the Windows Partition

Windows Partition in this case is the first one, with the start byte at 2048 and end at 718847

To mount this we used the following command
```
mount -t ntfs-3g -o loop, ro,show_sys_files,stream_interface=windows,offset=$((2048*512)) /mnt/ewf/ewf1 /mnt/windows_mount
```
{{< image src="mountcommand.png" alt="mountcommand" caption="mountcommand" >}}
mount via a loop device, **read only**,show system files, read out ADS (Alternate Data Streams), start the offset at byte number (**2048** sectors of **512** bytes).

A short explanation for a loop device is essentially a virtual block drive backed by a regular file. Once mounted the kernel redirects read/write requests on /mnt/windows_mount (in this case) back into the file that underlies it--hence the name "loop". It's like a loopback address but in the form of storage.

### Step 4: Ls the files

```
cd /mnt/windows_mount
ls /mnt/windows_mount
```
{{< image src="lsmountedimage.png" alt="lsmountedimage" caption="lsmountedimage" >}}
### Step 5: Do it all again with the OS Partition

```
sudo umount /mnt/windows_mount
```
{{< image src="umount.png" alt="umount" caption="umount" >}}

## On the OS Partition
```
mount -t ntfs-3g -o loop, ro,show_sys_files,stream_interface=windows,offset=$((718848*512)) /mnt/ewf/ewf1 /mnt/windows_mount
```
{{< image src="mountOSpartition.png" alt="mountOSpartition" caption="mountOSpartition" >}}

Took a look around found some interesting items

### Enumerate Users on DC
{{< image src="dcusers.png" alt="dcusers" caption="dcusers" >}}
 
### Administrator is a user of interest

Checked Contents of Administrator
{{< image src="Admincontents.png" alt="Admincontents" caption="Admincontents" >}}

Found Interesting Artifacts in "Recents" 
	Recents folder contains .lnk files of files and/or folders that have been recently opened. It is isn't an end all be all type of finding but by using "strings" or "exiftool" to extract legible strings or metadata we can learn more about the recent files most importantly where they are located. 

```
# -e = encoding type to look for -l = 16-bit little-endian (UTF-16LE)
strings -el Beth_Secret.lnk 

# You can also run it without the -el option, I will show both outputs below, I prefer without the -el
```

{{< image src="stringsBethSecret.png" alt="stringsBethSecret" caption="stringsBethSecret" >}}

```
exiftool Beth_Secret.lnk

# exiftool is awesome because it provides all metadata including Create, Access and Modify Date. But since this is a .lnk file it’s really showing the shortcut’s own timestamps (and any snapshot of the target file’s times recorded when the link was made), not the current live access time of the target file.
```

{{< image src="exiftoolBethSecrets.png" alt="exiftoolBethSecrets" caption="exiftoolBethSecrets" >}}

Checked that directory for it's contents
{{< image src="lssecretfileshare.png" alt="lssecretfileshare" caption="lssecretfileshare" >}}

There's the Szechuan sauce file! along with a few other assumed secrets, hence the "secret" folder

Not much else I can find from here, Moved on to extracting the Registry Hives of Interest such as SYSTEM & SOFTWARE

In the article he mentions drag and drop between VMs, I'm not sure how to make that work, it was not working for me so I just ran a simple http server from the sift workstation using

```
simple python http server running off port 8080 from current directory
python -m http.server 8080
```

To get the most accurate picture of the SYSTEM hive, the hive logs are required for proper analysis. Without the logs, the data will be incomplete and insufficient.

I used the following command to create a zip file with the SYSTEM Reg Hive
```
# the -e is to password protect the file
zip -e reghives.zip /mnt/windows_mount/Windows/System32/config/SYSTEM* 
```

Started the http server from the zip file directory
{{< image src="hivezip.png" alt="hivezip" caption="hivezip" >}}

Used wget from W10 VM (To Be safe I'd rather , and I'd recommend anyone not transfer potentially malicious artifacts into anything other than a sandbox/vm)
{{< image src="wget.png" alt="wget" caption="wget" >}}

I can confirm the GET was also received on the SIFT workstation end
{{< image src="getconfirm.png" alt="getconfirm" caption="getconfirm" >}}


## Registry Explorer

Opened up Reg Explorer on my Win10 VM > Extracted reghives.zip > Opened Hive in Reg explorer and began by checking:
### TimeZone
{{< image src="regexplorer.png" alt="regexplorer" caption="regexplorer" >}}
Appears they are on Pacific Standard time

### Computer name
{{< image src="regexplorer2.png" alt="regexplorer2" caption="regexplorer2" >}}
DC Hostname = CITADEL-DC01
## Network Shares
{{< image src="regexplorer3.png" alt="regexplorer3" caption="regexplorer3" >}}

Fileshare on DC is the one we saw earlier "Fileshare"

## Coreupdater
{{< image src="regexplorer4.png" alt="regexplorer4" caption="regexplorer4" >}}

Searched up Coreupdater and found it under services, within System32 folder..

## Autoruns

During an incident from the USB drive the following command can be ran
`.\autorunsc64.exe -accepteula -a * -s -h -c > .\autoruns-citadeldc01.csv`

I opened the CSV in Timeline Explorer and triaged the usual hiding spots (Run keys, Services, Scheduled Tasks, hijacks) by filtering for **Enabled** + **Unsigned** entries.

**Findings (two pivots):**

1. **Registry Run key → hidden PowerShell loader**  
    `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\coreupdate` launched PowerShell with a command that referenced `HKLM:\Software\9sEoCawv`. The value was nested **Base64 → UTF-16 → Base64 (GZIP)** that decoded to a script starting a hidden 64-bit PowerShell and executing **in-memory shellcode** (`VirtualAlloc` → copy bytes → `CreateThread` → `WaitForSingleObject`). Capa on the decoded blob showed loader behavior consistent with **file-less execution**.  
    _(Screenshots to keep: registry key hit; CyberChef decode; capa snippet.)_
    
2. **Service → suspicious binary in System32**  
    `coreupdater.exe` registered as a **service** and lived in **C:\Windows\System32** but was **unsigned**. On a DC, that’s a red flag and implies privileged write access. Detonation in Joe Sandbox identified it as a **Meterpreter** payload with C2 **203.78.103.109**.  
    _(Screenshots to keep: “Enabled & Unsigned” filter; sandbox IOC/MITRE panels.)_
    

**Why it matters:**  
We have two persistence mechanisms: (a) a registry-based PowerShell loader that runs shellcode from memory, and (b) a System32 service binary calling out to the same adversary infrastructure seen elsewhere in the case. Together they point to **elevated access and long-term persistence** on the DC

## Pcap Analysis with Snort, Tcpdump & Wireshark

In DFIR he used tcpdump, it was fun to follow along and I learned a lot but I wanted to take this opportunity to learn more about wireshark so with the help of Chris Greer I learned quite a bit, check out his channel [here](https://www.youtube.com/@ChrisGreer)

I started by installing Snort and pointing its `HOME_NET` to the target subnet:

`sudo snap install snort sudo nano /etc/snort/snort.debian.conf   # set HOME_NET 10.42.85.0/24`

If you don’t know the subnet ahead of time you can confirm it from the pcap with:

`sudo tcpdump -nr case001.pcap 'host 10.42' -c15`

{{< image src="pcap.png" alt="pcap" caption="pcap" >}}

To be able to find the Snort config quickly later I installed `locate` and updated its DB.  
Tested the configuration:

`snort -c /etc/snort/snort.conf -T -i lo`

{{< image src="snortconftest.png" alt="snortconftest" caption="snortconftest" >}}

---

### Reducing the Noise

The pcap had ~412 k packets (`capinfos case001.pcap`) {{< image src="capinfos.png" alt="capinfos" caption="capinfos" >}} so I ran Snort in offline mode, only alerting to console and saving to a text file:

`sudo snort -c /etc/snort/snort.conf -r case001.pcap -q -K none -A console | tee snort.out wc -l snort.out    # only a few hundred alerts`

{{< image src="snort2.png" alt="snort2" >}}

Right away Snort flagged brute-force RDP from **194.61.24.102** to **10.42.85.10**, followed by lateral RDP moves inside the subnet.

{{< image src="snort3.png" alt="snort3" >}}  
{{< image src="snort4.png" alt="snort4" >}}

A quick tcpdump filter confirmed an Nmap scan from the same IP:

{{< image src="nmap.png" alt="nmap" >}}
`Grabbed image above from DFIR, did not get to grab from my terminal`
This gave us two key external IOCs: **194.61.24.102** (initial access) and **203.78.103.109** (later C2).

---

### Mapping Connections

To quantify internal ↔ external traffic I used tcpdump with SYN-flag filters:

`# internal hosts reaching out tcpdump -nttttr case001.pcap 'tcp[13]&0x3f=0x02 and src net 10.42.85.0/24 and not dst net 10.42.85.0/24' \ | awk '{print $6}' | cut -d. -f1-4 | sort | uniq -c | sort -nr`

{{< image src="tcpdump.png" alt="tcpdump" >}}

`# external hosts initiating to internal tcpdump -nttttr case001.pcap 'tcp[13]&0x3f=0x02 and dst net 10.42.85.0/24' \ | awk '{print $4}' | cut -d. -f1-4 | sort | uniq -c | sort -nr`

{{< image src="tcpdump2.png" alt="tcpdump2" >}}

These showed ~29 k inbound SYNs and ~23 k outbound SYNs.  
Internal RDP conversations (port 3389) were isolated the same way:

`tcpdump -nttttr case001.pcap 'tcp port 3389 and src net 10.42.85.0/24 and dst net 10.42.85.0/24' -c15`

{{< image src="tcpdump3.png" alt="tcpdump3" >}}

---
### Pulling the Malware

Using Wireshark search (`coreupdater.ex`) and “Follow TCP Stream” between 194.61.24.102 and the DC, I found a simple Python HTTP server delivering **coreupdater.exe**.

{{< image src="wireshark.png" alt="wireshark" >}}

I exported that object from the capture, hashed it

`sha256sum coreupdater.exe # 10f3b92002bb98467334161cf85d0b1730851f9256f83c27db125e9a0c1cfda6`

and confirmed on VirusTotal that it’s malware.  
Joe Sandbox further identified it as a **Meterpreter** payload with C2 at **203.78.103.109**.

{{< image src="mitre.png" alt="mitre" >}}

---

### Quick Takeaways

- **Initial access:** 194.61.24.102 brute-forced RDP to 10.42.85.10 (Domain Controller).
- **Lateral movement:** Same IP pivoted to another internal host via RDP.
- **Payload delivery:** coreupdater.exe served over plain HTTP from 194.61.24.102.
- **Command & Control:** coreupdater.exe called back to 203.78.103.109 (Thailand).
- **Persistence link:** the same binary appears later in disk and autoruns artifacts.

---

**Key IOCs to carry forward**  
`coreupdater.exe` - SHA256: `10f3b92002bb98467334161cf85d0b1730851f9256f83c27db125e9a0c1cfda6`  
IPs: **194.61.24.102**, **203.78.103.109**

This phase tied network activity to the malware found elsewhere in the case and showed exactly how it entered and spread inside the network.

Next... Sleuth kit FLS & Timeline Generation 
## FLS (Filename Layer Tools)

> From DFIR:
> "FLS is used to extract a _quick picture_ of the history the Operating System via the disk image. The FLS tool is run against each partition of the disk image and the results are placed into body file. That body file is processed by the program `mactime` and output to a CSV. If we spend 5 additional minutes we greatly enhance the resultant CSV by adding the timeline of data that was resident in memory at the time of capture. Many events relevant to an investigation live in the memory of the victim machine."
> 
> Volatility has a cool plugin named timeliner that will parse memory images for interesting events with timestamps and will output it to a body file.
> 
> Image files = forensic image, sector by sector copy of a storage medium. 
> Body files = structured tab delimited  text file that lists file or artifact timestamps (MAC Times, etc) and metadata, it's a timeline database, the output will be a CSV file
> 
> So we can use FLS to enumerate a disk image and produce a body file of file-system timestamps, Volatility's timeliner will parse data from memory and also place it in a body file of file stamped memory artifacts, then we combine the body files which can then be fed into mactime which generates a unified CSV timeline for investigation.

Diagram from [DFIR](https://dfirmadness.com/triage-disk-analysis-case-001/) below
{{< image src="flsdfir.png" alt="flsdfir" >}}

## Running FLS

FLS requires the start byte value for each partition. The start byte can be found using mmls that we used earlier.

Commands for FLS in this case are below

First Partition
```
fls -m -r -o 2048 /mnt/ewf/ewf1 > fls-drive-dc01.body
```
{{< image src="fls.png" alt="fls" >}}

Second Partition
```
fls -m -r -o 718848 /mnt/ewf/ewf1 >> fls-drive-dc01.body
```
Reminder to use sudo or to run as root incase you get permission denied such as I did below{{< image src="fls2.png" alt="fls2" >}}

At this point we have carved 2 body files, 1 per partition

Next the memory body file

```
vol.py -f citadeldc01.mem --profile=Win2012R2x64 timeliner --output=body --output-file=mem
```
{{< image src="volmem.png" alt="volmem" >}}

Create backups of the image body files just in case something breaks after appending the mem body file

```
cp fls-drive-dc01.body fls-drive-dc01.body.bak
```

Ended up with the files below
{{< image src="bodyfilesls.png" alt="bodyfilesls" >}}

Lastly, merge the mem timeline with the image timeline body file
{{< image src="bodymerge.png" alt="bodymerge" >}}
## It's Mactime!

```
# -y=Use ISO-8601 date format in output -d=CSV Output -z=TimeZone -b= looks for 
# input file, in this case it is fls-drive-dc01.body
`mactime -y -d -z UTC -b fls-drive-dc01.body > dc01-fls.csv`
```
{{< image src="mactime1.png" alt="mactime1" >}}

Towards the beginning of the combined timeline CSV, most rows come from the Volatility timeliner memory body file. These records describe processes and other in-memory artifacts and typically lack traditional MACB timestamps, so the date/time fields may show as `0000-00-00T00:00:00Z`. They are still valuable for identifying what was active in memory.

{{< image src="csvcombined1.png" alt="csvcombined1" >}}

Towards the tail end we start to see disk-based events contributed by the Sleuth Kit body file (from `fls`). These entries correspond to actual file-system objects and therefore include valid MACB timestamps (Modified, Accessed, Changed, Birth/Created), providing concrete temporal context.

In DFIR he gives 3 options to view the CSV. LibreOffice, Microsoft Excel or Eric Zimmerman's TimelineExplorer. I tried LibreOffice and realized I made a mistake and should've gone with EZ's TE from the get go. It's awesome.

## IoC Reminder/Check
Host IP & Port: 10.42.85.10:62613
Malicious process: spoolsv.exe
Potentially Malicious process: coreupdater.exe Time: 2020-09-19 03:56:52 UTC
Potential Attacker, Remote IP: 203.78.103.109:443
PID: 3644

## dc01timeline.csv

	"Coreupdater" search results

{{< image src="coreupdtsrchrslts.png" alt="coreupdtsrchrslts" >}}

## Creating SuperTimeline

From DFIR
> "Super timelines are made up of many different data sources found on a systems disk and in it’s memory. Investigators can use tools like “Log2Timeline.py” to process a disk image and collect vast amounts of data for the timeline. Sources of data include the registry, system logs, and much more. All of these data points are placed into an SQLite database called a dump file. Volatility is also able to take time stamped events from memory images and add those to a body file. This body file is then processed by Log2timeline using the “mactime” parser. The Log2timeline “mactime” parser extracts timestamped events from the memory body file and places them into the dump file. Finally, Psort processes the dump file into a CSV file that can easily be examined using Eric Zimmerman’s Timeline Explorer or Excel. This process is illustrated later on in this section.
> 
> The best way to approach super timeline creation is to kick it off almost immediately after collecting the hard drive, and having obtained an [FLS collection of the drive](https://dfirmadness.com/triage-disk-analysis-case-001/). Super timeline processing can take many **hours** for large server drives. That won’t be the case for this lab, but in reality it can easily take hours. The best approach is for investigators to have the super timeline processing in the background as they tackle other tasks such as [memory analysis](https://dfirmadness.com/case-001-memory-analysis/)."

{{< image src="dfirsupertimeline.png" alt="dfirsupertimeline" >}}

## Tools used in this section and brief descriptions
### Pinfo.py
Plaso Info is a tool that returns information about a plaso dump file.
### Psort.py
Plaso sort processes the plaso dump file. The most common file type to process the data into is a CSV.
### PSteal.py
Combining Log2timeline and Psort into one action for a quick slice of the image. This will not be demonstrated in this lab.
### Image_Export.py
From the help header:

> This is a simple collector designed to export files inside an image, both within a regular RAW image as well as inside a VSS. The tool uses a collection filter that uses the same syntax as a targeted plaso filter.

## SuperTimeline Process
1. Process memory image with Volatility Timeliner, Shellbags, and MFT modules into 1 memory timeline
2. Process the E01 Image with log2timeline into a plaso dmp file
3. Combine the mem body file with the plaso dmp file
4. Sort the data with psort into a CSV

### Creating Mem Body File using volatility2
	$ vol.py -f citadeldc01.mem --profile=Win2012R2x64 timeliner --output=body --output-file=./dc01-super-time.body
	$ vol.py -f citadeldc01.mem --profile=Win2012R2x64 shellbags --output=body --output-file=./dc01-shell-bags.body
	$ vol.py -f citadeldc01.mem --profile=Win2012R2x64 mftparser --output=body --output-file=./dc01mft.body

{{< image src="membodyfile.png" alt="membodyfile" >}}

### Creating light targeted Timeline

	$ log2timeline.py --status_view window -f /usr/share/plaso/filter_windows.yaml --storage_file dc01triage.dump ../disk/E01-DC01/20200918_0347_CDrive.E01 --partitions all

	$ log2timeline.py --parsers="mactime" --status_view window --storage_file dc01triage.dump ./dc01-super-time.body

### Creating Targeted Timeline
	log2timeline.py --parsers="winevtx,usnjrnl,prefetch,winreg,esedb/srum" --status_view window --storage_file dc01targeted.dump ../disk/E01-DC01/20200918_0347_CDrive.E01 --partitions "all"

	$ log2timeline.py --parsers="mactime" --status_view window --storage_file dc01targeted.dump ./dc01-super-time.body

### SuperDump lol!

	log2timeline.py --parsers="winevtx,mft,prefetch,esedb,win_gen,winreg,olecf/olecf_automatic_destinations" --status_view window --storage_file dc01super.dump ../disk/E01-DC01/20200918_0347_CDrive.E01 --partitions "all"

	$ log2timeline.py --parsers="mactime" --status_view window --storage_file dc01super.dump ./dc01-super-time.body

## SuperTimeLine!

**_Recommended Method_:** Analysts that want a CSV with the **times adjusted to match the correct time (same as the network time)** can use the following command:

`psort.py dc01super.dump --output_time_zone "Atlantic/Cape_Verde" -o L2tcsv -w dc01-superduper-timeline.csv`

The following command will generate a super timeline from the dc01-super.dump dump file created with UTC as the time zone:

`psort.py dc01super.dump --output_time_zone "UTC" -o L2tcsv -w dc01-superduper-timeline.csv`

## SuperTimeline Findings

## IoC Reminder/Check
Host IP & Port: 10.42.85.10:62613
Malicious process: spoolsv.exe
Potentially Malicious process: coreupdater.exe Time: 2020-09-19 03:56:52 UTC
Potential Attacker, Remote IPs: 203.78.103.109:443 & 194.61.24.102
PID: 3644

### Coreupdater search results and findings
Got a few hits
{{< image src="coreupdtrsrchrslts2.png" alt="coreupdtrsrchrslts2" >}}

In the first line I noticed that coreupdater has a timestamp of 2010-04-14 22:06:53 and I was confused
{{< image src="timestamp1.png" alt="timestamp1" >}}
{{< image src="coreupdtr3.png" alt="coreupdtr3" >}}

Turns out this is actually the "compile" time from the EXE's header. It's not when it first hit the system. Windows binaries from Win7 era often have April 2010 dates. Though the weird thing is I can't find any reputable "coreupdater" online so... I guess that remains to be verified.

PE = Portable Executable
COFF = Common Object File Format
Together that's the Windows standard EXE/DLL format

"There's a PE executable called coreupdater.exe. It was compiled on April 14th 2010 and lives in System32. Here's its unique NTFS record (87137) and import hash"

Moving on.. 
2nd line (don't worry we're only doing a few for understanding (I was talking to myself there))

	Timestamp	Source Description	Source Name	macb	Inode	
	2020-09-19 03:24:06	Bodyfile	FILE	m...	87137	

Long Description
	[MFT FILE_NAME] Windows\System32\coreupdater.exe (Offset: 0x2cc50400) Owner identifier: 0 Group identifier: 0 Mode: ---a-----------

Owner Identifier: 0 = Absence of a defined security identifier
macb: m = modified, how? "File name?"
Offset = the byte offset inside the MFT where that record sits

"NTFS updated the name record for coreupdater.exe"

### **3rd line (First MACB entry for coreupdater.exe)**

	Timestamp	Source Description	Source Name	macb	Inode	
	2020-09-19 03:24:06	Bodyfile	FILE	macb	76711	

Long Description
	[MFT FILE_NAME] Users\Administrator\AppData\Local\Microsoft\Feeds\{5588ACFD-6436-411B-A5CE-666AE6A92D3D}~\WebSlices~\coreupdater[1].exe (Offset: 0x3209f288) Owner identifier: 0 Group identifier: 0 Mode: ---a-------I---

Path: Feeds\{GUID}\Webslices
	"Webslices" was an IE feature for live-updating pieces of a webpage. It has its own cache under AppData
MACB: m.a.c.b = Modified, Accessed, metadata Changed, Birth -- First instance of this file, all MACB indicators were set.
I flag in the mode = file is indexed by NTFS indexing service
The [1] usually means it's a duplicate of something already named coreupdater.exe

4th & 5th line

	Timestamp	          Source Description Source Name	macb	Inode	
	2020-09-19 03:24:06	NTFS USN change	     FILE      	..c.	84656	

Long Description
	coreupdater[1].exe File reference: 76711-12 Parent file reference: 87050-1 Update source:  Update reason: USN_REASON_DATA_EXTEND  USN_REASON_FILE_CREATE

	Timestamp	          Source Description Source Name    macb	Inode	
	2020-09-19 03:24:06	NTFS USN change	    FILE	    ..c.	84656	

Long Description
	coreupdater[1].exe File reference: 76711-12 Parent file reference: 87050-1 Update source:  Update reason: USN_REASON_FILE_CREATE

USN= Update Sequence Number journal -- NTFS's built-in change log
MACB: ..c. only metadata Changed 
USN_REASON_FILE_CREATE – NTFS logged that the file was created.
USN_REASON_DATA_EXTEND – file size grew because data was written

"Change journal logged the creation of coreupdater[1] and noted that its data was written."

## DC CSV Findings

Timestamps look different in the following entries as I was parsing a second supertimeline file.
After reviewing the .CSV under the "coreupdater" search results this is what I found

- A binary **compiled in 2010** (`coreupdater.exe`) was **downloaded via IE/Edge WebSlices cache** as `coreupdater[1].exe` at **02:24:06**.
- The browser created a `.partial` file, repeatedly **extended, truncated, and closed it** as the download progressed.
- Within seconds, the file was **renamed and moved** from the WebSlices cache to `C:\Windows\System32\coreupdater.exe`.
- At **02:24:50**, NTFS logged a **security change and final rename**, indicating the file was settled in System32 with its final ACLs.
- At **02:27:49**, the malware **installed itself as a Windows service** (`coreupdater`), configured to **auto-start**.
- By **02:56:37**, the executable **spawned a process (PID 3644)**, with registry/UserAssist entries confirming **execution** and **multiple launches**.

  ### 194.61.24.102 Search Results
	  Timestamp	Source     Description Source Name	macb	Inode	
		2020-09-19 02:21:47	WinEVTX	     EVT	    m..b	     467	

Long Description
	[1149 / 0x047d] Provider identifier: {c76baa63-ae81-421c-b425-340b4b24157f} Source Name: Microsoft-Windows-TerminalServices-RemoteConnectionManager Strings: ['Administrator'  ''  '194.61.24.102'] Computer Name: CITADEL-DC01.C137.local Record Number: 29322 Event Level: 4 Message string: Remote Desktop Services: **User authentication succeeded**:\n\nUser: Administrator\nDomain: \nSource Network Address: 194.61.24.102
{{< image src="IoC1.png" alt="IoC1" >}}

Looks like Attacker gained access at 02:21:47 after a series of brute force attempts. Which we already knew.

Maybe they logged off at 02:28:41

	Timestamp	         Source Description	Source Name	macb	Inode	
	2020-09-19 02:28:41	WinEVTX	             EVT	m..b	84706	
	
Long Description
	[4634 / 0x121a] Provider identifier: {54849625-5478-4994-a5ba-3e3b0328c30d} Source Name: Microsoft-Windows-Security-Auditing Strings: ['S-1-5-18'  'CITADEL-DC01$'  'C137'  '0x00000000005576b0'  '3'] Computer Name: CITADEL-DC01.C137.local Record Number: 7626 Event Level: 0 Message string: **An account was logged off**.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tCITADEL-DC01$\n\tAccount Domain:\t\tC137\n\tLogon ID:\t\t0x00000000005576b0\n\nLogon Type:\t\t\t3\n\nThis event is generated when a logon session is destroyed. It may be positively correlated with a logon event using the Logon ID value. Logon IDs are only unique between reboots on the same computer.

Noticed Lateral Movement attempt to DESKTOP-SDN1RPT at 2020-09-19 03:35:54, meaning they did not log off at 03:28:41
	Long Description
[1024 / 0x0400] Provider identifier: {28aa95bb-d444-4719-a36f-40462168127e} Source Name: Microsoft-Windows-TerminalServices-ClientActiveXCore Strings: ['Server Name'  'DESKTOP-SDN1RPT'  'Info'] Computer Name: CITADEL-DC01.C137.local Record Number: 1 Event Level: 4 Message string: RDP ClientActiveX is trying to connect to the server (DESKTOP-SDN1RPT)

Reviewed Wireshark a bit more
Confirmed Lateral Movement time at 02:35:55
{{< image src="wiresharkioc.png" alt="wiresharkioc" >}}

End of session between DC and Workstation at 02:52:14
{{< image src="wiresharkioc2.png" alt="wiresharkioc2" >}}

## FileShare Contents

Out of all the searches for the files within the Fileshare\Secrets directory I noticed something off about the events surrounding Beth_Secret.txt, I noticed it was renamed here

Timestamp	         
	2020-09-18 21:39:21	
Long Description
	SECRET_beth.txt File reference: 73635-13 Parent file reference: 86966-9 Update source:  Update reason: USN_REASON_RENAME_NEW_NAME
Used to be named SECRET_Beth.txt but is now named Beth_Secret.txt
It also appears it was deleted after it was extracted in a zip file
{{< image src="IoC2.png" alt="IoC2" >}}
{{< image src="IoC3.png" alt="IoC3" >}}

When I checked the file in the Recycling Bin I noticed the contents are different from the file that was left on the server.

Beth_Secret.txt (New File)
{{< image src="secretbeth1.png" alt="secretbeth1" >}}

Secret_Beth.txt (Original)
{{< image src="secretbeth2.png" alt="secretbeth2" >}}

I also checked metadata and noticed that it had a date prior to when the file was created given that the creation date per the macb timestamps in the timeline log indicate that it was created here Timestamp 2020-09-19 02:34:56
{{< image src="timestamp.png" alt="timestamp" >}}

But Exiftool metadata gives is a Modified and Accessed date of a day before? Time stomped?
{{< image src="exiftoolbethsecret.png" alt="exiftoolbethsecret" >}}
### Summary thus far
The attacker gained access to the domain controller (DC) after a series of **brute-force RDP (Remote Desktop Protocol)** attempts.  

Attacker deployed a **Metasploit Meterpreter payload** packaged in `coreupdater.exe`, which was **delivered via a malicious WebSlices download**.  

During execution, the malware **persisted as an auto-start Windows service** and Memory artifacts (malfind dumps + FLOSS strings) indicate shellcode injected into `spoolsv.exe``, allowing it to operate with `NT AUTHORITY\SYSTEM` privileges.

To cover their tracks and tamper with data, the attacker **replaced `Secret_Beth.txt` with a modified file `Beth_Secret.txt`** after collecting the contents of the `Fileshare\Secrets` directory in a ZIP file named `Secret.zip`.  
Finally, using the compromised **Administrator credentials**, the attacker performed **lateral movement over RDP to the workstation 10.42.85.115**.  
I learned a great deal during this investigation. I have not yet completed a deep dive into the workstation evidence and may publish a follow-up with those findings.

## Lastly, Answers to the Questions on DFIRMadness below
1. What’s the Operating System of the Server?
		Windows 2012 R2
2. What’s the Operating System of the Desktop?
		Windows 10 Enterprise Evaluation
	{{< image src="desktopOS.png" alt="desktopOS" >}}
3. What was the local time of the Server?
	{{< image src="servertimezone.png" alt="servertimezone" >}}
	
4. Was there a breach?
		Yes
5. What was the initial entry vector (how did they get in)?
		Brute force attempt from a kali machine using the administrator account
6. Was malware used? If so what was it? If there was malware answer the following:
    1. What process was malicious?
		    coreupdater.exe & spoolsv 
    2. Identify the IP Address that delivered the payload.
		    194.61.24[.]102
    3. What IP Address is the malware calling to?
		    203.78.103[.]109
    4. Where is this malware on disk?
		    System32
    5. When did it first appear?
		    02:24:06
    6. Did someone move it?
		    Yes from the Webslices/Downloads cache to C:\Windows\System32
    7. What were the capabilities of this malware?
		    Being that it was metasploit it likely is very versatile
    8. Is this malware easily obtained?
		    Yes
    9. Was this malware installed with persistence on any machine?
		    Yes
        1. When?
		        02:27:49
        2. Where?
				HKEY_LOCAL_MACHINE\System\ControlSet001\Services\coreupdater{{< image src="hkeycoreupdater.png" alt="hkeycoreupdater" >}}
7. What malicious IP Addresses were involved?
		At the time of the attack 194.61.24[.]102 was seen exploiting cve-2015-1635, a "HTTP.sys RCE Vuln." 
    1. Were any IP Addresses from known adversary infrastructure?
		    203.78.103[.]109 also appears in VT associated with Meterpreter
    2. Are these pieces of adversary infrastructure involved in other attacks around the time of the attack? See above.
8. Did the attacker access any other systems?
		Yes
    1. How?
		RDP from DC to Workstation
    2. When?
	    From 02:35:54 (Initial logon from DC to Workstation) till 02:35:54
    3. Did the attacker steal or access any data?
		    Yes, extracted all .txt files in Fileshare\Secrets directory in the form of a .zip file
        1. When?
	        02:34:18 the zip file was deleted and closed from the DC I could not find a transfer action in the pcap or in the timeline however in DFIR he states it was done at 02:32
9. What was the network layout of the victim network?
		Network: 10.42.85.0/24
		Domain: C137
		Hosts:
			DC CITADEL-DC01 10.42.85.10
			Workstation Desktop-SDN1RPT
10. What architecture changes should be made immediately?
	Disable RDP from outside of network. Make a stronger password for Administrator account, create a separate admin account with a unique name and enable/implement MFA
11. Did the attacker steal the Szechuan sauce? If so, what time?
	1. Yes at 02:32:39 
12. Did the attacker steal or access any other sensitive files? If so, what times?
		Beth's Secrets were manipulated, renamed and content modified. I have not analyzed the workstation yet, I will do that at a separate time and will likely write a part two to this post.
13. Finally, when was the last known contact with the adversary?
		Based on this pcap, attacker disconnected (after laterally spreading to workstation) at 02:52:14
		
### Advanced and Bonus Questions

1. What CIS Top 20 or SANS Top 20 Controls would have _directly_ prevented this breach?
2. What major architecture improvement could be made that would have prevented this breach?
		VPN, IPS, MFA, EDR
3. Can you identify policy improvements or controls that should be implemented to secure this environment?
		Unique username, Complex passwords, IPS, EDR, VPN, MFA, PW Encrypted files if they contain important secrets.
4. Which users have actually logged onto the DC?
		Administrator was the only one in the Users folder in the DC Disk Image
5. Which users have actually logged onto the Desktop machine? Did not check
6. What are the passwords for the users in the domain? Did not check
7. Can you recover the original file about Beth’s Secrets?
    1. What was the original name?
	    Secret_Beth.txt 
    2. Original Contents?
	    Earth Beth is the real Beth
8. Finally, what file was time stomped?
		The dupe copy of Secret_Beth.txt named Beth_Secret.txt