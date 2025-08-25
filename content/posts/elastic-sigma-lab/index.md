---
title: "Lab #2 – Hunting Scheduled Task Persistence with Elastic & Sigma"
slug: "scheduled-task-persistence-elastic-sigma"
date: "2025-08-24T16:30:00-04:00"
author: "RoninSec"
cover: "scheduled-task-banner.png"
tags: ["elastic", "sigma", "docker", "sysmon", "blue-team", "persistence"]
keywords: ["sigma", "scheduled task persistence", "Sysmon Event ID 1", "schtasks", "Elastic SIEM"]
description: "Detect scheduled task persistence using Sysmon Event ID 1, Elastic Agent, and a converted Sigma rule."
showFullContent: false
readingTime: true
hideComments: false
draft: false
---


## Overview

This lab was my first attempt at detection engineering with **Elastic + Sigma**.  
I set up a temporary Elastic/Kibana stack in Docker, connected a Windows VM via Elastic Agent, simulated persistence with `schtasks`, and hunted it with a converted Sigma rule.

Along the way, I hit a bunch of errors that forced me to dig deeper — exactly the kind of troubleshooting I want to document here.

---

## Step 1 – Elastic in Docker

I started by installing Docker and creating a `docker-compose.yml` to bring up **Elasticsearch** and **Kibana**:

```yaml
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.2
    container_name: es01
    environment:
      - node.name=es01
      - discovery.type=single-node
      - xpack.security.enabled=true
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
      - xpack.security.http.ssl.enabled=false
      - xpack.security.transport.ssl.enabled=false
      - ES_JAVA_OPTS=-Xms1g -Xmx1g
    ports:
      - "9200:9200"
    volumes:
      - esdata:/usr/share/elasticsearch/data

  kibana:
    image: docker.elastic.co/kibana/kibana:8.12.2
    container_name: kib01
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=KibanaPass123!
      - NODE_OPTIONS=--max-old-space-size=512
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
    restart: unless-stopped

volumes:
  esdata:
```
And an .env file with the superuser password:

```.env
ELASTIC_PASSWORD=ChangeMe123!
```

### 💡 Gotcha – Wrong account for Kibana
At first I tried logging into Kibana with the elastic superuser, but Kibana requires its own service account (kibana_system).
I had to reset its password with:
```Powershell
Invoke-RestMethod `
  -Method POST `
  -Uri "http://localhost:9200/_security/user/kibana_system/_password" `
  -Headers @{ "Content-Type" = "application/json" } `
  -Body '{ "password": "KibanaPass123!" }' `
  -Credential (New-Object System.Management.Automation.PSCredential("elastic", (ConvertTo-SecureString "ChangeMe123!" -AsPlainText -Force)))
```
## Step 2 – Installing the Windows Agent

The Elastic portal gave me a one-liner installer, but it failed. Instead I:

    Manually downloaded the ZIP from Elastic’s site.

    Extracted it to C:\Elastic\elastic-agent-8.12.2-windows-x86_64\.

    Noticed that running the agent actually created another directory:
    C:\Program Files\Elastic\Agent\ with its own elastic-agent.yml.

That’s the config Elastic actually uses — not the one in the extracted folder.

I edited it to point to my host instead of localhost:
```yml
outputs:
  default:
    type: elasticsearch
    hosts:
      - 'http://192.168.1.105:9200'
    username: 'elastic'
    password: 'ChangeMe123!'
    preset: balanced
```
Then restarted the agent:
```Powershell
Restart-Service -Name "Elastic Agent"
```
### 💡 Gotcha – Wrong config file
Editing the extracted .yml did nothing. The real config lives in
C:\Program Files\Elastic\Agent\elastic-agent.yml.
Step 3 – Simulating Persistence

On the VM, I created a scheduled task to dump whoami every minute:
```cmd
schtasks /create /sc minute /mo 1 /tn "UpdaterSvc" /tr "cmd.exe /c whoami > C:\Windows\Temp\whoami.txt" /ru SYSTEM /f
```
Could also be ran with PowerShell:
```Powershell
$A = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c whoami > C:\Windows\Temp\whoami_ps.txt"
$T = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
Register-ScheduledTask -TaskName "UpdaterSvcPS" -Action $A -Trigger $T -User "SYSTEM" -RunLevel Highest
```
Sysmon (event ID 1) captured it, and Elastic showed both the event and the whoami.txt file being written.

## Step 4 – Writing & Converting a Sigma Rule

I wrote my Sigma rule: artifacts/sigma/scheduled_task_creation_schtasks.yml
```yml
title: Scheduled Task Creation via Schtasks
id: 123e4567-e89b-12d3-a456-426614174000
status: experimental
description: Detects creation of scheduled tasks via schtasks.exe
author: RoninSec
date: 2025/08/24
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith: '\schtasks.exe'
  condition: selection
fields:
  - CommandLine
level: medium
```
### Conversion with Sigma CLI

Installed Sigma CLI and plugins:
```cmd
python -m pip install --upgrade pip
python -m pip install sigma-cli
sigma plugin install elasticsearch
sigma plugin install sysmon
```
Converted rule to Lucene:
```cmd
sigma convert -t lucene -p ecs_windows .\artifacts\sigma\scheduled_task_creation_schtasks.yml -o .\artifacts\scheduled_task_creation_schtasks_lucene.txt
```
### 💡 Gotchas – Conversion errors

    Missing UUID → Sigma requires a proper UUID for id. Fixed by adding one.

    YAML formatting error → My first draft had bad indentation. Fixed spacing.

    Lucene vs KQL → Elastic Discover defaults to KQL. Had to switch search language to Lucene.

{{< image src="elasticsyntaxerror.png" alt="Lucene Syntax Error" caption="Error I got before switching language in Elastic" >}}


## Step 5 – Hunting in Elastic

The final working Lucene query:
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational" AND event.code:1 AND process.executable:*\\schtasks.exe
```
✅ This returned the scheduled task execution events as expected.

{{< image src="schedtask.png" alt="Elastic Scheduled Task event" caption="Elastic Scheduled Task event shows up after converted Sigma query" >}}

### Wrap-Up

    Docker ran Elastic + Kibana fine on my lab box.

    Standalone agent required editing the right .yml in Program Files.

    Sysmon captured the persistence technique.

    Sigma rule + CLI let me hunt it in Elastic (after fixing UUID, YAML, and query language).

## Gotchas Appendix 📖

Quick reference of issues I ran into:

    Kibana login failed → Tried using elastic superuser; Kibana requires kibana_system.

    Agent not connecting → Edited the wrong .yml. The real one is in Program Files.

    Agent pointing to localhost → Default config uses http://localhost:9200; needed 192.168.1.105.

    Sigma UUID missing → Every Sigma rule needs a UUID.

    YAML formatting error → Misaligned indentation broke parsing.

    Lucene vs KQL → Elastic defaults to KQL. Switched to Lucene to run converted queries.

## Useful Docker Commands 🐋

Some Docker commands I used throughout:
```cmd
docker ps               # list running containers
docker compose up -d    # start services in background
docker compose down     # stop services
docker logs es01        # check logs for Elasticsearch
docker logs kib01       # check logs for Kibana
docker exec -it es01 sh # open a shell inside the container
```
### What’s Next

    Learn Elastic/Kibana query building in more depth.

    Deploy Wazuh permanently in my environment.

    Write more Sigma rules for persistence techniques.

    Later: simulate a Wi-Fi attack on my own network and test if alerts catch it.

⚡ Takeaway: This lab wasn’t clean copy-paste work — I ran into real-world gotchas at almost every step.
Fixing them forced me to learn how Elastic, its accounts, the Agent configs, and Sigma all actually fit together.