+++
title = "Lab #3 – Elastic Deep Dive: From Sigma to Dashboards"
slug = "elastic-deep-dive"
date = "2025-08-30T12:20:00-04:00"
author = "RoninSec"
cover = "banner.png"      # file lives in this page bundle folder
tags = ["elastic", "kibana", "sigma", "lucene", "eql", "dashboarding", "blue-team"]
keywords = ["Elastic", "Kibana", "Sigma", "Lucene", "EQL", "Sysmon", "Windows"]
description = "Exploring Elastic/Kibana queries and dashboards: KQL vs Lucene vs EQL, Sigma conversion, and a small hunting dashboard."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Lab #3 – Elastic Deep Dive

## 🎯 Goal
Go beyond a single detection. Treat Elastic like a mini-SIEM:
- Compare query languages (KQL, Lucene, EQL).
- Visualize Sysmon logs with dashboards.
- Convert and test Sigma rules for persistence.

---

## ⚙️ Environment
- ElasticSearch + Kibana (Docker containers `es01`, `kib01`)
- Elastic Agent (Windows VM) forwarding Sysmon logs
- Sigma CLI for detection rule conversion

Repo Structure:
- `artifacts/` → Sigma rules + converted queries  
- `deploy/` → docker-compose.yml, configs  
- `logs/` → raw samples, notes  
- `screenshots/` → Kibana dashboard images  

---

## 🔍 Step 1 — Explore Data in Discover
First, I queried raw Sysmon logs in **Discover**:

```kql
winlog.channel : "Microsoft-Windows-Sysmon/Operational"
Added columns: event.code, process.executable, CommandLine.
```

## ⚔ Step 2 — Querying with Different Languages
Elastic supports multiple query languages:

### KQL (default, user-friendly)

```kql
process.executable : "*\\schtasks.exe"
```

### Lucene (raw, what Sigma outputs)

``` lucene
winlog.channel:"Microsoft-Windows-Sysmon/Operational" AND event.code:1 AND process.executable:*\\schtasks.exe
```

### EQL (sequence logic, requires SIEM/Timeline)

```eql
sequence by process.entity_id
  [process where process.name == "schtasks.exe"]
  [process where process.name == "taskeng.exe"]
```
⚠ EQL didn’t run in Discover (it belongs in the SIEM → Timeline module). Still, it’s valuable to know the syntax.

## 📊 Step 3 — Build Dashboards
Created a new Kibana dashboard with three panels:
    
    Sysmon Process Creation Trend (Event ID 1 over time).
    Event Code Counts (stacked bar by event.code).
    Top Processes (pie chart by process.name).

These give quick situational awareness instead of typing queries every time.

## 🛠 Step 4 — Add a Sigma Rule
Grabbed a persistence rule from SigmaHQ:
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_susp_reg_persist_explorer_run.yml
📌 

Converted with Sigma CLI:

``` powershell
sigma convert -t lucene -p ecs_windows `
  .\artifacts\sigma\registry_set_susp_reg_persist_explorer_run.yml `
  -o .\artifacts\registry_set_susp_reg_persist_explorer_run_lucene.txt
```
Result: Lucene query ready for Kibana Discover.

## ⚠ Challenges
* Docker overhead slowed my laptop.
* Sysmon config only captured process creation (no registry events).
* EQL queries not supported in Discover.

## 📝 Takeaways
* Learned Elastic query language differences.
* Built basic hunting dashboards.
* Structured repo with Sigma YAML + converted Lucene queries.
* Realized Elastic is heavy for home labs — Wazuh may be more practical.

## 🚀 Next Steps
* Deploy Wazuh on a dedicated Ubuntu host.
* Expand Sysmon config for registry/network events.
* Write my own Sigma rules from scratch.

## 📖 Wrap-up:
This lab made Elastic feel less like a black box. Even though Docker dragged performance, I can now navigate Discover, compare query languages, and visualize Sysmon telemetry. The repo documents both the wins and the limitations — which is exactly what a real SOC analyst does.