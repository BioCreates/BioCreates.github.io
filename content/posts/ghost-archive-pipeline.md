+++
title = "Ghost Archive: The Pipeline That Published This Post"
slug = "ghost-archive-pipeline"
date = "2026-07-21"
author = "RoninSec"
cover = "/img/ghost-archive-pipeline-banner.png"
tags = ["automation", "n8n", "hugo", "docker", "devops"]
keywords = ["n8n", "hugo", "github actions", "automation pipeline", "self-hosted"]
description = "How I built a self-hosted publishing pipeline that validates, sanitizes, illustrates, and ships blog posts from a watched folder to a live site - including the AI-generated cover on this post."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Ghost Archive: The Pipeline That Published This Post

No human committed this post. I dropped a Markdown file into a watched folder
on a homelab server, and everything after that was automation.

The problem it solves: months of troubleshooting sessions and lab notes
trapped in old AI chat conversations - worth publishing, tedious to move by
hand. The fix: a staged pipeline built on n8n.

## How it works

An article moves through a small state machine of folders: incoming, review,
approved, processing, published. A workflow validates each file - TOML front
matter, slug rules, date sanity - then scans it for anything that should never
go public: private keys, cloud credentials, internal addresses, and a denylist
of protected names.

Because the hardened n8n container allows no shell access and fences file
paths, the pipeline delegates to two tiny sidecar containers: a file butler
that performs atomic moves and writes the publication ledger, and a metadata
stripper that runs every image through exiftool before it can leak camera or
location data.

Clean articles get committed to a branch and opened as a pull request, where
CI builds the entire Hugo site before anything merges. Merging fires a
webhook: the pipeline waits for the deploy, polls the live URL, confirms the
post actually rendered, archives the source file, and records the publication.
Only then does my phone get the message that the original conversation is
safe to delete.

The cover image on this post was generated, metadata-stripped, and committed
by the pipeline itself.

More build details - including the failures along the way - in future posts.
