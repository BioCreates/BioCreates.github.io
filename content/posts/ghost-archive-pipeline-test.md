+++
title = "Testing the Ghost Archive Pipeline"
slug = "ghost-archive-pipeline-test"
date = "2026-07-14"
author = "RoninSec"
cover = ""
tags = ["automation", "n8n", "hugo", "meta"]
keywords = ["automation", "n8n", "hugo", "github actions"]
description = "First post published end-to-end by the Ghost Archive automation pipeline."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

This post was not committed by a human.

It started life as a Markdown file dropped into a watched intake folder on a
homelab server. An n8n workflow picked it up, checked the front matter, scanned
it for leaked credentials and protected names, verified the slug wasn't already
taken, then created a branch, committed the file, and opened a pull request on
GitHub. GitHub Actions rebuilt the site and GitHub Pages served it. If you can
read this, every stage of that chain held.

More on how it's built in a future write-up.
