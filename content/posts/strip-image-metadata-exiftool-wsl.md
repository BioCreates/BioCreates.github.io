+++
title = "Stripping Image Metadata Recursively With ExifTool in WSL"
slug = "strip-image-metadata-exiftool-wsl"
date = "2026-09-18"
author = "RoninSec"
cover = "/img/strip-image-metadata-exiftool-wsl-banner.png"
tags = ["wsl", "exiftool", "metadata", "privacy", "opsec"]
keywords = ["exiftool", "image metadata", "remove exif", "wsl", "metadata removal", "privacy", "opsec"]
description = "A practical WSL workflow for recursively stripping image metadata with ExifTool and verifying what was removed before publishing files."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Stripping Image Metadata Recursively With ExifTool in WSL

Images can carry much more information than the pixels we actually intend to publish. Depending on the source, an image may contain EXIF, GPS coordinates, camera details, timestamps, software information, comments, XMP, IPTC data, and other metadata.

While preparing images for a technical blog, I wanted a simple workflow: point a command at the directory containing my posts, recursively process every image underneath it, and remove as much metadata as possible.

WSL and ExifTool made that almost ridiculously easy. The more interesting part was figuring out what ExifTool meant when it reported that some files were "unchanged."

---

## The Symptom

My blog content contained images spread across multiple directories and subdirectories. Manually locating and sanitizing each image was not practical.

The directory structure was effectively something like this:

```text
posts/
├── article-one/
│   ├── screenshot-01.png
│   └── screenshot-02.jpg
├── article-two/
│   └── images/
│       ├── terminal.png
│       └── diagram.jpg
└── article-three/
    └── example.png
```

I wanted to start at `posts/` and recursively remove metadata from everything underneath it.

There were two requirements:

1. Process subdirectories automatically.
2. Modify the existing files instead of leaving backup copies everywhere.

ExifTool was the obvious tool for the job.

---

## The Investigation

### 1. Install ExifTool in WSL

On Ubuntu-based WSL distributions, ExifTool is available through the `libimage-exiftool-perl` package.

```bash
sudo apt update
sudo apt install -y libimage-exiftool-perl
```

Once installed, I could inspect an image with:

```bash
exiftool path/to/image.jpg
```

This provides a useful baseline because it shows the metadata ExifTool can identify before anything is removed.

### 2. Strip Metadata Recursively

ExifTool can recurse through directories directly, so I did not need to build a complicated `find` loop.

The command was:

```bash
exiftool -overwrite_original -all= -r posts/
```

The important options are straightforward:

* `-r` recursively processes subdirectories.
* `-all=` requests removal of metadata across metadata groups.
* `-overwrite_original` prevents ExifTool from retaining its normal `_original` backup files.
* `posts/` is the root directory being processed.

ExifTool then returned a summary similar to:

```text
9 directories scanned
84 image files updated
21 image files unchanged
```

The first number was expected.

The second was good.

The third made me stop.

What exactly were those 21 unchanged files?

### 3. Investigate the "Unchanged" Result

An "unchanged" result is not automatically an error. It means ExifTool processed the file but did not end up making a change.

After a metadata-removal pass, one likely explanation is that there was nothing removable left in those files. However, that summary alone does not prove exactly what metadata each file contained before the command ran.

That distinction matters.

Because I had already run the destructive cleanup with `-overwrite_original`, I could inspect the current state, but I could not reconstruct the exact pre-cleanup metadata state from ExifTool's summary alone.

To identify files that currently contain no EXIF metadata, I could run:

```bash
exiftool -r -if 'not $exif:all' -p '$directory/$filename' posts/
```

This is read-only.

The condition:

```text
not $exif:all
```

selects files without EXIF-group metadata, while:

```text
$directory/$filename
```

prints a useful path instead of only the filename.

I could also save the results:

```bash
exiftool -r -if 'not $exif:all' -p '$directory/$filename' posts/ > unchanged_images.txt
```

This gives me an audit file that can be reviewed separately.

---

## What the Evidence Showed

The cleanup itself worked as expected: ExifTool recursively traversed the blog directory and modified dozens of images.

The "unchanged" count was not evidence that ExifTool had failed on 21 files. It meant no resulting change was made to those files.

There is an important gotcha here: checking for `not $exif:all` only checks the EXIF group. It should not be interpreted as a universal proof that absolutely no metadata of any kind remains in a file.

ExifTool can work with many metadata families beyond EXIF, including XMP and IPTC. For a privacy-sensitive publishing workflow, I would inspect questionable files directly rather than equating "no EXIF" with "contains zero metadata."

A spot check is easy:

```bash
exiftool path/to/image.jpg
```

Some basic information will still appear because ExifTool reports properties derived from the file itself. Seeing fields such as file size, dimensions, or file type does not necessarily mean embedded privacy-sensitive metadata survived.

---

## The Root Cause

There was not actually a failure to troubleshoot.

The confusion came from interpreting ExifTool's summary:

```text
84 image files updated
21 image files unchanged
```

"Unchanged" does not mean "failed."

It means ExifTool did not make a modification to those files during that operation. In this situation, files that already lacked removable metadata were a likely contributor.

The bigger lesson was that the summary describes what ExifTool did, not necessarily the historical metadata state of every file.

Because I used:

```bash
-overwrite_original
```

I intentionally discarded ExifTool's automatic backup copies. That keeps the repository clean, but it also means I should not expect to perform a perfect before-and-after metadata comparison afterward unless the repository or another backup contains the original versions.

---

## Key Takeaways

* ExifTool works extremely well inside WSL for bulk image sanitization.
* `-r` eliminates the need to manually traverse nested image directories.
* `-all=` requests broad metadata removal.
* `-overwrite_original` avoids `_original` backup files, but it also removes an easy rollback path.
* "Image files unchanged" is not the same as "image files failed."
* A post-cleanup scan can verify the current state, but it cannot necessarily prove what existed before cleanup.
* `not $exif:all` specifically concerns EXIF metadata and should not be treated as proof that every possible metadata family is absent.
* For important publishing or OPSEC workflows, inspect representative files before and after sanitization.

---

## Summary

**Symptom:** I needed to remove metadata from images distributed throughout a blog's directory tree and later noticed ExifTool reporting several files as unchanged.

**Investigation:** I used ExifTool recursively, reviewed its updated-versus-unchanged summary, and used conditional metadata queries and direct inspection to understand the resulting files.

**Root Cause:** There was no confirmed processing failure. "Unchanged" meant ExifTool made no modification to those files, with already-clean files being a likely explanation.

**Resolution:** The recursive cleanup command was:

```bash
exiftool -overwrite_original -all= -r posts/
```

I then used read-only ExifTool queries and individual file inspection to audit the sanitized images.

The pixels can keep their secrets. The metadata does not get that privilege.
