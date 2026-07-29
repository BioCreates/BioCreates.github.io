+++
title = "Deploying a Shared Windows Screensaver with Group Policy"
slug = "deploy-shared-windows-screensaver-gpo"
date = "2026-07-29"
author = "RoninSec"
cover = "/img/deploy-shared-windows-screensaver-gpo-banner.png"
tags = ["active-directory", "group-policy", "windows", "sysadmin", "automation"]
keywords = ["group policy screensaver", "photoscreensaver.scr", "shared folder", "active directory", "gpo registry", "windows screensaver", "domain users"]
description = "Learn how to deploy a centralized Windows Photos screensaver with Group Policy, avoid common OU mistakes, and simplify future image updates."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Deploying a Shared Windows Screensaver with Group Policy

Sometimes the simplest requests end up teaching you the most about how Group Policy actually works.

In this case, a client wanted every workstation to use the same screensaver while allowing images to be updated from a single shared folder. The goal was straightforward: add or remove images in one place and have every computer automatically display them without touching each workstation again.

The implementation was simple once I separated what Windows expects from what I initially assumed.

---

## The Symptom

The request sounded easy enough:

* Configure all domain computers to use the Windows Photos screensaver.
* Store all images on a shared network folder.
* Allow administrators to update images by simply copying new files into that folder.
* Avoid visiting every workstation whenever new images need to be added.

At first glance, this seemed like a computer policy. After all, the screensaver runs on the computer.

That assumption turned out to be my first roadblock.

---

## The Investigation

### 1. Verify the Shared Folder Requirements

The first question I wanted answered was whether users needed anything beyond read permissions.

The answer was no.

For a screensaver that only displays images:

* Share permissions: Read
* NTFS permissions: Read and List Folder Contents

There is no need for:

* Execute
* Modify
* Full Control

Unless users are expected to upload new images themselves, read-only permissions are sufficient.

---

### 2. Create the Shared Folder

I created a shared folder on the file server similar to:

```text
\\FILESERVER\ScreensaverImages
```

Administrators manage the images while users only consume them.

This keeps the design simple and minimizes the chance of accidental file deletion.

---

### 3. Create a New GPO

While creating the policy, Windows asked whether I wanted to use a Starter GPO.

The correct answer was:

```text
(none)
```

The older Windows XP and Windows Vista templates are legacy starter policies and provide no benefit for this deployment.

I created a dedicated GPO named:

```text
ScreensaverPolicy
```

Keeping the policy separate makes future troubleshooting much easier than burying unrelated settings inside an existing GPO.

---

### 4. Configure the Screensaver Policy

Under:

```text
User Configuration
  Administrative Templates
    Control Panel
      Personalization
```

I configured:

* Enable screen saver
* Force specific screen saver
* Screen saver executable name
* Screen saver timeout

The executable entered was:

```text
PhotoScreensaver.scr
```

This is the actual Windows Photos screensaver executable, not a placeholder.

---

### 5. Configure the Image Folder

There is one catch.

Group Policy contains settings to force a screensaver, but it does not provide a native policy to specify where the Photos screensaver should load images from.

Instead, I used a Group Policy Preference Registry item.

The registry value looked like this:

```text
Hive:
HKEY_CURRENT_USER

Key:
Software\Microsoft\Windows Photo Viewer\Slideshow\Screensaver

Value:
ImagePath

Type:
REG_SZ

Data:
\\FILESERVER\ScreensaverImages
```

Once applied, the Photos screensaver knows exactly where to look.

---

### 6. The Biggest Gotcha

This was the most important lesson of the deployment.

Initially I linked the GPO to the Computers organizational unit.

That seemed logical.

It was also wrong.

Because every setting I configured lived under:

```text
User Configuration
```

the policy only processes correctly when linked to an organizational unit containing user accounts.

I moved the link to the Users organizational unit instead.

Alternatively, I could have enabled Group Policy Loopback Processing if I wanted to keep the policy linked to the computer objects, but that would have introduced unnecessary complexity for this use case.

---

## What the Evidence Showed

After reviewing the policy design, everything lined up.

The deployment flow became:

1. User signs into a domain workstation.
2. User policy applies.
3. Registry preference sets the image folder.
4. Windows launches `PhotoScreensaver.scr`.
5. Images load directly from the shared folder.

An added bonus is that the Photos screensaver reads the folder dynamically.

If an administrator copies new images into the shared directory, users automatically see them the next time the screensaver starts.

No workstation changes.

No GPO updates.

No reboot required.

---

## Root Cause

The deployment itself was never particularly difficult.

The real issue was understanding that the Windows Photos screensaver is configured entirely through user policy rather than computer policy.

That distinction affects where the GPO must be linked.

It also explains why the registry value belongs under `HKEY_CURRENT_USER` instead of `HKEY_LOCAL_MACHINE`.

Once those two pieces fell into place, the rest of the deployment became straightforward.

---

## Key Takeaways

* Create a dedicated shared folder for images.
* Read-only permissions are sufficient for normal users.
* Use `PhotoScreensaver.scr` as the screensaver executable.
* Configure the image path using a Registry Preference.
* Link the GPO to the User organizational unit unless intentionally using Loopback Processing.
* Create a dedicated GPO instead of modifying unrelated policies whenever practical.
* New images appear automatically without updating the policy or visiting individual workstations.

---

## Summary

**Symptom**

A client wanted every workstation to display a centrally managed slideshow from a shared network folder.

**Investigation**

Created a shared folder, verified permissions, configured the Photos screensaver through Group Policy, added the required registry preference, and validated where the policy should be linked.

**Root Cause**

The screensaver configuration is a User Configuration policy. Linking the GPO to a Computers organizational unit prevented the settings from applying as expected.

**Resolution**

Linked the policy to the appropriate Users organizational unit, configured `PhotoScreensaver.scr`, pointed the registry to the shared folder, and verified that future image updates only require copying new files into the shared directory.

Remember: the hardest part of Group Policy usually is not the policy itself, it is figuring out which half of Group Policy is actually in charge.
