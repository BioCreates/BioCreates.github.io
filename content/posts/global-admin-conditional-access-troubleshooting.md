+++
title = "Why Global Administrator Was Not Enough: Troubleshooting Microsoft Entra Conditional Access"
slug = "global-admin-conditional-access-troubleshooting"
date = "2026-07-28"
author = "RoninSec"
cover = "/img/global-admin-conditional-access-troubleshooting-banner.png"
tags = ["microsoft-entra", "conditional-access", "identity", "microsoft-365", "troubleshooting"]
keywords = ["conditional access", "global administrator", "microsoft entra", "azure ad", "sign-in logs", "identity security", "microsoft 365"]
description = "A Global Administrator account still could not access Microsoft admin portals. Here is how sign-in logs revealed the real blocker."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Why Global Administrator Was Not Enough: Troubleshooting Microsoft Entra Conditional Access

Assigning someone the Global Administrator role should unlock administrative access, right?

Not always.

Recently I ran into a situation where a newly promoted administrator still could not access Microsoft administrative portals. At first glance it looked like a permissions problem. In reality, the role assignment was working exactly as intended. Something else was standing in the way.

This is a walkthrough of how I tracked the issue down, the dead ends I encountered, and why Conditional Access should always be one of the first places you investigate.

---

## The Symptom

After assigning the account the Global Administrator role through the Microsoft 365 admin portal, every attempt to access an administrative portal resulted in an error similar to:

```text
You don't have permission to access this page.

Your sign-in was successful, but it doesn't meet the conditional access policy assigned to you.
```

The important clue was that authentication succeeded.

The account was successfully signing in, but authorization was being interrupted after authentication completed.

That distinction immediately shifted my focus away from role assignments and toward Conditional Access.

---

## The Investigation

### 1. Verify the Role Assignment

The first assumption was simple:

Did the Global Administrator assignment actually apply?

The account had already been promoted successfully inside the Microsoft 365 admin center, so there was no indication that the directory role itself had failed.

Since authentication was succeeding, the issue clearly was not an invalid account or missing administrative role.

---

### 2. Review Sign-In Logs

The next stop was the Microsoft Entra sign-in logs.

Navigate to:

```text
Microsoft Entra
  -> Monitoring
      -> Sign-in logs
```

Locate the failed sign-in attempt and open the Activity Details.

The most valuable tab here is:

```text
Conditional Access
```

This page lists every Conditional Access policy evaluated during the authentication process along with whether each policy allowed, challenged, or blocked the sign-in.

This is often the fastest way to determine exactly why an administrator cannot access Microsoft services.

---

### 3. Identify the Policies Being Evaluated

Several policies appeared during evaluation.

Some required additional authentication.

Others required a compliant device.

One policy explicitly returned a Block result.

Seeing multiple policies is normal.

A sign-in may satisfy several policies simultaneously while failing only one.

The goal is to identify which policy actually prevented access.

---

### 4. Investigate the Microsoft-Managed Policy

One policy initially looked suspicious because it referenced administrators accessing Microsoft admin portals.

However, after opening the policy details, its state was:

```text
State: Off
```

This raised an important question.

Could a disabled Microsoft-managed policy still be enforcing restrictions?

The answer was no.

If the policy state is Off, it is not evaluated or enforced during authentication.

Even though the policy targeted administrator roles, it was not contributing to the problem.

That ruled out another possible cause.

---

## What the Evidence Showed

The investigation ultimately pointed toward active Conditional Access policies rather than administrative permissions.

Examples included policies similar to:

* Email-only user restrictions
* Legacy authentication blocking
* Device compliance requirements
* Multifactor authentication requirements

The Global Administrator role only grants permissions.

Conditional Access determines whether those permissions are allowed to be exercised under current conditions.

Those are two completely separate authorization layers.

This is one of the easiest concepts to overlook when troubleshooting Microsoft identity issues.

---

## The Root Cause

The administrator account was correctly assigned the Global Administrator role.

However, one or more active Conditional Access policies were still applying to the account and preventing access.

Examples of common causes include:

* Membership in a restricted user group
* Device not marked compliant
* Required MFA enrollment not completed
* Location restrictions
* Explicit block policies

In other words:

The account had sufficient privileges.

The authentication context did not satisfy organizational security policy.

---

## The Resolution

The next troubleshooting steps were straightforward.

Review each active Conditional Access policy and determine whether the administrator account should be excluded or configured to satisfy the policy requirements.

Typical review locations include:

```text
Microsoft Entra
  -> Protection
      -> Conditional Access
          -> Policies
```

For each relevant policy, verify:

* Included users or groups
* Excluded users or groups
* Grant controls
* Device requirements
* Location conditions
* Authentication strength or MFA requirements

If appropriate, temporarily exclude the administrator account while validating access.

After successful testing, decide whether the exclusion is permanent or whether the account should instead comply with organizational policy.

---

## Gotchas and Roadblocks

Several details made this investigation more confusing than expected.

### Global Administrator is not an override

Many administrators assume Global Administrator bypasses Conditional Access.

It does not.

Conditional Access is evaluated independently of directory roles.

### Sign-in succeeded

The wording of the error is easy to misinterpret.

Because authentication succeeded, password resets and role changes were never going to solve the problem.

### Microsoft-managed policies can be misleading

Simply seeing a Microsoft-managed policy in the environment does not mean it is responsible.

Always check the policy state before spending time investigating it.

An Off policy is not enforcing anything.

### Multiple policies can appear simultaneously

Seeing numerous Conditional Access policies in the sign-in log does not mean they all caused the failure.

Focus on the policies that actually return Block or unmet grant requirements.

---

## Key Takeaways

* Global Administrator does not bypass Conditional Access.
* Successful authentication does not guarantee successful authorization.
* The Conditional Access tab in sign-in logs should be one of the first troubleshooting steps.
* Verify whether a Microsoft-managed policy is actually enabled before investigating it.
* Separate directory role troubleshooting from Conditional Access troubleshooting.
* Maintain an emergency administrator account that is excluded from restrictive Conditional Access policies when organizational policy allows.

---

## Summary

**Symptom**

A newly assigned Global Administrator could not access Microsoft administrative portals despite successful authentication.

**Investigation**

Verified the role assignment, reviewed Microsoft Entra sign-in logs, examined the Conditional Access evaluation, and confirmed that a Microsoft-managed administrator policy was disabled.

**Root Cause**

Active Conditional Access policies were preventing access even though the account had sufficient administrative privileges.

**Resolution**

Review active Conditional Access policies, determine which policy is enforcing the restriction, and either satisfy the required conditions or appropriately exclude the administrator account.

Sometimes the hardest bug to find is the one that is doing exactly what you told it to do.
