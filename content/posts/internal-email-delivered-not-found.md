+++
title = "When Internal Email Says Delivered but the User Cannot Find It"
slug = "internal-email-delivered-not-found"
date = "2026-08-03"
author = "RoninSec"
cover = "/img/internal-email-delivered-not-found-banner.png"
tags = ["email-troubleshooting", "mail-flow", "message-trace", "secure-email-gateway", "exchange-online"]
keywords = ["internal email missing", "message trace delivered", "blank destination ip", "mail flow troubleshooting", "inbox rules", "email gateway routing"]
description = "A practical investigation into an internal email marked delivered by the cloud mail platform but missing from the recipient mailbox."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# When Internal Email Says Delivered but the User Cannot Find It

An internal message was marked as successfully delivered by the cloud mail platform, but the recipient could not find it. The secure email gateway had no record of the message, and the destination IP field in the trace was blank.

At first glance, that looked like a routing failure between the cloud mail service and the email security gateway.

It was not that simple.

---

## The Symptom

The reported behavior was narrow:

* One internal recipient appeared to be affected.
* Internal senders reported that messages were not arriving.
* External sending and receiving still worked.
* One message trace showed Receive, Submit, Transfer, and Deliver events.
* The detailed trace said the message was successfully delivered.
* The secure email gateway did not show the message.
* The destination IP field was empty.
* A later test message did not immediately appear in the message trace.

The first temptation was to blame the gateway connector. That was understandable because the gateway had recently published an additional source IP range, and the connector configuration had not yet been updated.

However, several details pointed away from a simple gateway routing problem.

---

## The Investigation

### 1. Determine whether the message was internal or external

The sender and recipient were both mailboxes in the same cloud tenant and used the same accepted domain.

That matters because internal mailbox-to-mailbox messages are usually delivered inside the cloud service. They do not necessarily leave the provider, pass through the external gateway, and return.

A blank destination IP can therefore be normal for an internal delivery. There may be no remote SMTP host to display.

This was the first major gotcha:

> A blank destination IP does not automatically mean that delivery failed.

### 2. Review the message trace events

The trace contained the following sequence:

```text
Receive
Submit
Transfer
Deliver
```

The final event stated that the message was successfully delivered.

That evidence meant the transport service believed it had completed delivery to the recipient mailbox. It did not prove that the message was visible in the Inbox.

Once the Deliver event appears, the investigation should move beyond connector routing and into mailbox-level processing.

Possible destinations include:

* Inbox
* Junk Email
* Deleted Items
* Archive
* A folder selected by an inbox rule
* A folder selected by a client-side rule
* Recoverable Items
* Quarantine, depending on post-delivery processing
* A delegated mailbox or forwarding target

### 3. Check mailbox forwarding and recipient properties

I would inspect the mailbox for forwarding, alternate addresses, and unusual delivery settings.

```powershell
Get-Mailbox user@example.invalid |
    Format-List PrimarySmtpAddress,
                EmailAddresses,
                ForwardingAddress,
                ForwardingSmtpAddress,
                DeliverToMailboxAndForward
```

Expected findings for a normal mailbox would usually include:

```text
ForwardingAddress           :
ForwardingSmtpAddress       :
DeliverToMailboxAndForward  : False
```

An unexpected forwarding address could explain why transport reported success while the user did not see the message where expected.

### 4. Review inbox rules

Inbox rules are one of the most common causes of apparently missing mail.

```powershell
Get-InboxRule -Mailbox user@example.invalid |
    Format-List Name,
                Enabled,
                Priority,
                Description,
                MoveToFolder,
                DeleteMessage,
                ForwardTo,
                RedirectTo,
                StopProcessingRules
```

I would specifically look for rules that:

* Move messages based on sender or subject
* Delete messages
* Redirect messages
* Forward messages
* Stop later rules from running
* Use vague conditions such as body text or broad sender matching

Hidden, corrupted, or client-created rules may require additional investigation beyond the standard rule listing.

### 5. Test the web client

The user should check the mailbox through the provider's web interface rather than relying only on the desktop client.

This separates mailbox delivery from local synchronization.

* Message visible in the web client but not the desktop client: likely cache, profile, view, or synchronization trouble.
* Message missing from both: likely mailbox rule, filtering, retention, deletion, or transport-side processing.

The desktop client should also be checked for:

* Filters applied to the current folder
* Focused or categorized views
* Cached mode delays
* Shared mailbox confusion
* Conversation view grouping
* Local-only rules

### 6. Search the gateway logs correctly

The absence of an internal message from the external gateway was not proof of failure.

If the organization only routes internet-bound and internet-originated messages through the gateway, same-tenant messages may never appear there.

The mail-flow design must be confirmed before treating missing gateway logs as evidence.

### 7. Review the connectors without changing the accepted domain

The environment contained:

* A gateway-to-cloud inbound connector
* A cloud-to-gateway outbound connector
* An additional connector for an internal system

The connectors should be inspected for:

* Scope
* Smart host configuration
* Transport Layer Security requirements
* Sender domain restrictions
* Recipient domain restrictions
* Certificate validation
* Source IP validation

A newly published gateway network was added using the supported parent prefix because the connector interface did not accept the narrower subnet.

For example, if the gateway documents:

```text
198.51.100.0/25
```

but the interface only accepts a /24, the parent network would be:

```text
198.51.100.0/24
```

That change should only be made when the range is verified through official gateway documentation or support.

---

## What the Evidence Showed

The available evidence supported several conclusions:

1. The traced message entered the cloud transport service.
2. The service reported successful mailbox delivery.
3. The message did not need to pass through the external gateway merely because both gateway connectors existed.
4. The blank destination IP was consistent with internal delivery.
5. The newly added gateway IP range was relevant to connector trust, but it did not explain an internal message already marked delivered.
6. The delayed or missing trace for a later test could have been trace latency, an incorrect search window, an incorrect sender or recipient, or a message that was never submitted.

The evidence did not prove that the accepted domain type was wrong.

---

## The Root Cause

The exact root cause was not definitively proven during the conversation.

The strongest remaining possibilities were recipient-specific mailbox behavior or client visibility issues, including:

* Inbox rules
* Hidden or corrupted rules
* Forwarding
* Junk filtering
* Message movement to another folder
* Desktop client synchronization
* Cached profile problems
* Search or view filters
* Post-delivery deletion

Changing the accepted domain from Authoritative to Internal Relay would not have been an appropriate first fix.

An Authoritative domain simply means the cloud service is responsible for all valid recipients in that domain. Existing local mailboxes can still receive internal messages normally. Internal Relay is intended for shared namespace or split-delivery designs where some recipients exist outside the cloud tenant.

Changing that setting without a documented routing requirement could introduce nondelivery reports, unexpected routing, or mail loops.

That was the biggest troubleshooting roadblock in this case: a plausible routing theory was initially treated as a confirmed root cause before the evidence supported it.

---

## Key Takeaways

* A blank destination IP is often normal for same-tenant delivery.
* A Deliver event means transport completed delivery, not necessarily that the message remained in the Inbox.
* Missing gateway logs do not matter if internal mail is not designed to traverse the gateway.
* Check mailbox rules, forwarding, folders, quarantine, and the web client before changing connectors.
* Message trace searches may lag or miss messages when the time range, sender, or recipient is wrong.
* Do not change an accepted domain to Internal Relay unless the organization actually uses split delivery or a shared mail namespace.
* Connector IP ranges should only be expanded after confirming the published source range with the gateway provider.

---

> **Summary**
>
> **Symptom:** An internal message was marked delivered, but the recipient could not find it, the gateway had no record of it, and the destination IP was blank.
>
> **Investigation:** Reviewed trace events, connector roles, accepted-domain behavior, gateway IP ranges, forwarding, inbox rules, and client-versus-web visibility.
>
> **Root Cause:** Not conclusively proven. The evidence pointed more strongly toward recipient mailbox processing or client synchronization than a connector failure.
>
> **Resolution:** Keep the accepted domain unchanged, verify the gateway IP update independently, and continue with mailbox rules, forwarding, folder, quarantine, and web-client checks.

When the trace says "delivered," the email may not be lost - it may just be hiding better than the user who filed the ticket.
