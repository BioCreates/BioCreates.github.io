+++
title = "Transferring A Domain Without Breaking WordPress Or Email"
slug = "domain-transfer-without-downtime"
date = "2026-07-24"
author = "RoninSec"
cover = "/img/domain-transfer-without-downtime-banner.png"
tags = ["dns", "domain-transfer", "wordpress", "email-migration", "troubleshooting"]
keywords = ["domain transfer", "dns migration", "wordpress hosting", "email routing", "mx records", "nameserver change", "zero downtime"]
description = "A practical walkthrough for transferring a domain while keeping WordPress hosted separately and preserving the existing email service."
showFullContent = false
readingTime = true
hideComments = false
draft = false
+++

# Transferring A Domain Without Breaking WordPress Or Email

A domain transfer sounds simple until the registrar, DNS provider, website host, and email provider are all different companies.

That was the situation I ran into with a small business domain. The goal was to move the domain registration to a new provider, keep the WordPress website exactly where it was, and temporarily retain the existing hosted email service.

The challenge was making sure the transfer did not accidentally replace the website with a default hosting page or route incoming mail to the wrong provider.

---

## The Symptom

The original environment was split across three services:

* The domain was registered with one provider.
* DNS was hosted by the WordPress hosting provider.
* Email was hosted through the original registrar.
* The new registrar also offered DNS, email, and basic web hosting.

The client wanted to reduce costs by transferring the domain registration to the new provider. However, the existing WordPress website needed to remain untouched because the new provider did not offer a compatible WordPress hosting environment.

The main concern was straightforward:

> Can I transfer the domain without moving the website or interrupting email?

The answer was yes, but only if I treated domain registration, DNS, web hosting, and email as separate services.

---

## The Investigation

### 1. I documented the existing DNS zone

Before touching the domain, I copied every DNS record from the existing DNS provider.

The important records included:

* Root A and AAAA records for the website
* A record for the FTP hostname
* CNAME for `www`
* MX record for hosted email
* SPF and DMARC TXT records
* Autodiscover and identity-related CNAME records
* SIP and federation SRV records
* Certificate Authority Authorization records

I treated this export as the rollback plan. Once nameservers change, records at the old DNS provider no longer answer queries.

### 2. I separated the four functions

I mapped the desired final state:

| Function            | Final Location                       |
| ------------------- | ------------------------------------ |
| Domain registration | New registrar                        |
| Authoritative DNS   | New registrar                        |
| WordPress website   | Existing web host                    |
| Email               | Existing email provider, temporarily |

This was the key mental model. Transferring the domain did not require transferring the website.

The new DNS zone only needed to tell browsers to visit the existing web server and tell mail servers to continue using the existing email platform.

### 3. I prepared the registrar transfer

The transfer required:

1. Confirming the domain was not near expiration.
2. Unlocking the domain.
3. Obtaining the EPP authorization code.
4. Verifying access to the registrant contact address.
5. Initiating the inbound transfer.
6. Approving any transfer notices.
7. Waiting for the transfer to complete.

Unlocking the domain and initiating the transfer did not change DNS, so the website and email remained online during this stage.

### 4. I encountered the privacy contact problem

The registration contact was hidden behind a privacy proxy address. That created uncertainty because the transfer confirmation could be delivered to the proxy instead of an inbox I could access.

I updated the registration contact address, but this introduced another major gotcha: changing the registrant name, organization, or email can trigger a 60-day transfer lock.

The registrar interface provided an option similar to:

```text
Do not lock domain transfers after contact information updates
```

I selected that option before submitting the contact update.

This was one of the most important steps in the entire process. Missing that checkbox could have delayed the project for two months.

### 5. The transfer completed without the expected approval message

I expected a transfer approval message from both the losing and gaining registrars, but I did not receive the expected message.

After more than a week, the domain appeared in the new provider's control panel and no longer appeared under the old registrar.

I could not definitively prove whether the transfer had been automatically approved, timed out into completion, or processed through another registrar workflow. The evidence still indicated that the transfer had completed successfully.

### 6. I reviewed the new DNS zone

The new provider automatically created records for its own services:

* A records pointing to its default web hosting server
* MX records pointing to its mail servers
* Its authoritative NS records

Those defaults were wrong for the desired design.

If left in place, the website would eventually resolve to the new provider's placeholder server, and incoming mail would begin routing to mailboxes that had not been configured.

### 7. I replaced the core records first

I changed the root website record to the existing WordPress host:

```text
A    example.org        <WEB-HOST-IP>
```

For `www`, I used either a CNAME to the root domain or an A record to the same server, depending on what the DNS interface supported:

```text
CNAME    www.example.org    example.org
```

I then removed the new provider's MX records and restored the existing email provider's MX destination:

```text
MX    example.org    0    example-org.mail.protection.example
```

Supporting records were restored afterward:

```text
TXT    example.org    v=spf1 include:mail-provider.example -all
TXT    _dmarc.example.org    v=DMARC1;p=none;sp=none;adkim=r;aspf=r;pct=100
```

I also recreated the required autodiscover, identity, SIP, and federation records from the original DNS export.

### 8. I hit a confusing SRV record interface

The DNS panel split SRV records into separate fields for service, protocol, port, priority, weight, and destination.

The original record looked like this:

```text
_sip._tls
```

The interface rejected multiple formats, including versions with and without underscores.

Because the panel behavior was unclear, I did not assume the record was successfully created. This was a good reminder that optional collaboration records should not delay restoration of the core website and mail flow.

### 9. I planned external validation

After saving the records, I planned to verify them from multiple resolvers:

```bash
nslookup example.org
nslookup -type=mx example.org
nslookup -type=txt example.org
nslookup -type=ns example.org
```

On systems with `dig` available:

```bash
dig example.org A
dig www.example.org CNAME
dig example.org MX
dig example.org TXT
dig _dmarc.example.org TXT
dig example.org NS
```

I also planned real-world tests:

* Load the website using the root domain and `www`.
* Send mail into the domain from an external mailbox.
* Send mail out and inspect SPF results.
* Confirm the old registrar no longer lists the domain.
* Confirm the old email subscription remains active until a later migration.

---

## What The Evidence Showed

The domain transfer itself did not move the WordPress site or email service.

The real risk appeared after the transfer, when the new DNS provider created default records for its own hosting and mail platforms.

The website and email initially continued working, but that did not prove the new DNS zone was correct. Cached DNS responses can temporarily hide bad authoritative records.

The safe approach was to replace the incorrect records before relying on apparent uptime.

---

## The Root Cause

The underlying issue was not the registrar transfer.

The root cause was assuming that transferring a domain would preserve or migrate every connected service automatically.

It did not.

The new registrar became responsible for the domain registration, while the nameserver change made its DNS zone authoritative. Its default DNS records pointed to services the client was not yet using.

---

## Key Takeaways

* Domain registration, DNS, website hosting, and email hosting are separate services.
* Unlocking a domain does not interrupt the website or email.
* Starting a registrar transfer does not normally change nameservers.
* Export the entire DNS zone before changing anything.
* Changing registrant contact information can trigger a 60-day lock.
* Look for an explicit option to opt out of the post-change transfer lock.
* Do not cancel the old email subscription until the replacement mailboxes and DNS records are tested.
* Cached DNS can make an incorrect configuration appear healthy temporarily.
* Replace incorrect A and MX records before spending time on optional records.
* Treat unfamiliar SRV record interfaces carefully and validate externally.

---

## Summary

> **Symptom:** A client needed to transfer a domain while keeping WordPress at the existing host and retaining the current email provider.
>
> **Investigation:** I documented the DNS zone, unlocked the domain, obtained the authorization code, addressed privacy contact issues, monitored the transfer, and inspected the new provider's default DNS records.
>
> **Root Cause:** The new authoritative DNS zone automatically pointed the website and email toward the new provider's services instead of the existing hosts.
>
> **Resolution:** I restored the website A and CNAME records, restored the existing MX and email authentication records, retained the old email subscription, and scheduled external DNS and service validation.

The domain moved, the website stayed put, and DNS once again proved that "simple migration" is usually three services wearing a trench coat.
