# Mail Delivery Triage

A guided check for "I never got the email" and "mail is delayed" tickets. Give the recipient, and optionally the sender and how far back to look (default 48 hours, up to 240). CIPP runs nine read-only checks in order and returns an evidence bundle: each check is marked **OK**, **Problem** or **Unknown** (could not be checked), with a plain-English summary on top.

Nothing is changed in the tenant. All times are shown in US Central (CDT/CST, stated) with UTC alongside.

## The checks

| # | Check | What makes it a Problem |
| - | ----- | ----------------------- |
| 1 | Service health | An open Exchange Online incident, or an advisory about mail flow or delivery. |
| 2 | Message trace | Nothing arrived in the window (with a sender: the sender's side never handed it over), or messages were filtered as spam (Junk), quarantined, failed or are still pending. |
| 3 | Quarantine | Unreleased quarantined messages for the recipient (and sender, if given). |
| 4 | Mail flow rules | An enabled, enforced transport rule names the sender, the sender's domain, the recipient or the recipient's domain and deletes, rejects, quarantines, redirects, moderates or sets SCL 5+ - unless one of its exceptions covers this mail. Broad rules with such actions (attachment-type blocks, for example) are listed as notes. |
| 5 | Inbox rules | A rule (hidden rules included) deletes, moves or redirects mail from this sender, or does so for every message. |
| 6 | Restrictions | The recipient only accepts mail from listed senders, rejects this sender, only accepts internal senders (and the sender is external), or forwards everything without keeping a copy. |
| 7 | Quota | The mailbox is full (new mail bounces with 5.2.2) or above 95% of its receive quota. Archive state is shown. |
| 8 | Block lists | A Tenant Allow/Block List sender block covers the sender (address, domain or `*.TLD`), the user has blocked the sender in Outlook, or the user only accepts mail from Safe Senders. |
| 9 | Sign-in | The account is disabled, or its recent sign-ins all failed (the mail may be there but the user cannot get to it). |

## Posting to ConnectWise

After a run, enter a ConnectWise ticket number and choose **Post as internal note**. CIPP posts the summary and each check (with a few evidence rows) as Markdown to the ticket's **Internal Analysis** tab with ConnectWise notifications off, so the client is not emailed. **Preview note** shows the text without posting.

The note is refused when the ticket belongs to a different ConnectWise company than the one this tenant is mapped to (Settings > Integrations > ConnectWise mapping). If the tenant has no mapping the note is posted and the result says the company was not checked. This uses the ConnectWise extension's stored credentials.

## Limits

* Message trace is read with Get-MessageTraceV2 under the recipient's primary address; it holds 90 days.
* A message the sender's server never sent does not appear anywhere in Microsoft 365. Ask for the bounce (NDR) or the exact send time.
* Inbox rules only show rules stored on the server; client-only Outlook rules are not visible.
* Sign-in activity needs Entra ID P1. Without it the check reports the account state only.

{% hint style="info" %}
Aspendora fork addition (Vikunja CIPP-38). API: `ListMailTriage` (read, Exchange.Mailbox.Read) and `ExecMailTriageNote` (Exchange.Mailbox.ReadWrite).
{% endhint %}
