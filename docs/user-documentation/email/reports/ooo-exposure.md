# Out-of-office Exposure

A read-only report for one tenant: which mailboxes are sending an automatic reply to **external** senders right now, and what that reply gives away. An external out-of-office reply tells anyone who emails the mailbox, including an attacker, that the person is away, until when, and often who to contact instead. That is the timing and the impersonation target for business email compromise (BEC) payment fraud: "Hi, Sarah is out until the 12th, so I am chasing the invoice with you."

## What is listed

User and shared mailboxes whose auto-reply is **Enabled**, or **Scheduled** and inside its start/end window, with an external audience of **All** (every external sender) or **Known** (only senders in the mailbox's contacts). Mailboxes with the external audience set to None send nothing outside and are not listed. **Show upcoming (14 days)** adds scheduled replies that have not started yet, so you can fix them before they go live.

Times are shown in US Central time with the UTC value.

## Flags

The external message is reduced to plain text and checked for:

| Flag | What it means |
| ---- | ------------- |
| InternalEmail | An address in one of the tenant's accepted domains (other than the mailbox's own): a named colleague to impersonate or to target. |
| ExternalEmail | Any other address, for example a personal or partner address. |
| Phone | A phone number (written out, or in a tel: link). |
| Travel | Travelling, vacation, holiday, abroad, overseas, out of the country, conference, trade show, flight, business trip, in transit. City names are not checked. |
| ReturnDate | A written date (Nov 5, 11/05, 2026-11-05) or "back on Monday". |
| Title | A job title such as CFO, controller, office manager or executive assistant. |
| Finance | Invoices, payments, wires, ACH, payroll, billing, accounts payable/receivable, remittance, banking details, purchase orders. |

## Severity

| Severity | Rule |
| -------- | ---- |
| High | External audience All, and the message names a colleague's address, a phone number or a finance cue. |
| Medium | External audience All, no such cues. The reply still confirms the mailbox is live and the person is away. |
| Low | External audience Known (contacts only). |

The **Snippet** column masks addresses and phone numbers. The full message text is in the row's details panel only.

## Fixing an exposed reply

Set the mailbox's external audience to **Known** (contacts only) and take colleague addresses, phone numbers and payment instructions out of the external message. Today CIPP's out-of-office editor (Exchange settings on the user page, or the Set Out of Office user action) always sets the external audience to **All** when an external message is saved, so it cannot make this change; use Exchange admin center, or Outlook on the web as the user. Note that a reply scheduled through **Vacation Mode** with an external message gets audience All again when the vacation's start task runs.

## Alert

The scripted alert **Alert on out-of-office replies that expose colleagues, phone numbers or payment contacts to external senders** (`OooExposure`) raises High rows by default; switch on the Medium option to raise every All-audience reply. Each out-of-office period notifies once (a new schedule notifies again). The alert text carries the flags and the masked snippet, never the message. Recommended interval 4 hours: most out-of-office periods last a few days and the risk starts the moment the reply is turned on, so a daily check would leave a large part of the period unreported.

Tenants without Exchange Online are reported as such, not as errors.

{% hint style="info" %}
Aspendora fork addition (Vikunja CIPP-40). API: `ListOooExposure` (Exchange.Mailbox.Read; `tenantFilter`, optional `includeUpcoming`, `upcomingDays`). Settings are read with two Exchange bulk requests per tenant: state and schedule for every mailbox, then the external message for the listed mailboxes only.
{% endhint %}
