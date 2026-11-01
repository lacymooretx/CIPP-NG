# Message Center Digest

Lists the Microsoft 365 Message Center posts that need attention, once each, with the tenants they were posted to. Microsoft publishes 100 or more posts a week, and almost all of them are tagged "Admin impact". This page sorts out the few that carry a deadline, retire something or change security behaviour. The page is read only.

With **All Tenants** selected, the page reads the posts cached in the CIPP reporting database. Posts are cached nightly, at about 03:00 US Central. For a single tenant it also reads the cache, and only calls Graph live when that tenant has nothing cached. Tenants with no cached posts are listed in a warning at the top of the page.

## Which posts are shown

A post is shown when it was published or updated in the last 7 days, or when its deadline is 30 days away or less. The **Window Reason** column says which: New, Updated or Deadline approaching. Informational posts are hidden until you turn on **Include informational**.

## Categories

Each post gets the first category that matches. The **Flags** field in the row details lists every rule that matched, and **Reasons** says why.

| Category | When | Alerts |
| --- | --- | --- |
| Action required / deadline | Microsoft set an act-by date (`actionRequiredByDateTime`), the severity is high or critical, the post is tagged Breaking change, or the title starts with "Action required". | Yes |
| Retirement | Tagged Retirement, or the title says retire, deprecate, end of support/life/availability or sunset. | Yes |
| Security / compliance | Tagged Data privacy; a security word in the title (MFA, authentication, phishing, malicious, Conditional Access, passkey, TLS, SMTP AUTH and similar); or a planned change or major change to Defender, Entra or Purview. | Yes |
| New feature off by default / opt-in | The title or summary says off by default, not enabled by default, opt-in, or that admins must turn it on. | No |
| On by default (admin opt-out) | The title or summary says on/enabled by default, default enablement, opt-out, or "will become the default". | No |
| Informational | Everything else. | No |

The rules are kept in one table in `Get-CIPPMessageCenterClassification.ps1`, so they can be tuned in one place. Keyword rules only read the title and Microsoft's summary. The full post body uses words like "security" in too many ordinary feature posts to be a useful signal.

## Deadlines

**Deadline** is Microsoft's act-by date shown as a US Central date. Microsoft sets the date at midnight Pacific time, so 2026-11-06T07:00Z is shown as 2026-11-06. **Days left** counts calendar days in US Central time. **Deadline status** is one of:

* Due soon: 30 days or fewer away.
* Overdue: the date has passed.
* Upcoming: more than 30 days away.

Only about 1 post in 20 has an act-by date. Retirements often give their date only in the text, and the page does not read dates from the text.

## Weekly alert

The **Weekly Message Center digest** alert (`MessageCenterDigest`, recommended interval 7 days) uses the same rules. It raises only the Action required, Retirement and Security categories. Schedule it on the **partner tenant**. When it runs on the partner tenant, it digests every managed tenant in one run, so each post is one row listing all the tenants it affects. When it runs on any other tenant, it covers only that tenant, unless **Digest all managed tenants** is on. Do not schedule it on All Tenants with that switch on, or every tenant sends the same digest.

Each post notifies once:

* A post notifies when it first appears.
* A post with a deadline stays open, without notifying again, until its deadline passes.
* A deadline post notifies a second time, marked **DUE IN n DAYS**, when the deadline is 30 days away or less. Change the number of days with the alert's deadline input.

Each alert row carries the MC id, title, deadline, days left, tenants and admin center link, so a ticket or task can be raised from it. The alert does not create ConnectWise tickets or Vikunja tasks.

{% hint style="info" %}
Times on this page are US Central. The cache timestamp in the last tile is the oldest tenant's cache time.
{% endhint %}

Aspendora fork addition (Vikunja CIPP-37). Endpoint: `/api/ListMessageCenterDigest?tenantFilter=<tenant|AllTenants>&days=7&deadlineDays=30&includeInformational=false`.
