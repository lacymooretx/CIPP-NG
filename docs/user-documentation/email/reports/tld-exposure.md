# Abused TLD Exposure

An audit-only report for one tenant: how much mail came **from** senders under heavily abused top-level domains (for example `.zip`, `.top`, `.xyz`, `.icu`, the former Freenom `.tk`/`.ml`/`.ga`/`.cf`/`.gq`), and how much the tenant's users **sent to** them. Run it before blocking those TLDs so you can see what a block would have stopped and what it would have broken. It changes nothing.

## Why outbound matters

A Tenant Allow/Block List **sender** block (`*.TLD`) quarantines inbound mail from that TLD as high confidence phishing **and** stops users sending to it: Microsoft rejects the message with `550 5.7.703`, and the whole message fails for every recipient if one recipient matches. The outbound counts and the "Top recipient domains" table are the business mail that would break.

## Running it

| Field | Description |
| ----- | ----------- |
| Days back | 1 to 90 (default 10). Message trace keeps 90 days. |
| Max pages | Each page is up to 5,000 trace rows (default 10). Busy tenants, especially ones that journal, can produce 5,000 rows a day. When the cap is hit the report says so and shows how far back it got. |
| TLDs | Optional, for example `xyz,top`. Empty uses the full abused-TLD list. |

The report shows per-TLD inbound messages (and how many were already delivered or already filtered), outbound messages and the number of internal senders, plus the top sender domains and top outbound recipient domains. Each TLD carries a sender and URL false-positive risk rating.

URL blocks (`*.TLD/*`) act on links inside messages, which message trace cannot see; use Threat Explorer or URL click reports for link exposure. For a full 90-day view on a busy tenant, use [Historical Search](../../tools/email-tools/historical-search.md).

## Block templates

The page lists three Tenant Allow/Block List templates that ship with CIPP. They are **not deployed**:

| Template | Entries | Notes |
| -------- | ------- | ----- |
| Abused TLDs - Senders | `*.TLD` for every listed TLD | Also blocks outbound mail to those TLDs. |
| Abused TLDs - URLs | `*.TLD/*` for every listed TLD except .zip and .mov | Blocks messages with links to those hosts. |
| Abused TLDs - URLs .zip/.mov | `*.zip/*`, `*.mov/*` | High false-positive risk: file names such as `invoice.zip` in body text can be read as links. Microsoft may also refuse these as file extensions. |

**Save to template library** adds them to Email > Allow/Block List Templates (saving again updates them in place). To use one, add the **Tenant Allow/Block List Template** standard to a standards template, pick the template, and run it in report mode first.

## Exceptions for one tenant

In the Tenant Allow/Block List, **block entries beat allow entries**, so an allow entry for `partner.xyz` does not get past a `*.xyz` block. Instead:

* Leave the tenant out of the standards template that deploys the TLD block (exclude it, or use a tenant group without it), or
* Save a copy of the template without the TLD that tenant needs and use that copy in the tenant's standards template.

The standard only ever adds entries. If a tenant already has the block and needs an exception, remove the `*.TLD` entry on its Tenant Allow/Block Lists page as well.

{% hint style="info" %}
Aspendora fork addition (Vikunja CIPP-30). API: `ListTldExposure` (Exchange.SpamFilter.Read) and `ExecTldBlockTemplates` (Exchange.SpamFilter.ReadWrite; Action=Preview or Save).
{% endhint %}
