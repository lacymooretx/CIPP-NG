# CIPP-30 / CIPP-38: abused-TLD block templates and mail delivery triage (Aspendora fork)

Branch `feat/cipp30-38-mail`, based on `aspendora` 80df12d7d. Built 2026-10-31. Nothing deployed; no template saved; no tenant or ConnectWise write made.

## CIPP-30: abused-TLD Tenant Allow/Block List templates

### What Microsoft supports (checked 2026-10-31, Microsoft Learn)

* Sender TLD block: `*.TLD` (for example `*.zip`). Blocks inbound **and** outbound: users get `550 5.7.703` and the whole message fails for every recipient if one matches.
* URL TLD block: `*.TLD/*`. `*.com` alone is invalid. URL entries may not be file extensions (`test.pdf`), so `*.zip/*` and `*.mov/*` may be refused.
* **Block entries beat allow entries.** An allow for `partner.xyz` does not get past `*.xyz`.
* Limits: 500 sender blocks without Defender for Office 365, 1000 with Plan 1, 10000 with Plan 2. The templates use 20 sender and 20 URL entries.

### The list

`.zip .mov .top .xyz .click .sbs .cfd .bond .cyou .icu .buzz .rest .quest .lol .country .gq .cf .tk .ml .ga` (Config/AbusedTlds.json, with a note on each).

False-positive risk for US SMB clients:

* **Medium (check ListTldExposure first):** `.xyz` (real startups, crypto/web3 vendors, some SaaS), `.top` and `.click` as URL blocks (some ESP / link-shortener tracking domains).
* **High, URL only:** `.zip` and `.mov`. A file name such as `invoice.zip` in body text can be read as a link. These are in their own template.
* **Low:** the rest, including the former Freenom ccTLDs, which are almost entirely abuse.

### Pieces

| Piece | Path |
| ----- | ---- |
| TLD list + risk | `backend/Config/AbusedTlds.json` |
| Importable templates | `backend/Config/TenantAllowBlockListTemplates/AbusedTlds-{Senders,Urls,Urls-FileLike}.json` (exact `AddTenantAllowBlockListTemplate` body shape, plus `GUID` and `description`) |
| Save into the library | `POST /api/ExecTldBlockTemplates` `{ Action: "Save" }` (Exchange.SpamFilter.ReadWrite). `Preview` (default) just returns them. Fixed GUIDs, so a re-save updates in place. |
| Audit | `ListTldExposure?tenantFilter=x&Days=10&MaxPages=10[&Tlds=xyz,top]` (Exchange.SpamFilter.Read) |
| UI | Email > Reports > Abused TLD Exposure (`/email/reports/tld-exposure`) |

The templates can also be imported by POSTing the JSON body to the existing `AddTenantAllowBlockListTemplate` (that creates a new random GUID each time).

### Audit window

Get-MessageTraceV2 keeps 90 days, answers 10 days and 5000 rows per query, has no wildcard sender filter and no paging token (continuation is `StartingRecipientAddress` + `EndDate` from the last row; verified on 3endt.com). The Graph message-trace API **silently ignores** `endswith(senderAddress,'.xyz')` (verified on aspendora.com), so there is no server-side TLD filter: the audit reads everything and counts locally.

Volume seen 2026-10-31: aspendora.com and 3endt.com each produced about 5000 trace rows per day (journaling to Avanan and DropMyEmail doubles rows). 10 days is about 10 pages; 90 days is about 90 pages, past the cap. For a full 90-day view use Historical Search (Start-HistoricalSearch, already in CIPP under Email Tools > Message Trace > Historical Search).

Probe on the last ~24 h of each tenant (one 5000-row page): **zero** inbound or outbound mail touching any listed TLD, at aspendora.com or 3endt.com.

### Per-tenant exceptions

Allow entries do not override the block. Exclude the tenant from the standards template that deploys the block (or use a tenant group without it), or save a copy of the template without that TLD and use it for that tenant. The standard only adds entries, so a tenant that already has the block needs the entry removed by hand (Tenant Allow/Block Lists page).

### Rollout (Lacy)

1. Deploy the branch. Run `pwsh build/tools/build-openapi.ps1` first (openapi.json is generated; not hand-edited here) and the Pester suite.
2. Run Abused TLD Exposure for each tenant (Days 10, raise MaxPages for busy tenants). Note anything in the outbound table.
3. Save to template library. Add the **Tenant Allow/Block List Template** standard with the Senders template to a standards template scoped to Aspendora only, **report mode**; then remediate.
4. Test the URL template in Aspendora first; try the .zip/.mov template last and expect Microsoft to possibly refuse it.
5. Widen to client tenants after a week with no complaints, excluding any tenant with outbound exposure.

## CIPP-38: mail-not-received triage

### Endpoint

`ListMailTriage` (Exchange.Mailbox.Read). Body: `tenantFilter`, `Recipient`, optional `Sender`, optional `Hours` (default 48, max 240). Returns:

```
{ Tenant, Recipient (primary SMTP), Sender, Hours,
  WindowStart/WindowEnd/GeneratedAt: { Utc, Central, Display },   e.g. "2026-10-31 18:51 CDT (23:51 UTC)"
  TimeZone, Overall: OK|Problem|Unknown, Summary,
  Steps: [ { Order, Key, Title, Status, Summary, Findings[], Evidence, DurationS } ] }
```

Steps in order: ServiceHealth, MessageTrace, Quarantine, TransportRules, InboxRules, Restrictions, Quota, SenderBlocks, SignIn. A step that cannot be read is Unknown and does not stop the others. Every call is a Get-* (the Pester test asserts no non-Get cmdlet is called). The trace uses Get-MessageTraceV2 directly so it never provisions the Graph trace SP (ListMessageTrace does).

Reused: same EXO/Graph calls as ListMessageTrace (V2 path), ListMailQuarantine (Get-QuarantineMessage), ListUserMailboxRules (Get-InboxRule -IncludeHidden), ListServiceHealth (serviceAnnouncement/issues), ListUserSigninLogs (beta signIns by userId).

### ConnectWise note

CIPP's PSA path (New-CippExtAlert -> New-ConnectWiseTicket) only adds a note to a ticket it opened itself (ConsolidateTickets table); nothing posts to a ticket by number. Added `Add-ConnectWiseTicketNote` (CippExtensions) using the extension's stored credentials (`Get-ConnectWiseHeaders`):

1. `GET service/tickets/{id}?fields=id,summary,company,closedFlag,...`; refuse if missing, or if `company.id` is not the tenant's ConnectWise mapping (CippMapping, PartitionKey ConnectWiseMapping, RowKey = tenant customerId). `Force=true` skips the company check.
2. `POST service/tickets/{id}/notes` with `internalAnalysisFlag: true, internalFlag: true, detailDescriptionFlag: false, processNotifications: false` (no CW email; Aspendora's Email Bridge mails Discussion notes, so Internal Analysis keeps the client out of it).

Text is classic-Manage-safe Markdown (bold, numbered list, no HTML), capped at 12000 characters (Asio's limit), dropping evidence rows first. `ExecMailTriageNote` (Exchange.Mailbox.ReadWrite) takes `tenantFilter`, `TicketId`, `Bundle` (or `Recipient`/`Sender`/`Hours` to re-run) and `Preview=true` to return the text without posting.

UI: Email > Email Tools > Mail Delivery Triage (`/email/tools/mail-triage`).

### Production probes (read-only, 2026-10-31)

Shapes confirmed on aspendora.com: Get-MessageTraceV2 rows (Received UTC `Z`), Graph serviceAnnouncement issues filtered to Exchange Online (one open OWA Notes advisory, correctly not mail-flow), Get-TransportRule (15 rules incl. attachment-type delete rule `RansomwareBlocking`, which the triage lists as a broad finding), Get-InboxRule -IncludeHidden (returns the hidden "Junk E-mail Rule" and a delegate rule), Get-Mailbox restriction/quota properties, Get-MailboxStatistics (incl. `-Archive`), Get-QuarantineMessage by recipient + sender, Get-TenantAllowBlockListItems Sender, Get-MailboxJunkEmailConfiguration (large: 160 blocked / 1198 trusted entries on one mailbox).

## Tests

`backend/Tests/Email/AbusedTldTemplates.Tests.ps1`, `TldExposure.Tests.ps1`, `MailTriage.Tests.ps1`, `backend/Tests/Extensions/Add-ConnectWiseTicketNote.Tests.ps1`. Written with mocks; **not run** by the agent (pwsh blocked). Frontend: eslint clean, `next build --webpack` passes; help-links test passes for both new pages (13 pre-existing failures for other fork pages without docs).

## Rollback

Revert the branch commits. The only stored state is the three template rows (templates table, PartitionKey TenantAllowBlockListTemplate, RowKeys a70c6b39-..., bee99ed5-..., 18fc3dc5-...) if Save was used; delete them on the Allow/Block List Templates page. Any TABL entries a standard deployed must be removed per tenant.
