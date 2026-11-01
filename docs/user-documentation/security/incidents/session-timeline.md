# Session Timeline

Shows exactly what one Entra sign-in session read, sent, shared or changed. Take the **Session ID** of a suspicious sign-in, and the page pulls every Unified Audit Log record that carries the same session, merges it with the session's sign-ins and shows one timeline in US Central time (UTC alongside). Use it to turn "the attacker had access" into a precise list of what was touched, which drives client notification.

It changes nothing in the tenant. It creates one audit log search, which also shows on the Audit Log Searches page.

## How to use it

1. Find the session ID: in the Entra admin center open the suspicious sign-in (**Sign-in logs > the sign-in > Basic info > Session ID**). Or pick the user here and press **List sessions**: the page lists the user's interactive sessions in the last days (default 7) with first and last sign-in, IP addresses, countries and apps. **Trace this session** on a row starts the search.
2. Paste the session ID and press **Start search**. The user and the time window are taken from the session's sign-ins: from 15 minutes before the first sign-in to 2 hours after the last one. Enter a user and a window yourself if the sign-ins are older than 30 days.
3. Microsoft runs the search in the background, usually 5-20 minutes. The page checks every 30 seconds and shows the timeline when it is done.

You can link straight to it: `/security/incidents/session-timeline?sessionId=<id>&userPrincipalName=<upn>`.

## What you get

* **Highlights**: sign-ins (and failed ones), mails read, attachments opened, mails sent and deleted, inbox rule and forwarding changes, mailbox permission changes, files accessed, downloaded, changed and deleted, shares created, Teams messages and app consents. Changes and exfiltration are shown in orange.
* **Timeline**: time, workload, operation, the object, count, result, client IP, location (sign-ins), user agent, app and which field tied the record to the session.
* **By operation** and **By client IP** counts. Several IP addresses in one session can mean a stolen session cookie or token being replayed.

Mail is identified by its Internet message ID and folder, never by subject. Files are shown by path.

## How records are tied to the session

The Unified Audit Log has no session filter, so CIPP searches the user's Exchange, SharePoint, OneDrive, Teams and Entra logon records for the window and keeps a record when:

| Field in the audit record | Where it appears |
| --- | --- |
| `AppAccessContext.AADSessionId` equals the session | Exchange mailbox items (MailItemsAccessed, Create, FolderBind, AttachmentAccess), Exchange admin cmdlets (Set-Mailbox, New-InboxRule), SharePoint and OneDrive file operations |
| `SessionId` equals the session | Exchange records (the same value as AADSessionId) |
| `DeviceProperties` SessionId equals the session | Entra logon records (UserLoggedIn, UserLoginFailed) |
| `AppAccessContext.UniqueTokenId` is the token ID of one of the session's sign-ins | Records that carry the token but no AADSessionId, such as some MailItemsAccessed and Send records |

These were checked against live audit records on 2026-11-01. Teams records were not in that sample; they are matched by the same fields when they carry them. Directory changes (Update user, Add member to group) carry no session field and cannot be tied to a session; look at them in the user's audit log instead.

{% hint style="info" %}
**Not included: Graph activity logs.** Microsoft Graph activity logs (what an app or token read through Graph) exist only when the tenant sends them to Log Analytics, a storage account or an Event Hub through Entra diagnostic settings. CIPP cannot read those.
{% endhint %}

## Limits

* Sign-ins are kept for 30 days and need Entra ID P1. The audit log goes back 180 days, so for an older session enter the user and the window yourself.
* A busy session can have thousands of background token refreshes. The newest 999 sign-ins are used; the page says when there were more, and token-ID matching then only covers those.
* The window is capped at 31 days. Microsoft caps a search at its record limit and the page says when that happens; narrow the window.
* Unified auditing must be on in the tenant. If it is off, the search is not created and the page says so.
* Starting a search needs Security.Incident.ReadWrite; reading the timeline needs Security.Incident.Read.

Aspendora fork addition (Vikunja CIPP-12). Endpoints: `POST /api/ExecSessionTimelineSearch` with `tenantFilter`, `sessionId` and optional `userPrincipalName`, `startTime`, `endTime` (ISO 8601 or Unix seconds) returns `QueryId`; `GET /api/ListSessionTimeline?tenantFilter=<tenant>&queryId=<id>&sessionId=<id>` returns the status and, when `Ready` is true, the timeline; `GET /api/ListSessionTimeline?tenantFilter=<tenant>&userPrincipalName=<upn>&days=7` lists recent sessions.
