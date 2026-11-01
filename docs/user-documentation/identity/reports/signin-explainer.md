# Sign-in Failure Explainer

Answers "why can't this user sign in?" in plain language. Pick a user (or paste the correlation ID from the user's error screen) and the page reads the tenant's Entra sign-in log live, keeps the failed and interrupted sign-ins plus the latest successful one, and explains each. It changes nothing in the tenant.

You can also open it from a user: **Explain sign-in failures** in the user actions menu opens this page for that user and runs it.

## What you get for each sign-in

* **Time** in US Central with UTC alongside, the app, client app, IP address and location, and the device (name, OS, browser, compliant, managed, join type).
* **The error code** (for example AADSTS53003), Microsoft's own reason, a plain-English explanation and a **Fix**.
* **Every Conditional Access policy** evaluated for that sign-in, with its result: applied and met, applied and *not* met (this is what blocks or prompts), did not apply (and which condition did not match), or report-only. For a policy that failed you see what it requires (block, MFA, compliant device, authentication strength, with "one of" / "all of" from the policy) and which conditions matched, for example location with the city, IP and whether it was a named location.
* **Where MFA came from**: Conditional Access (which policies), per-user MFA, security defaults, an Identity Protection risk policy or the app itself. If the user has per-user MFA on as well as Conditional Access MFA, the page says so: per-user MFA ignores Conditional Access exclusions such as trusted locations.
* **Flags** for lockout, legacy authentication (IMAP, POP, SMTP AUTH, ActiveSync, "other clients"), risk-based blocks, security defaults, report-only policies that would have failed, and a missing device identity.
* **Followed by a success**: an MFA prompt or a typo followed by a successful sign-in with the same correlation ID is marked as resolved, so it does not distract from the real problem.

Above the sign-ins, a summary line gives the diagnosis, the account state (enabled, per-user MFA, security defaults, synced) and counts. When there were wrong-password or lockout events, a second line says how many, from how many IP addresses and countries, and whether it looks like someone else guessing the password rather than the user. CIPP does not recommend a password reset just because a password is being guessed.

## Error codes CIPP explains

Wrong password (50126), smart lockout (50053), disabled account (50057), expired password (50055, 50144), no password (50056), sessions ended by a password change (50133, 50132, 50173), account not in tenant (50034, 51004, 50020, 16000, 90072), MFA required, prompted, failed or expired (50076, 50074, 500121, 50078, 50158), MFA registration (50079, 50072, 53004, 53010), Conditional Access block (53003), device not compliant / not hybrid joined / not an approved app (53000, 53001, 53002, 50005, 50155, 50097, 50127, 50129), tenant security policy (530032), security defaults (530035), risk (50142, 50135, 53011, 530034), app assignment and consent (50105, 65001, 90095, 700016, 7000112, 7000218, 50011, 50196), and the normal prompts (50140, 50199, 50125, 50058, 81010, 50089, 70043, 9002341). Any other code shows Microsoft's reason and a link to Microsoft's error lookup.

## Microsoft's Sign-in Diagnostic

Microsoft does not publish a direct link to the Sign-in Diagnostic for one sign-in. Each card shows the correlation ID and request ID: in the Entra admin center go to **Diagnose and solve problems > Sign-in diagnostic > Troubleshoot** and search for it. The card also links the user's sign-in log in Entra and Microsoft's error lookup page.

## Copy summary and ConnectWise

**Copy summary** puts a short Markdown write-up on the clipboard. **Post to a ConnectWise ticket** shows a preview first; **Post as internal note** adds it to the ticket's Internal Analysis tab with ConnectWise notifications off, so the client is not emailed. CIPP refuses to post when the tenant has no ConnectWise company mapping, or when the ticket belongs to a different company. Posting needs the Identity.User.ReadWrite permission.

{% hint style="info" %}
Sign-in logs need an Entra ID P1 licence in the tenant. Without it the page says so and shows only the account state; ask the user for the error screen, which shows the AADSTS code and a correlation ID. Sign-in logs are kept for 30 days.
{% endhint %}

By default only interactive sign-ins are read. Turn on **Include non-interactive sign-ins** for apps that sign in in the background (Outlook, Teams and OneDrive refreshing their tokens). The page explains the newest 25 failed or interrupted sign-ins in full and counts the rest by error code.

Aspendora fork addition (Vikunja CIPP-10). Endpoints: `/api/ListSignInExplanation?tenantFilter=<tenant>&userPrincipalName=<upn>&hours=24` (or `&correlationId=<guid>`, optional `&includeNonInteractive=true&maxResults=25`) and `POST /api/ExecSignInExplanationNote` with `tenantFilter`, `TicketId`, `Bundle` and `Preview` (true by default).
