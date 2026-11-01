# Reports

**Tools > Reports** runs the branded, client-facing report suite for one tenant. Pick a tenant and a report type, then generate it on demand (HTML/PDF) or schedule it. Every type runs through `/api/ExecReport?ReportType=<type>` on demand and through the scheduler command `Push-ExecReport { TenantFilter, ReportType }` on a schedule.

Report types with their own page:

* [Security Posture Change](posture-change.md): month-over-month change in CIPP test results and Secure Score.
