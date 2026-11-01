---
description: Review all Conditional Access Policies per tenant
---

# CA Policies

This page lists the Conditional Access policies on the selected tenant, flattened into a single table so you can compare policies at a glance rather than opening each one. CIPP resolves the GUIDs Microsoft stores for users, groups, applications, roles, and named locations into display names, so the table reads as names rather than identifiers.

This page supports the All Tenants view. The first time you select it, CIPP queues a background collection across every tenant and shows a message asking you to check back in a few minutes. Results are cached for an hour, so subsequent loads are immediate.

## Action Buttons

<details>

<summary>Deploy Conditional Access Policy</summary>

Opens the deployment drawer, for pushing a template to a tenant. See [#deploying-a-policy](./#deploying-a-policy "mention") for the available options.

</details>

<details>

<summary>View Logs</summary>

Opens the Conditional Access entries from the CIPP [logs](../../../cipp/logs/ "mention"), covering policies, templates, and deployments.

</details>

### Deploying a Policy

Conditional Access policies reference users, groups, and named locations by GUID, and those GUIDs are tenant-specific. A template built in one tenant will not resolve correctly in another unless the references are translated, which is what most of the options below are for.

| Field                                                     | Description                                                                                                                      |
| --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Tenant                                                    | The tenant to deploy to. Required.                                                                                               |
| Template                                                  | The CA template to deploy, drawn from list-template.                                                                             |
| Conditional Access Parameters                             | The raw policy JSON, populated from the selected template and editable before deployment.                                        |
| How should groups and users be handled?                   | Controls how user and group references are translated. See below.                                                                |
| Policy State                                              | Deploy the policy as enabled, disabled, or report only, or leave the template's own state unchanged.                             |
| Overwrite Existing Policy                                 | Replaces a policy of the same name in the target tenant rather than failing. The policy is returned to the template in full, so anything changed in the tenant since the last deployment, such as an extra excluded group or a platform condition, is removed. |
| Disable Security Defaults if enabled when creating policy | Turns off Security Defaults in the target tenant, which otherwise blocks Conditional Access from taking effect.                  |
| Create groups if they do not exist                        | Creates any group named in the template that is missing from the target tenant. Only available when translating by display name. |

#### Translation modes

| Option                                    | Behaviour                                                                                                                                                                                                                                                                                                                                                    |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Replace by display name                   | CIPP enumerates the target tenant's users and groups and swaps each display name in the template for the matching object's GUID in that tenant. Special tokens such as `All`, `None`, and `GuestOrExternalUsers` are left alone, and GUIDs already present pass through unchanged. This is the option to use for any template that came from another tenant. |
| Remove all exclusions, apply to all users | Strips every user and group include and exclude, scoping the policy to all users. Useful for tenant-wide baseline policies that should not depend on group membership.                                                                                                                                                                                       |
| Leave the groups and users as is          | Deploys the template verbatim, sending the original tenant's GUIDs unchanged. This only works where those exact identifiers already exist in the target tenant.                                                                                                                                                                                              |

{% hint style="info" %}
**Create groups if they do not exist** only applies alongside **Replace by display name**, and is disabled otherwise. Where a CIPP group template exists with the same display name, the group is created from that template, preserving group type and membership rules. Otherwise a basic security group is created. With the option off, a missing group causes the deployment to fail so you can create or rename it yourself first.
{% endhint %}

{% hint style="info" %}
Standards deploy Conditional Access templates using the display-name translation, which is why standards-driven deployments are portable across tenants without any extra configuration. Use a standard rather than this drawer when you want the policy re-applied automatically on drift. A standard reapplies the template the same way an overwrite does, so a policy edited in the tenant is put back the way the template describes it rather than keeping both sets of changes.
{% endhint %}

## Table Details

CIPP flattens each policy's nested conditions into single columns and resolves identifiers to display names, so these columns do not map one-to-one onto the Graph resource.

| Column                  | Description                                                                     |
| ----------------------- | ------------------------------------------------------------------------------- |
| Tenant                  | The tenant the policy belongs to. Most useful in the All Tenants view.          |
| Display Name            | The name of the policy.                                                         |
| State                   | Whether the policy is enabled, disabled, or in report-only mode.                |
| Modified Date Time      | When the policy was last changed.                                               |
| Client App Types        | The client app types the policy applies to, for example browser or mobile apps. |
| Include Platforms       | Device platforms the policy targets.                                            |
| Exclude Platforms       | Device platforms excluded from the policy.                                      |
| Include Locations       | Named locations the policy targets, resolved to their names.                    |
| Exclude Locations       | Named locations excluded from the policy.                                       |
| Include Users           | Users the policy targets, resolved to display names.                            |
| Exclude Users           | Users excluded from the policy.                                                 |
| Include Groups          | Groups the policy targets, resolved to display names.                           |
| Exclude Groups          | Groups excluded from the policy.                                                |
| Include Applications    | Applications the policy targets, resolved to display names.                     |
| Exclude Applications    | Applications excluded from the policy.                                          |
| Grant Controls Operator | Whether the grant controls are combined with AND or OR.                         |
| Built In Controls       | The grant controls the policy requires, for example MFA or a compliant device.  |

{% hint style="info" %}
Where an identifier cannot be resolved, users, roles, and locations fall back to showing the raw GUID. Groups instead show **No Data**, which usually means the group has been deleted while the policy still references it.
{% endhint %}

## Table Actions

<table><thead><tr><th>Action</th><th>Description</th><th data-type="checkbox">Bulk Action Available</th></tr></thead><tbody><tr><td>Edit Policy</td><td>Opens <a data-mention href="edit-ca-policy.md">edit-ca-policy.md</a> for editing.</td><td>false</td></tr><tr><td>View identity coverage</td><td>Opens a drawer that lists every identity this policy's assignment <strong>touches</strong> (include or exclude), with net status (covered or excluded). The table shows a short include/exclude summary per row; open the row for the full why (users, transitive groups, directory roles, guests, special tokens such as All). Row actions open the user in CIPP or in Entra. Does not evaluate apps, locations, or sign-in what-if conditions. When the policy includes all users, that is shown as a flag; individual rows still appear only for concrete assignment touches or exclusions.</td><td>false</td></tr><tr><td>Create template based on policy</td><td>Creates a CIPP template from the policy, making it available to deploy to other tenants. See below.</td><td>false</td></tr><tr><td>Change Display Name</td><td>Renames the policy.</td><td>false</td></tr><tr><td>Run pre-flight</td><td>Aspendora fork. Runs the lockout pre-flight for the policy (see below) and shows the checks, the What-If table and the would-be-blocked report-only sign-ins, with a gated <strong>Enable policy</strong> button.</td><td>false</td></tr><tr><td>Enable Policy</td><td>Sets the policy to enabled once the lockout pre-flight passes (see below). Tick <strong>Override a failed pre-flight</strong> to enable a policy that fails; the override is logged with your name. Greyed out when the policy is already enabled.</td><td>true</td></tr><tr><td>Disable Policy</td><td>Sets the policy to disabled. Greyed out when the policy is already disabled.</td><td>true</td></tr><tr><td>Set policy to report only</td><td>Sets the policy to report only, so it logs what it would have done without enforcing anything. Greyed out when the policy is already in report-only mode.</td><td>true</td></tr><tr><td>Add service provider exception to policy</td><td>Adds an exclusion for your partner tenant's accounts, so the policy cannot lock you out of the customer tenant.</td><td>true</td></tr><tr><td>Delete Policy</td><td>Deletes the policy from the tenant.</td><td>true</td></tr><tr><td>More Info</td><td>Opens the Extended Info flyout with the full details for the selected row.</td><td>false</td></tr></tbody></table>

{% hint style="info" %}
The Extended Info flyout shows the policy's complete raw JSON, including conditions the table does not surface such as sign-in risk, user risk, roles, terms of use, and session controls.
{% endhint %}

## Lockout pre-flight (Aspendora fork, Vikunja CIPP-5)

Before CIPP turns a policy **On** (Enable Policy, saving the editor with state On, or deploying a policy or template with state On), it checks that the change cannot lock the admins out:

| Check | Fails when |
| --- | --- |
| Break-glass accounts excluded | A registered break-glass account (Identity > Break-glass accounts) would be subject to the policy, or none is registered. |
| A Global Admin can still sign in | No Global Administrator other than break-glass is excluded or has a registered method that meets the grant controls (from the authentication methods registration report; per-user methods without Entra ID P1). |
| What-If | You (normally a GDAP service-provider user in the customer tenant) or a break-glass account would be blocked. CIPP evaluates users, groups, roles, external user types and grant controls itself; app, platform, location and risk conditions are assumed to match. |
| Ran in report-only for 7 days | The policy is new, disabled, or has been report-only for less than 7 days. |
| Would-be-blocked sign-ins | A Global Admin or break-glass account had a report-only failure in the window. Other users' would-be failures are a warning, listed for review. |

A failed pre-flight blocks the change and says why. Tick the override to go ahead; CIPP logs the override at Warning with your name. Scheduled standards and drift deploys are never blocked: they log a warning instead.

{% hint style="info" %}
How "report-only for 7 days" is worked out: a policy that is report-only now and whose modifiedDateTime is at least 7 days old has been report-only that long, since every change, a state change included, moves modifiedDateTime. When it changed more recently, CIPP reads the directory audit log (kept 7 days without Entra ID P1, 30 days with it) for the change into report-only. Edits made while in report-only are a warning, since part of the window ran against an older definition.
{% endhint %}

## Template Creation

**Create template based on policy** saves a policy as a reusable template, which then appears in list-template.

Every property of the policy is captured. Inclusions and exclusions are stored in a form CIPP can translate on redeployment, and everything else carries across, including named locations, authentication strengths, and session controls.

{% include "../../../../../.gitbook/includes/feature-request.md" %}
