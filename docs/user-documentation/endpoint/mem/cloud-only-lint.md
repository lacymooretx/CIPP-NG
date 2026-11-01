# Cloud-only Lint

Flags Intune settings that misbehave, or do nothing, on Microsoft Entra joined (cloud-only) devices and Entra ID users. The best-known example is **Display information about previous logons during user logon**. On a cloud-only device, Entra ID users see a "Windows couldn't retrieve information about previous logons" message at every sign-in. The page is read-only and changes nothing.

It runs in two modes:

* **Tenant**: lints every Settings Catalog policy (endpoint security policies included), custom OMA-URI profile and Administrative Template in the selected tenant.
* **Template**: lints one saved Intune template. Open it from **Policy Templates** with the **Cloud-only Lint** row action. The Policy Templates list also has a **cloudOnlyWarnings** column that shows the same result for every template. That column is only a warning: it does not block saving or deploying.

## Columns

| Column      | Meaning |
| ----------- | ------- |
| Severity    | High: users see errors or a feature silently fails. Low: wasted effort, such as a slower sign-in. Info: the setting has no effect. |
| Relevance   | **Applies**: the tenant has devices the setting misbehaves on. **Not applicable**: every Windows device is hybrid joined or registered. **Check**: the tenant syncs from on-premises AD, so the setting may be intentional. **Unknown**: template mode with no tenant, or the device list could not be read. |
| Settings    | The matching setting and its value. In a nested Settings Catalog setting the parent and its children are checked. An encrypted OMA-URI value is matched on its URI only, and **ValueVerified** is No. |
| Symptom, Alternative, Source | What users see, what to use instead, and the Microsoft Learn page the rule is based on. **Why** is in the row details. |

The tiles show how many Windows devices are Entra joined (cloud-only), hybrid joined and registered, and whether the tenant syncs from on-premises Active Directory.

## Rules

The rules live in `backend/Config/IntuneCloudOnlyLintRules.json`. Every rule has a Microsoft Learn source.

| Rule | Setting | Severity |
| ---- | ------- | -------- |
| CLOUDONLY-001 | Display information about previous logons during user logon (ADMX_WinLogon/DisplayLastLogonInfoDescription) enabled | High |
| CLOUDONLY-002 | Windows LAPS Backup Directory = Active Directory | High |
| CLOUDONLY-003 | Windows LAPS settings that only apply to AD backup (AD password encryption, encrypted history, password expiration protection) | Info |
| CLOUDONLY-004 | Always wait for the network at computer startup and logon | Low |
| CLOUDONLY-005 | Net Logon domain controller locator settings (only when there is no on-premises AD) | Info |
| CLOUDONLY-006 | Cloud Kerberos trust / cloud Kerberos ticket retrieval (only when there is no on-premises AD) | Info |
| CLOUDONLY-007 | Windows Hello for Business certificate trust (only when there is no on-premises AD) | Low |

{% hint style="info" %}
For sign-in history on cloud-only devices, use the Entra sign-in logs (Entra admin center > Monitoring > Sign-in logs, or a user's sign-in logs in CIPP) instead of the last-logon message.
{% endhint %}

To add a rule, add an entry to the JSON file with the setting's `settingDefinitionId` (Settings Catalog), its OMA-URI and its Administrative Template definition, plus the symptom, why, alternative and a source URL. The fields are described in the file's `_comment`.

Aspendora fork addition (Vikunja CIPP-28). Endpoint: `/api/ListIntuneCloudOnlyLint?tenantFilter=<tenant>` or `/api/ListIntuneCloudOnlyLint?templateId=<GUID>[&tenantFilter=<tenant>]`.
