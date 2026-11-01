# Personal Devices

Lists the devices enrolled in Intune as **personally owned** (owner type `personal`) and shows the two settings that stop new ones. The page is read only.

A single tenant is read live. **All tenants** is read from the CIPP reporting cache (managed devices, enrollment configurations and the MDM policy), so a device enrolled after the last cache run does not show yet.

## Columns

| Column            | Meaning                                                                                                                         |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Enrollment type   | How the device enrolled, for example *Windows automatic enrollment (work account added)*, *User enrollment (Company Portal or Access work or school)*, *Apple User Enrollment*. |
| Join type         | `azureADRegistered` (Entra registered: a personal device with a work account added), `azureADJoined`, `hybridAzureADJoined`.   |
| Via work account  | A Windows device that is Entra registered. It was most likely enrolled when the user added a work account under **Settings > Accounts > Access work or school** and accepted "Allow my organization to manage my device". |
| Is new            | Enrolled in the last 30 days (`newDays`).                                                                                       |

## BYOD controls

For a single tenant the second row of tiles shows:

* **Personal Windows enrollment.** `personalDeviceEnrollmentBlocked` on the default platform restriction ("All users and all devices"). Set it with the **DefaultPlatformRestrictions** standard. Group-assigned restrictions with a higher priority can override it for their members; the page does not evaluate them.
* **MDM enrollment when adding a work or school account.** Intune: **Devices > Windows > Enrollment > Automatic Enrollment > Disable MDM enrollment when adding work or school account on Windows**. In Graph this is `isMdmEnrollmentDuringRegistrationDisabled` on beta `policies/mobileDeviceManagementPolicies/0000000a-0000-0000-c000-000000000000`. Set it with the **MDMEnrollmentDuringRegistration** standard ("Configure MDM enrollment when adding work or school account", switch on).
* **Personal iOS / Android work profile enrollment** and the **MDM user scope** (`appliesTo`: all, selected, none).

With all tenants selected, the same values are columns of the per-tenant summary table. **Unknown** means the value could not be read (no Intune licence, a missing permission, or not cached yet).

{% hint style="warning" %}
**What users notice when MDM enrollment during registration is disabled.** A user who adds a work account to a personal Windows PC gets the device Entra registered only, not enrolled. Single sign-on to Office and Teams keeps working, but Intune does not manage or wipe the PC, and Conditional Access that requires a compliant device treats it as unmanaged. Entra join, Autopilot, Company Portal enrollment and Group Policy auto-enrollment of hybrid joined devices are not affected. With only the platform restriction in place, the same user instead sees an enrollment error after accepting the prompt.
{% endhint %}

## Alert

The **PersonalDevices** alert raises each personally owned device once and clears when the device is retired or changed to corporate. Turn on *Only raise Windows and macOS devices* for tenants that allow personal phones on purpose. A weekly interval is enough.

Aspendora fork addition (Vikunja CIPP-21). Endpoint: `/api/ListPersonalDevices?tenantFilter=<tenant or AllTenants>&newDays=30`.
