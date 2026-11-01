# Driver Updates

Lists the Windows driver and firmware updates waiting for a decision in each tenant's Windows driver update profiles, for the selected tenant or across all tenants. By default only drivers with the status **needsReview** are shown; switch to **All** to see approved, declined and suspended drivers too.

{% hint style="info" %}
Driver update management needs Windows Enterprise E3/E5 or Microsoft 365 Business Premium (or equivalent) rights, and devices onboarded to the Windows Update for Business deployment service, which Windows Autopatch does for you. Tenants without it are listed as "without driver management" instead of showing an empty queue.
{% endhint %}

{% hint style="warning" %}
Approve, Decline and Suspend change the tenant. An approved driver starts installing on the applicable devices in the profile's assigned groups. If Multi Admin Approval protects driver updates in a tenant, Intune refuses the action.
{% endhint %}

## Action Buttons

<details>

<summary>Approve</summary>

Approves the driver in its profile with a deployment date of now. The response reads the driver back from Intune and states the status Intune now holds.

</details>

<details>

<summary>Decline</summary>

Declines the driver so it is not offered to devices in that profile.

</details>

<details>

<summary>Suspend</summary>

Suspends a previously approved driver. Devices that have not installed it yet stop receiving it.

</details>

## Table Details

| Column                  | Description                                                                                   |
| ----------------------- | --------------------------------------------------------------------------------------------- |
| Tenant                  | The tenant the driver update profile belongs to.                                              |
| Name                    | The driver name as Windows Update publishes it.                                               |
| Manufacturer            | The driver publisher.                                                                         |
| Driver Class            | The hardware class, for example Networking, Video, Firmware.                                  |
| Version                 | The driver version.                                                                           |
| Applicable Device Count | How many devices in the profile's groups the driver applies to.                               |
| Approval Status         | needsReview, approved, declined or suspended.                                                 |
| Profile Name            | The driver update profile. Profiles named "Windows Autopatch Driver Update Policy" are managed by Autopatch. |
| Approval Type           | automatic (recommended drivers are approved after the deferral) or manual.                    |
| Release Date            | When Microsoft released the driver.                                                           |

## Related

* The **Standardize the Windows driver and firmware update profile** standard (DriverUpdateProfile) keeps a driver update profile with a consistent approval type and deferral in every tenant.
* The **DriverUpdatesBlocked** alert flags update rings and Settings Catalog policies that block Windows Update drivers, which stops any driver profile from working.
