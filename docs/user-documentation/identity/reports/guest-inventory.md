# Guest Inventory

Lists every guest in the selected tenant and recommends what to do with each one. The page reads the tenant live and changes nothing on its own. The only writes are the **Disable Guest** and **Delete Guest** row actions, which ask for confirmation and can be applied to several selected guests at once.

For a client-facing PDF of the same data, run the **Guest Access Review** report from **Tools > Reports**.

## Recommended action

The first rule that matches wins.

| Action  | When                                                                                                                                   |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| REMOVE  | The invitation has not been redeemed for 30 days or more (measured from the latest invitation, so a re-sent invite restarts the clock), or the guest is already disabled and has not signed in for 90 days. |
| DISABLE | The guest redeemed the invitation but has not signed in for 90 days, or redeemed it and never signed in more than 90 days after creation. |
| REVIEW  | A personal account (personal Microsoft account, Google, Facebook, or a consumer email domain such as gmail.com), the user who invited the guest is now disabled, or sign-in activity is unavailable. |
| KEEP    | Everything else.                                                                                                                       |

The **Reasons** column lists every rule that applied, so a guest recommended for DISABLE can also show that it is a personal account.

## Columns

| Column        | Meaning                                                                                                                         |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Account type  | How the guest signs in: work or school (Entra), personal Microsoft account, email one-time passcode, Google, Facebook, or "not redeemed yet". |
| Invited by    | The user who sent the invitation or shared the file. A guest SharePoint or OneDrive created through the Entra B2B integration shows the person who shared, so the page cannot tell those apart from an Entra invitation. "None recorded" means an admin, an app or an older process created the guest. |
| Inviter state | Active, Disabled, None recorded, or Unknown (the lookup failed).                                                                |
| Teams, groups | The guest's Microsoft Teams and other group memberships.                                                                        |

## Tenant settings

The second row of tiles shows the settings that decide how guests are created:

* **SharePoint/OneDrive Entra B2B integration.** On means people shared with from SharePoint or OneDrive become Entra guests, so Conditional Access and this inventory cover them. CIS 7.2.2 recommends On.
* **SharePoint external sharing level.**
* **Who can invite guests.** "everyone" includes other guests and is highlighted.

{% hint style="info" %}
Sign-in activity needs an Entra ID P1 licence in the tenant. Without it, no guest is recommended for DISABLE, and older guests are marked REVIEW because their activity is unknown.
{% endhint %}

Aspendora fork addition (Vikunja CIPP-14). Endpoint: `/api/ListGuestInventory?tenantFilter=<tenant>&staleDays=90&pendingDays=30`.
