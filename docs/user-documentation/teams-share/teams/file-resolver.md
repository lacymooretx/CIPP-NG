# Teams File Resolver

Finds where a Teams file is really stored, who it is shared with, and why a particular user cannot open it. Most "I can't open the Teams file" tickets get treated as a team-membership problem, but where the file is stored decides who can open it:

| Where the file was shared  | Where it is stored                                                   | Who gets access                                                                                       |
| -------------------------- | -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| 1:1 or group chat          | The **sender's** OneDrive, folder *Microsoft Teams Chat Files*       | Only the people who were in the chat when the file was sent (a people-specific link). Joining the chat later, or being in the same team, gives no access. |
| Standard channel           | The team's SharePoint site, in a folder named after the channel      | Team members, through the site's Members group, unless the file or a folder has its own permissions. |
| Private channel            | A separate SharePoint site for the channel                           | Channel members only. Team members do not get access.                                                 |
| Shared channel             | A separate SharePoint site for the channel                           | Channel members, members of teams the channel is shared with, and people in other organisations through B2B direct connect. |

The page changes nothing. The suggested fix is advice and a link to the CIPP page that applies it.

## Using it

1. Pick a single tenant.
2. Paste the file link. Any of these work:
   * the Teams link (in Teams: the file's **...** menu > **Copy link**),
   * a SharePoint or OneDrive sharing link,
   * the address from the browser when the file is open.
3. Optionally pick the user who cannot open it. Without a user the page shows where the file lives and its permissions; with one it also checks whether that user is covered and suggests the smallest fix.
4. Click **Resolve**.

No link? Leave the link empty and search by **user** and **file name**. The page searches that user's *Microsoft Teams Chat Files* folder and the libraries of the first 25 teams they are in, and lists up to 25 matches. Click **Resolve** on the right one. For a chat file, search as the person who **sent** it: the file is in their OneDrive, not the recipient's.

## What the result shows

* **Most likely cause and smallest fix**, with a button to the CIPP page that applies it.
* **Location**: OneDrive (chat file), team site, private channel site, shared channel site, or a plain SharePoint site. Also the path, owner, team and channel, and the site and library links.
* **The user**: access yes / no / unknown and what covers them (a sharing link, a direct grant, a group, or the site's Members group), plus team and channel membership.
* **Channel membership** (private and shared channels): member count, the teams a shared channel is shared with, and members from other tenants with this tenant's B2B direct connect inbound setting for each of their tenants.
* **Permissions on the file**: every grant and sharing link with its scope, type and expiry. Sharing-link URLs are never shown, because an "anyone" link works like a password.

## Causes and fixes

| Cause                     | Smallest fix                                                                                                        | CIPP page                    |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| Chat file not shared with the user | The sender shares the file with them (Share > specific people). If the sender is gone, give someone access to the sender's OneDrive and share it from there. | Teams & SharePoint > OneDrive |
| Sender disabled or deleted | Give a manager access to the OneDrive and move the file before retention removes it.                               | Teams & SharePoint > OneDrive |
| Not a team member (standard channel) | Add them to the team.                                                                                    | Edit group (team members)    |
| Team member but not covered | The file or a folder has its own permissions. Grant access on the site, or restore inheritance.                  | Teams & SharePoint > SharePoint |
| Not in the private channel | A channel owner adds them (Teams: channel > **...** > **Manage channel** > **Members**). Team membership is not enough. | None (done in Teams)        |
| Not in the shared channel | A channel owner adds them, or shares the channel with a team they are in.                                        | None (done in Teams)         |
| External user, shared channel | B2B direct connect must be allowed inbound here and outbound in their home tenant, then a channel owner adds them. | None                       |
| User already has access   | The block is not permissions. Check the account they are signed in with, Conditional Access and unmanaged-device policies. | Identity > Reports > Sign-in Failure Explainer |
| Link does not resolve     | The file was deleted or moved, the link was removed or expired, or the file belongs to another organisation.         | None                         |

## Limits

* Single tenant. A file in another organisation cannot be read; the page says so.
* The chat folder is found by its English name, *Microsoft Teams Chat Files*. In tenants where OneDrive uses another language, paste the link instead of searching.
* Search covers the user's chat folder and the main library of their first 25 teams. Private and shared channel sites are not searched; paste the link.
* A standard channel is matched by its folder name. A renamed channel keeps its old folder name, so the channel may show as unmatched.
* An "organisation" sharing link counts as access for internal users, but only if they open the file through that link.

Aspendora fork addition (Vikunja CIPP-33). Endpoint: `/api/ListTeamsFileResolution?tenantFilter=<tenant>&url=<link>&affectedUser=<upn>`, or `&userPrincipalName=<upn>&fileName=<name>` to search.
