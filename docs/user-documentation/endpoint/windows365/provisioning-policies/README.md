# Windows 365 — Provisioning Policies

Provisioning policies are the templates Cloud PCs are built from: the image, naming template,
single sign-on setting, join type and the network the Cloud PC lands on.

## Creating a policy provisions nothing

A policy on its own builds no machines and consumes no licences. Cloud PCs are created only when
the policy is **assigned** to a group whose members hold Windows 365 licences. That is a separate
action on purpose — starting to build machines for people should not share a button with "save".

## Join types

- **Microsoft Entra join** — needs a region (Microsoft-hosted network), or one of your own network
  connections if you are bringing your own vNet.
- **Hybrid Entra join** — needs one of your own network connections with line of sight to a domain
  controller. Provisioning fails if that connection's health check is not passing.

CIPP validates this before sending, because Microsoft reports the mismatch only as a schema error.

## Assigning — read this before using Replace

Microsoft's assign API is **replace-mode**: the list you send becomes the *entire* assignment set.

CIPP defaults to **Add**, which keeps the groups already assigned and adds yours. The **Replace**
option discards every group not in your list — sending one group to a policy that already serves
five detaches the other four, and detaching a policy from the group whose users own Cloud PCs is
not a paperwork change. Clearing every assignment requires a further explicit confirmation.

## Not available here

Editing and deleting policies is portal-only for now. Deleting a policy deprovisions the Cloud PCs
built from it, so it belongs behind the same confirmation as the other destructive actions.
