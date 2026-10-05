# Mailbox Copies

This page tracks mailbox copies and moves started from a user's page with **Copy or move mailbox content to another mailbox**. A copy takes mail, calendar items, contacts and tasks from one mailbox and imports them into another in full fidelity. Each item keeps its dates, sender, read state, categories and attachments.

## Starting a copy

On the source user, open the action menu and choose **Copy or move mailbox content to another mailbox**. The options are:

* **Copy into the mailbox of**: the mailbox that receives the items. A shared mailbox works too.
* **Put the items in**:
  * **A new folder "From <name> (date)"**: the source folder tree is recreated under one new folder at the top of the destination mailbox.
  * **Their own folders**: items merge into the destination's own Inbox, Sent Items, Calendar, Contacts and so on. Custom folders are matched by name and created when missing.
* **Folder name**: optional. Replaces the default "From <name> (date)" name.
* **Copy or move**: Move deletes each item from the source once it has been imported. Folders are left in place, empty.
* **Include Deleted Items / Include Junk Email**: both are off by default.
* **Include the online archive**: on by default. Copies the source's online archive as well, if it has one.
* **Put the archive in**:
  * **Their online archive** (default): uses the same layout as above, inside the destination's archive.
  * **An 'Online Archive' folder in their main mailbox**: also used automatically when the destination has no archive. Enable their archive first if you want it to land in the archive.

These folders are never copied: search folders, Sync Issues, Recoverable Items, Outbox and hidden system folders.

{% hint style="warning" %}
A new copy is not de-duplicated: starting the same copy twice imports every item twice. To finish or retry a copy, use **Resume** on its row. Resume skips items that are already in the destination. When you merge into the destination's own folders, the extra copies land beside the user's existing mail.
{% endhint %}

## Table Details

| Column             | Description                                                                       |
| ------------------ | --------------------------------------------------------------------------------- |
| Operation          | Copy or Move.                                                                     |
| Source User        | The mailbox the items come from.                                                  |
| Destination User   | The mailbox that receives them.                                                   |
| Destination Folder | The new folder, or "merged into existing folders".                                |
| Status             | Planning (listing items), Copying, Completed, CompletedWithErrors, Failed or Cancelled. |
| Progress Percent   | Items processed out of items listed.                                              |
| Items Copied / Failed | Running totals.                                                                |
| Archive Items      | How many of the items came from the online archive.                              |
| Archive Destination | Where the archive content went.                                                 |
| Recent Errors      | The last few item-level errors.                                                   |

## Actions

* **Cancel copy**: stops between item groups. Items already copied stay where they are.
* **Resume (copy only what is missing)**: available on a cancelled, failed or partly failed copy.
  * CIPP compares each destination folder with its source folder and copies only the items that are not there yet. The match uses each item's search key, which survives the copy, so nothing is duplicated.
  * Use it to retry failures, or to finish a copy you cancelled.

## Requirements

CIPP's app needs the Graph application permissions MailboxFolder.ReadWrite.All, MailboxItem.ImportExport.All and MailboxItem.ReadWrite.All. Run a CPV refresh on a tenant if a copy fails with an access error.
