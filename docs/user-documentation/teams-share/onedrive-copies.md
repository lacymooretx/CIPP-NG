# OneDrive Copies

This page tracks OneDrive copies and moves started from a user's page with **Copy or move OneDrive files to another user**. The copy runs inside SharePoint as server-side copy jobs, so version history and metadata come along. The copied files show the copy time as their modified date.

## Starting a copy

* **Copy into the OneDrive of**: the receiving user. Their OneDrive must already exist, so they need to have opened OneDrive at least once.
* **Put the files in**: a new folder "From <name> (date)", or the root of their OneDrive.
* **Copy or move**: Move removes each item from the source after it is copied.
* **If a file or folder with the same name already exists**: keep both (rename the new one), skip it, or replace it.

A check runs first. It stops when the destination is out of space, when the source has more than 1,000 items at its root, or when the destination OneDrive does not exist yet.

## Table Details

| Column             | Description                                           |
| ------------------ | ----------------------------------------------------- |
| Operation          | Copy or Move.                                         |
| Source / Destination User | The two OneDrive owners.                       |
| Destination Folder | The new folder, or the OneDrive root.                 |
| Status             | Progress of the SharePoint copy jobs.                 |
| Files Created      | Files written so far.                                 |
| Errors / Message   | Copy job errors, if any.                              |
