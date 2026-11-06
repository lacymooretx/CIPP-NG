# What's New (Aspendora)

Our own changelog for features this fork adds on top of upstream CyberDrain CIPP. Upstream changes keep showing in the upstream release notes dialog; ours show at **CIPP > What's New (Aspendora)** (`/cipp/whats-new`) and in the account menu, which shows a green dot until the operator has seen the newest entry.

## Rule
Every user-visible fork feature or behaviour change gets an entry **in the same commit or PR**. Bug fixes don't need one unless an operator would notice the change.

## How to add an entry
Edit `frontend/src/data/aspendora-whats-new.json` and add an object at the **top** of `entries` (newest first):

```json
{
  "id": "short-kebab-id",
  "date": "YYYY-MM-DD",
  "title": "Plain name of the feature",
  "area": "Identity",
  "summary": "One to three sentences: what it does for the operator.",
  "path": "/where/it/lives",
  "ref": "CIPP-123"
}
```

- `date` is the day it went live (US Central).
- `area` must be one of the `areas` in the same file.
- `path` and `ref` are optional. A `path` must be a real page; the test checks.
- No secrets, tenant names or customer data.

## Checks
- `frontend/tests/lint/aspendora-whats-new.test.js`: schema, unique ids, newest-first order and that each `path` has a page.
- `frontend/tests/pages/aspendora-whats-new.test.jsx`: the page renders every entry and records the visit.
- `.github/workflows/aspendora-whats-new.yml` runs both on pushes and PRs to `aspendora`, and warns (never fails) when a push adds a page or HTTP entrypoint without touching the JSON. Upstream syncs are skipped.

Run locally (node 22):
```
cd frontend && npx vitest run --project unit tests/lint/aspendora-whats-new.test.js tests/pages/aspendora-whats-new.test.jsx
```

## Files
- `frontend/src/data/aspendora-whats-new.json` (content)
- `frontend/src/pages/cipp/whats-new.jsx` (page)
- `frontend/src/utils/aspendora-whats-new.js` (seen-date helpers, localStorage key `aspendora_whats_new_seen`)
- `frontend/src/layouts/account-popover.jsx`, `frontend/src/layouts/config.jsx` (menu entries, marked "Aspendora fork")
