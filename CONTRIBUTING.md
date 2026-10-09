# Contributing to Forensicator Core

Thanks for considering a contribution.

## Before you start

* **Open an issue for anything non-trivial first**, especially a new
  feature, a schema change, or anything touching authentication or the
  update mechanism — it's a much shorter conversation before code is
  written than after.
* Small, focused pull requests are much easier to review than large ones
  that touch several unrelated things.
* Forensicator Core is always single-organization ("appliance mode") —
  changes that assume multi-tenancy belong in a different layer, not here.

## Repository layout

```
src/app/        Next.js App Router — pages and API routes (src/app/api/)
src/components/ Shared UI components
src/lib/        Business logic — auth, cases, hosts, jobs, license,
                reports, settings, updates, upload
src/prisma/     Prisma schema and migrations
scripts/        One-off scripts (seeding, migration helpers)
deploy/         provision.sh, first-boot.sh, the update installer,
                systemd units, Docker config
```

`src/lib/config/deployment.ts` is intentionally hardcoded to appliance
mode — don't "fix" it to read an environment variable; that's deliberate,
not an oversight.

## Testing

* There's no unit-test harness yet — the standard verification is running
  the app locally (`npm run dev`) and checking the feature end-to-end
  against a real Postgres database.
* `npm run lint` and `npm run build` are the minimum bar before opening a
  PR — the build step also runs `tsc` via Next.js's own type-checking.
* Don't claim a fix works against a scenario you couldn't actually verify
  (a specific deployment mode, a specific update path) — say what you
  tested and what you couldn't.

## Coding conventions

* Match the existing style in the file you're editing over introducing a
  new one.
* No new external dependency without a real reason — check `package.json`
  first.
* Comments should explain *why*, not *what* — a non-obvious constraint, a
  workaround for a specific real bug, or a decision that would otherwise
  look wrong at a glance. If the code is self-explanatory, skip the
  comment.
* Never write an actual secret (password, API key, encryption key) to a
  log, API response, or committed file — see `SECURITY.md` for why this
  matters.

## Pull requests

* Reference the issue you opened (or explain the "why" directly in the PR
  description if it's small enough to skip that step).
* Describe what you tested and how, per the Testing section above.
* Focus on accuracy, clarity, and usability.

## Code of Conduct

Participation in this project is governed by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting security issues

Please don't open a public issue for a security vulnerability — see
[SECURITY.md](SECURITY.md) for the private reporting process.
