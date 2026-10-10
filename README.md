<h1 align="center">🛡️ Forensicator Core 🛡️</h1>

<h3 align="center">
Free, Self-Hosted Digital Forensics & Case Management Platform
</h3>

<p align="center">
Upload collected evidence, triage findings, manage cases, and generate reports.
</p>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/user-attachments/assets/22187cf0-5b12-4c44-8644-45405d393109">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/user-attachments/assets/f30b9752-edd4-491f-b466-40d302e5c73c">
  <img alt="Forensicator Logo" src="https://github.com/user-attachments/assets/22187cf0-5b12-4c44-8644-45405d393109" >
</picture>

---

## 🤔 About

**Forensicator Core** is the free, self-hosted edition of Forensicator's case management platform — the server-side counterpart to the [Forensicator collector](https://github.com/Johnng007/Live-Forensicator), where the artifacts it gathers actually get triaged, analyzed, and reported on.

Forensicator Core:

* Ingests collector archives and extracts normalized findings, a timeline, and an attack-path reconstruction
* Groups related investigations, hosts, and findings under Cases
* Builds a cross-investigation Host profile — finding counts, IOC hits, persistence events — every time a hostname shows up again
* Generates executive and technical reports (PDF, CSV, JSON, ZIP)
* Includes AI-assisted finding analysis (Ollama, OpenAI, Anthropic, or any OpenAI-compatible endpoint)
* Ships with a signed, offline-capable update mechanism — online, offline `.fpk` package, or CLI


---

## ⚙️ Quickstart

### 🐳 Docker (recommended for Windows/macOS)

The easiest way to run Core, especially on Windows: [Docker Desktop](https://www.docker.com/products/docker-desktop/) (uses WSL2 under the hood on Windows — Docker Desktop sets that up for you) handles Postgres, Redis, and the app itself as containers, so there's nothing to install on the host beyond Docker.

```bash
git clone https://github.com/Raptormatics/Forensicator-Core forensicator-core
cd forensicator-core
cp .env.docker.example .env
```

Edit `.env` — at minimum, set `NEXTAUTH_SECRET` (generate one with `openssl rand -base64 32`, or any 32+ character random string if you don't have `openssl` handy on Windows).

```bash
docker compose up -d
```

Then open **http://localhost:3000** and complete the setup wizard — that's where you create the first admin account; nothing is seeded automatically.

To stop: `docker compose down` (add `-v` to also delete all data — cases, investigations, everything).

> ⚠️ Note: the in-app "Check for Updates" (Settings → Updates) doesn't apply to the Docker path — there's no `sudo`/systemd inside a container for it to use. To update, pull this repo's latest changes and run `docker compose up -d --build` again.

### 🐧 Bare metal / VM (Linux)

For a real install on a machine you're already logged into — a dedicated box or a VM — skip Docker and provision it directly. Requires a fresh Debian/Ubuntu machine.

```bash
git clone https://github.com/Raptormatics/Forensicator-Core /opt/forensicator-core
cd /opt/forensicator-core
sudo bash ./deploy/provision.sh
```

No reboot needed — `provision.sh` installs Node.js, PostgreSQL, Redis, builds the app, sets up systemd units, then generates secrets, runs migrations, and starts the services itself, right there in the same command. Visit the machine's address in a browser once it prints "Setup complete" and complete the setup wizard.

Optional environment variables for `provision.sh` (see documentation for full list):

```bash
ORG_NAME="Acme Corp" ORG_SLUG=acme PUBLIC_URL="https://forensicator.acme.internal" sudo ./deploy/provision.sh
```

To remove a bare-metal install — services, config, the database (backed up first), the service account:

```bash
sudo ./deploy/uninstall.sh --dry-run   # preview first
sudo ./deploy/uninstall.sh
```

See `sudo ./deploy/uninstall.sh --help` for options (keeping the database, also removing this checkout, etc.). Docker installs don't need this — `docker compose down -v` instead.

---

## 🔍 Key Features

* Case management — organize related investigations, hosts, and findings under a single Case as an incident unfolds
* Investigation analysis — upload a collector archive and get normalized findings, a timeline, and an attack-path reconstruction
* Host intelligence — every host that's had data collected from it, rolled up across every investigation it's ever appeared in
* Executive/technical reporting — PDF, CSV, JSON, ZIP
* AI-assisted analysis — per-finding verdicts from a local (Ollama) or commercial LLM
* REST API with its own API Keys — build integrations without needing Enterprise
* Audit log, role-based access, and a signed update mechanism (online, offline `.fpk`, or CLI) that verifies, backs up, migrates, and auto-rolls-back on a failed health check

---

## 🔄 Updates

Three ways to update an existing install, covered in more detail in-app (Settings → Updates):

* **Online** — if `UPDATE_SERVER_URL` is configured (set by default on bare-metal installs), click "Check for Updates" then "Install Update".
* **Offline** — upload a signed `.fpk` package directly (Settings → Updates → Offline Update). Works fully air-gapped.
* **CLI** — `sudo forensicator update <package.fpk>`, or `sudo forensicator update --rollback <backup-id>` to undo a previous update.

---

## 🧑‍💻 Development - Manual Options

```bash
npm install
cp .env.example .env   # fill in DATABASE_URL at minimum — needs a real local Postgres
npm run prisma:generate
npm run prisma:migrate
npm run dev
```

| Script | What it does |
|---|---|
| `npm run dev` | Next.js dev server with hot reload |
| `npm run build` | Production build |
| `npm run workers` | Runs the background job worker (reports, AI analysis) standalone |
| `npm run prisma:generate` | Regenerate the Prisma client after a schema change |
| `npm run prisma:migrate` | Create and apply a new migration (dev only) |
| `npm run prisma:deploy` | Apply existing migrations (production) |
| `npm run seed-admin` | Seed a first admin user directly, bypassing the /setup wizard — local dev only |
| `npm run lint` | Lint the codebase |

**Stack**: Next.js 15 (App Router), PostgreSQL via Prisma, Redis + BullMQ for background jobs.

---

## 🤝 Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for repo layout and testing/PR guidelines. The short version:

* Open an issue to discuss major changes
* Submit pull requests with clear descriptions
* Focus on accuracy, clarity, and usability

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). Found a security vulnerability? Please report it privately — see [SECURITY.md](SECURITY.md) rather than opening a public issue.

---

## 📄 License

Forensicator Core is open-source software licensed under the **Apache License 2.0**.

Copyright © 2026 [Raptormatics LLC](https://raptormatics.com).

You are free to use, reproduce, modify, and distribute Forensicator Core in accordance with the terms of the Apache License 2.0.

See the [`LICENSE`](LICENSE) file for the full license text.

### Third-Party Components

Forensicator Core may include or interact with third-party tools, libraries, or components that are distributed under their own licenses. Those licenses remain applicable to their respective components.

---

## ☕ Documentation

<a href="https://docs.forensicator.io">docs.forensicator.io</a>
