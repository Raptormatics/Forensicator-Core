<h1 align="center">🛡️ Forensicator Core 🛡️</h1>

<h3 align="center">
Free, Self-Hosted Digital Forensics & Incident Response (DFIR) Platform
</h3>

<p align="center">
Ingest evidence from memory, disk, network, Windows artifacts, and logs. Enrich it against threat intelligence, correlate it across hosts and cases, and report on it — all from one self-hosted app.
</p>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/user-attachments/assets/22187cf0-5b12-4c44-8644-45405d393109">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/user-attachments/assets/f30b9752-edd4-491f-b466-40d302e5c73c">
  <img alt="Forensicator Logo" src="https://github.com/user-attachments/assets/22187cf0-5b12-4c44-8644-45405d393109" >
</picture>

---

## 🤔 About

**Forensicator Core** is the free, self-hosted edition of Forensicator — a full DFIR (Digital Forensics & Incident Response) platform, not just a case tracker. It's the server-side counterpart to the [Forensicator collector](https://github.com/Johnng007/Live-Forensicator): the collector gathers evidence from a live host, Core is where that evidence actually gets parsed, analyzed, enriched, correlated, and reported on.

Forensicator Core:

* Parses RAM dumps, PCAPs, raw log files, and Windows forensic artifacts (registry hives, Prefetch, $MFT, SRUM, Defender quarantine, and more) into structured, searchable findings — see Key Features below
* Enriches indicators automatically against VirusTotal, AbuseIPDB, OTX, URLhaus, ThreatFox, and MalwareBazaar
* Groups related investigations, hosts, and findings under Cases, with built-in incident-response playbooks
* Builds a cross-investigation Host profile — finding counts, IOC hits, persistence events — every time a hostname shows up again
* Correlates findings across uploads into a single narrative and relationship graph per case
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

No reboot needed — `provision.sh` installs Node.js, PostgreSQL, Redis, `tshark` (for PCAP Analysis), builds the app, sets up systemd units, then generates secrets, runs migrations, and starts the services itself, right there in the same command. Visit the machine's address in a browser once it prints "Setup complete" and complete the setup wizard.

Optional environment variables for `provision.sh`:

| Variable | Default | Purpose |
|---|---|---|
| `ORG_NAME` | `Default Organization` | Seeded organization name |
| `ORG_SLUG` | `default` | Seeded organization slug |
| `PUBLIC_URL` | `http://localhost:3000` | Externally reachable URL, used as `NEXTAUTH_URL` |
| `APP_PORT` | `3000` | Port `next start` binds to |
| `SERVICE_USER` | `forensicator` | System account the app runs as |
| `UPDATE_SERVER_URL` | `https://updates.forensicator.io/core` | Where "Check for Updates" queries. Set to an empty string to disable online update checks entirely (e.g. air-gapped installs) — offline/CLI `.fpk` installs work regardless of this setting |

```bash
ORG_NAME="Acme Corp" ORG_SLUG=acme PUBLIC_URL="https://forensicator.acme.internal" sudo ./deploy/provision.sh
```

To remove a bare-metal install — services, config, the database (backed up first), the service account:

```bash
sudo ./deploy/uninstall.sh --dry-run   # preview first
sudo ./deploy/uninstall.sh
```

`uninstall.sh` leaves PostgreSQL/Redis/Node.js themselves, any swapfile `provision.sh` added, and this checkout's own files alone by default — pass `--purge-packages`, `--remove-swap`, or `--remove-app-dir` respectively to also remove those. `--keep-data` leaves the database and its role untouched (e.g. if you plan to point a fresh install at it later); `--no-backup` skips the pre-removal `pg_dump`. See `sudo ./deploy/uninstall.sh --help` for the full list. Docker installs don't need this — `docker compose down -v` instead.

---

## 🔍 Key Features

### Case & Investigation Management

* **Cases** — organize related investigations, hosts, and findings under a single Case as an incident unfolds, with a human-readable case number
* **Investigations** — upload a collector archive and get normalized findings, a timeline, and an attack-path reconstruction
* **Built-in playbooks** — select an incident type on a case to apply a bundled response playbook
* **Notes & bookmarks** — per-investigation/finding/evidence notes, and personal bookmarks for anything you want to get back to quickly
* **Known-hash allowlisting** — link an NSRL-style known-good hash set to a case to cut down on noise

### Analysis Engines

Each of the following is its own upload type with independent background processing, a detail page with per-artifact-type tabs, and its own no-code detection-rule builder:

* **RAM Analysis** — Volatility3-based memory image analysis (processes, network connections, malfind/injection detection, and more)
* **PCAP Analysis** — network capture analysis: conversations, DNS queries, extracted IOCs
* **Log Analysis** — upload any raw log file (including raw `.evtx`, UTF-16 and `.gz` logs), pick a built-in or custom decoder, and get normalized events, extracted IOCs, and detection-rule matches. Built-in Windows decoders cover Security, Sysmon, PowerShell, Defender, Task Scheduler, WMI-Activity, BITS-Client, RDP (RCM/LSM), Directory Service, DFS Replication and DNS Server channels, plus Tomcat Catalina logs Linux decoders cover syslog in both the traditional and the RFC 3339 timestamp format (current Ubuntu/Debian, `journalctl -o short-iso`), auth.log/secure (SSH, sudo, user management), auditd, and dpkg/apt history.
* **Host Artifacts (Windows)** — upload the collector's host folder in one step (**Collector folder** mode routes every file by its path and verifies each one's SHA-256 against the collector's CollectionManifest), or individual artifacts: registry hives + transaction logs (SYSTEM, SOFTWARE, SECURITY, SAM, DEFAULT, Amcache, NTUSER/UsrClass, plus RegBack/Windows.old/restore-point copies), every regipy plugin result (SAM accounts and group membership, LSA secret names, cached domain logons, installed programs, IFEO, WDigest/LSA configuration, ...), Prefetch, LNK/Jump Lists/Shellbags, $MFT/$UsnJrnl (any volume)/$LogFile/SRUM, Windows Search (ESE and Windows 11 SQLite), Defender quarantine/DetectionHistory/Support logs, WER, Recycle Bin ($I and $R), Notifications, BITS (qmgr*.dat and qmgr.db, including carved deleted jobs), Windows Timeline, WMI permanent subscriptions and repository, application artifacts (remote-access tool logs, Notepad/Notepad++ unsaved text, cloud-sync and EDR logs), pagefile/swapfile/hiberfil indicator sweeps, and LOG4J/GPResult/RAM-triage extras — paired with the [Forensicator collector](https://github.com/Johnng007/Live-Forensicator)'s `-WINARTIFACTS` flag
* **Host Artifacts (Linux)** — upload the Linux collector's `-A` folder the same way (hashes verified against its CollectionManifest): accounts, shadow and groups, sudoers, PAM, login records (wtmp/btmp/utmp), every user's shell and application histories, SSH authorized_keys and known_hosts, cron/at jobs, systemd units and drop-ins, shell startup files, ld.so.preload, module/udev/sysctl/APT hooks, the process table (with deleted executables recovered from `/proc`), sockets, packages, containers, eBPF programs and a filesystem timeline (bodyfile) — each parsed into searchable records, flagged, and checked by built-in Linux detection rules (UID-0 backdoors, reverse shells, download-and-execute, log clearing, PAM backdoors, processes running from deleted or temp binaries, SUID files in temp dirs, ...). The collection's logs (auth, syslog, audit, journal, dpkg/apt, web server) go to Log Analysis in the same case
* **Host Artifacts (macOS)** — upload the macOS collector's `-A` folder the same way: Directory Services account records (UID-0 and hidden accounts, creation and password-change times), sudoers and the login authorization mechanisms, LaunchAgents/LaunchDaemons with what they run, login and background items (Background Task Management), the code signature of every running executable and launch item program, TCC privacy grants, downloads (quarantine events), KnowledgeC app usage, install history, XProtect behavioural detections, security settings (SIP, Gatekeeper, FileVault, firewall, remote access), FSEvents, every user's shell and Terminal session histories, SSH files, cron/at, startup files, sockets, proxy settings and a filesystem timeline with birth times — SQLite databases read together with their `-wal` files — checked by built-in macOS detection rules (login hooks, DYLD injection, fake password prompts, quarantine removal, unsigned persistence, non-Apple authorization plugins, sensitive TCC grants to bare binaries, ...). Its unified log exports and install log go to Log Analysis in the same case

### Threat Intelligence

* Automatic IOC enrichment against **VirusTotal**, **AbuseIPDB**, **OTX AlienVault**, **URLhaus**, **ThreatFox**, and **MalwareBazaar** — bring your own API keys for the ones that need them; URLhaus and MalwareBazaar also offer a free, keyless bulk-feed cache you can sync on demand
* **Host Intelligence** — every host that's had data collected from it, rolled up across every investigation it's ever appeared in
* **Correlation** — cross-upload correlation into a single narrative and relationship graph per case, with an optional AI-generated interpretation on top of the deterministic facts

### Reporting & AI

* Executive and technical reporting — PDF, CSV, JSON, ZIP
* AI-assisted analysis — per-finding verdicts and case correlation narratives from a local (Ollama) or commercial LLM (OpenAI, Anthropic, or any OpenAI-compatible endpoint)

### Platform

* REST API with its own API Keys — build integrations without writing glue code against the UI
* Global search and a severity-ranked dashboard across every case
* Audit log of account and data-changing actions
* A signed update mechanism (online, offline `.fpk`, or CLI) that verifies, backs up, migrates, and auto-rolls-back on a failed health check

---

## 📸 Screenshots

<details>
<summary>Host Artifacts</summary>

<img width="1244" height="507" alt="image" src="https://github.com/user-attachments/assets/472efe06-a3b7-4ce5-b39f-82983cbeda1f" />
<br>
<img width="1112" height="568" alt="image" src="https://github.com/user-attachments/assets/770c8914-e07c-4999-afbe-3b29becb93e3" />
<br>
<img width="1104" height="845" alt="image" src="https://github.com/user-attachments/assets/6c43890b-e407-4507-9f4a-6bb39e00ae38" />
<br>
<img width="980" height="970" alt="image" src="https://github.com/user-attachments/assets/5dc867bf-363b-43d6-8b77-bf10b0209c28" />

</details>

<details>

<summary>Artifact Explorer</summary>

<img width="1759" height="1228" alt="image" src="https://github.com/user-attachments/assets/41198ddf-5bb1-423f-9701-f7270ebd398e" />
<br>
<img width="1235" height="1115" alt="image" src="https://github.com/user-attachments/assets/de3f2987-eedd-4c53-aab6-aec0d4dd226c" />
<br>
<img width="976" height="977" alt="image" src="https://github.com/user-attachments/assets/7c1eea34-0900-43f3-ab10-d04921d1835f" />


</details>

<details>

<summary>Case Management</summary>

<img width="1015" height="1095" alt="image" src="https://github.com/user-attachments/assets/296e5e5a-fcc9-441f-886e-2ed5af69491d" />
<br>
<img width="669" height="765" alt="image" src="https://github.com/user-attachments/assets/11916155-47c4-4d0a-8bc8-8d611510e9f8" />
<br>
<img width="1124" height="905" alt="image" src="https://github.com/user-attachments/assets/7adc591d-50d0-4b60-a6bb-841c7ed51fa9" />
<br>
<img width="2248" height="648" alt="image" src="https://github.com/user-attachments/assets/f70802f6-dfd7-4f46-97b1-7320afc56b66" />

</details>

<details>

<summary>Full Functions</summary>

<img width="227" height="1247" alt="image" src="https://github.com/user-attachments/assets/4360ab7c-9296-4cfc-84b6-7a4a43c5b49b" />

</details>



## 🔄 Updates

Three ways to update an existing install, covered in more detail in-app (Settings → Updates):

* **Online** — if `UPDATE_SERVER_URL` is configured (set by default on bare-metal installs), click "Check for Updates" then "Install Update".
* **Offline** — upload a signed `.fpk` package directly (Settings → Updates → Offline Update). Works fully air-gapped.
* **CLI** — see below.

### CLI (bare-metal only)

`provision.sh` installs a `forensicator` command for admins who prefer console/SSH over the Admin UI:

```bash
forensicator update <package.fpk>                    # install a signed update package
forensicator update <package.fpk> --allow-downgrade   # install even if it's an older version
forensicator update --list-backups                    # list available rollback points
forensicator update --rollback <backup-id>             # undo a previous update
```

Every update is preceded by a database backup; a failed post-update health check triggers an automatic rollback on its own, before you'd even need `--rollback` yourself.

---

## 🩺 Troubleshooting (bare-metal)

| Check | Command |
|---|---|
| Is the app running? | `systemctl status forensicator` |
| Is the background worker running? | `systemctl status forensicator-workers` |
| App logs | `journalctl -u forensicator -f` |
| Worker logs (reports, enrichment) | `journalctl -u forensicator-workers -f` |
| First-boot setup logs (secrets/DB/migrations) | `journalctl -u forensicator-firstboot` |
| Is the app healthy? | `curl http://localhost:3000/api/health` — `{"status":"ok"}` means the app can reach Postgres |
| Restart after a config change | `sudo systemctl restart forensicator` |
| Check Live Update Log | `sudo tail -150 ./backups/update.log` |

Common first issues:

* **Setup wizard never appears / blank page on first visit** — check `journalctl -u forensicator-firstboot` for a failed migration or secret-generation step; `forensicator.service` depends on it and won't start cleanly until it succeeds.
* **"Check for Updates" does nothing** — confirm `UPDATE_SERVER_URL` is set in `/etc/forensicator/forensicator.env` and the box has outbound HTTPS; otherwise use an offline `.fpk` package instead.
* **Running in Docker and `systemctl`/`journalctl` aren't available** — that's expected; use `docker compose logs -f` instead, and see the Docker-specific note under Quickstart above for why the in-app updater doesn't apply there.

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
| `npm run start` | Production build + start (what `forensicator.service` effectively runs) |
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

Forensicator Core is **source-available** software licensed under the **[Business Source License 1.1](LICENSE)** (BUSL-1.1).

Copyright © 2026 [Raptormatics LLC](https://raptormatics.com).

In plain terms:

* You can read, use, self-host, and modify Forensicator Core free of charge — including for your own organization's internal digital forensics and incident response work, even commercially.
* You can't take Forensicator Core (or a modified version of it) and offer it to third parties as a hosted, managed, white-labeled, or otherwise commercially-provided forensics/incident-response product or service without a separate commercial agreement with Raptormatics LLC.
* Every version automatically converts to the permissive **Apache License 2.0** on its stated Change Date (currently **January 1, 2030**) — so this isn't a permanent restriction, just a time-boxed one.

BUSL-1.1 is not an OSI-approved "open source" license (the use restriction above is exactly why), but the source is fully available here, and older versions become genuinely open source automatically over time. See the [`LICENSE`](LICENSE) file for the full, authoritative text — the summary above is for convenience only and isn't a substitute for reading it, or for your own legal advice if you're unsure whether your intended use is covered.

### Third-Party Components

Forensicator Core may include or interact with third-party tools, libraries, or components that are distributed under their own licenses. Those licenses remain applicable to their respective components.

---

## ☕ Documentation

<a href="https://docs.forensicator.io">docs.forensicator.io</a>
