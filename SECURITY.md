# Security Policy

Forensicator Core handles forensic evidence and incident-response data — a
vulnerability here can mean tampered evidence, a broken chain of custody, or
exposure of sensitive case data. We take security issues in this codebase
seriously.

## Supported Versions

Security fixes are provided for the latest released version of Forensicator
Core and Forensicator Enterprise. Older releases are not patched — please
upgrade before reporting an issue that may already be fixed.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately:

* Email **hello@raptormatics.com**
* Or use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) feature on this repository, if enabled

Please include:

* Steps to reproduce, or a proof-of-concept
* The potential impact as you see it (e.g., authentication bypass, data exposure, evidence tampering)
* The deployment mode you tested against (Docker or bare-metal/appliance) and version

We aim to acknowledge reports within **5 business days** and to provide a
remediation timeline once the issue is confirmed. We'll credit reporters in
the fix's release notes unless you ask us not to.

## Scope

**In scope** — vulnerabilities in Forensicator Core's own code, for example:

* Authentication or authorization bypass — session handling, API key
  validation, or role-based access control letting a user see or act on
  data/organizations outside their scope
* Injection — SQL/Prisma, command injection in report generation, or
  path traversal in file upload/evidence handling
* XSS or CSRF in the web UI
* SSRF via user-configurable URLs (threat-intel provider endpoints, webhook
  destinations)
* Secrets or credential exposure — an API key, encryption key, or password
  hash ending up in a log, API response, or report where it shouldn't
* Weaknesses in the signed update mechanism (Ed25519 signature
  verification on `.fpk` packages) that would let an unsigned or tampered
  package install
* A dependency pinned by this project with a known, exploitable
  vulnerability

**Out of scope** — these are not Forensicator vulnerabilities:

* Findings that require an attacker to already hold the level of access
  being tested against (e.g., an already-authenticated `platform_admin`
  doing something only a `platform_admin` can do)
* Issues in third-party dependencies this project uses — please report
  those upstream, though we're happy to hear about them too if they
  affect how we use the dependency
* Missing security hardening that's a deliberate deployment-mode choice
  documented elsewhere (e.g., Docker's update path intentionally not
  using the privileged installer)

## Design Notes for Reviewers

A few things worth knowing if you're auditing this codebase:

* Authentication resolves from either a NextAuth JWT session or a Bearer
  API key (`src/lib/auth/api-guard.ts`) — API keys are stored as bcrypt
  hashes, never in plaintext, and are shown to the user exactly once at
  creation.
* The privileged update installer (`deploy/forensicator-update.sh`) is the
  only script the app's own service account can run as root (via a
  narrowly-scoped sudoers rule) — the app itself never runs as root.
* Every `.fpk` update package is Ed25519-signed; the public key is baked
  into the build (`deploy/update-public-key.pem`), not fetched at
  install time.
* Org-specific secrets at rest (threat-intel provider API keys, etc.) are
  encrypted with a dedicated key (`ENCRYPTION_KEY`, falls back to
  `NEXTAUTH_SECRET` if unset — set a dedicated value in production).
