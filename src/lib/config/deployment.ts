/**
 * Deployment mode.
 *
 * Forensicator Core always runs in appliance mode — single organization,
 * seeded on first boot, no organization-creation. Hardcoded (not just
 * defaulted) rather than read from DEPLOYMENT_MODE: Core has no SaaS
 * code path to fall into at all — the multi-tenant "saas" mode (multiple
 * organizations, platform_admin role) is an Enterprise-only capability.
 * The Enterprise overlay replaces this file with the real dual-mode
 * version that reads DEPLOYMENT_MODE from the environment.
 *
 * This mirrors the same fail-open bug class fixed in the Enterprise
 * license-enforcement default (isLicenseEnforced() used to default to
 * "off" unless explicitly enabled) — an env-var-dependent default here
 * would mean a Core instance someone forgot to configure correctly
 * silently allows multi-org creation, a mode it was never built or
 * tested for. Hardcoding removes the footgun entirely rather than just
 * changing which way it fails.
 */
export type DeploymentMode = "appliance";

export function getDeploymentMode(): DeploymentMode {
  return "appliance";
}

export function isAppliance(): boolean {
  return true;
}

/**
 * True when running as the Docker image (baked in via the Dockerfile's
 * own ENV, not left to docker-compose.yml or a .env file to set
 * correctly — this has to be true no matter how the image actually gets
 * run: compose, a bare `docker run`, Kubernetes, whatever).
 *
 * The update mechanism (Settings → Updates) needs this: installing an
 * update means replacing the running app's files and restarting its
 * systemd unit, via `sudo deploy/forensicator-update.sh` — neither sudo
 * nor systemd exist inside this container, so the whole flow is
 * structurally impossible here, not just unconfigured. See
 * src/lib/updates/container-guard.ts.
 */
export function isContainerized(): boolean {
  return process.env.DEPLOYMENT_CONTAINER === "docker";
}
