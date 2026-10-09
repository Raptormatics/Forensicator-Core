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
