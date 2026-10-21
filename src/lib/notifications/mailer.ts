/**
 * SMTP email moved to Forensicator Enterprise along with critical-finding
 * alerting (see critical-finding-alert.ts). The Enterprise overlay replaces
 * this file with the real nodemailer-backed implementation.
 *
 * Kept as an inert stub rather than deleted: Core updates and overlay
 * applies are a flat `tar -xzf` over the install, so a deleted path would
 * leave an older copy — which imports nodemailer, no longer a Core
 * dependency — on already-installed appliances and break their next build.
 */
export {};
