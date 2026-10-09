/**
 * Uploads a single file to the Cloudflare R2 bucket backing
 * updates.forensicator.io, via R2's S3-compatible API. Uses aws4fetch (a
 * minimal SigV4 signer) rather than the full AWS SDK, since this is only
 * ever used by build-time tooling (scripts/publish-update.sh), never
 * shipped in the app itself.
 *
 * Credentials come from ~/.forensicator/r2-credentials.env if present
 * (never committed — see that file's own comments), or straight from the
 * environment (CI-friendly). If neither is configured, exits with code 2
 * so callers can treat "not configured" as a skip, not a hard failure.
 *
 * Usage:
 *   npx tsx scripts/upload-to-r2.ts <local-file> <object-key> [content-type]
 */
import fs from "fs";
import os from "os";
import path from "path";
import { AwsClient } from "aws4fetch";

const CREDENTIALS_FILE = path.join(os.homedir(), ".forensicator", "r2-credentials.env");

function loadCredentialsFile(): void {
  if (!fs.existsSync(CREDENTIALS_FILE)) return;
  for (const rawLine of fs.readFileSync(CREDENTIALS_FILE, "utf8").split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (!match) continue;
    const [, key, rawValue] = match;
    const value = rawValue.replace(/^"(.*)"$/, "$1");
    if (!process.env[key]) process.env[key] = value;
  }
}

async function main() {
  loadCredentialsFile();

  const [localFile, objectKey, contentType] = process.argv.slice(2);
  if (!localFile || !objectKey) {
    console.error("Usage: upload-to-r2.ts <local-file> <object-key> [content-type]");
    process.exit(1);
  }

  const { R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET, R2_ENDPOINT } = process.env;
  if (!R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY || !R2_BUCKET || !R2_ENDPOINT) {
    console.error(
      `R2 credentials not configured (expected in ${CREDENTIALS_FILE} or the environment) — skipping upload.`
    );
    process.exit(2);
  }
  if (!fs.existsSync(localFile)) {
    console.error(`No such file: ${localFile}`);
    process.exit(1);
  }

  const client = new AwsClient({
    accessKeyId: R2_ACCESS_KEY_ID,
    secretAccessKey: R2_SECRET_ACCESS_KEY,
    service: "s3",
    region: "auto",
  });

  const body = fs.readFileSync(localFile);
  const url = `${R2_ENDPOINT.replace(/\/+$/, "")}/${R2_BUCKET}/${objectKey}`;

  // latest.json needs to be discoverable quickly after a publish — appliances
  // poll it live on "Check for Updates", so a long edge-cache TTL would mean
  // admins seeing a stale version for a while after a real release. The .fpk
  // itself is content-addressed by version in its filename and never
  // mutates once published, so it's safe to cache aggressively.
  const cacheControl = objectKey.endsWith("/latest.json") || objectKey === "latest.json"
    ? "public, max-age=60, must-revalidate"
    : "public, max-age=31536000, immutable";

  const res = await client.fetch(url, {
    method: "PUT",
    body,
    headers: {
      "content-type": contentType || "application/octet-stream",
      "cache-control": cacheControl,
    },
  });

  if (!res.ok) {
    console.error(`Upload failed: HTTP ${res.status} ${await res.text()}`);
    process.exit(1);
  }

  console.log(`Uploaded ${localFile} -> ${objectKey}`);
}

main();
