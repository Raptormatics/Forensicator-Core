import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  serverExternalPackages: ["@prisma/client", "adm-zip", "pdfmake"],
  // Pins the workspace root to this directory. Without it, Next walks up
  // looking for the "real" root and finds the Enterprise repo's own
  // package-lock.json one level up (FORENSICATOR-CORE lives nested inside
  // it during development) — then picks up ITS .eslintrc.json too, which
  // conflicts with this one's own eslint-config-next version.
  outputFileTracingRoot: __dirname,
};

export default nextConfig;
