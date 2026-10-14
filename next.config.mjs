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
  experimental: {
    // Next.js clones+caps every request body that passes through
    // middleware (src/middleware.ts, matched on every non-static path —
    // this is the global auth gate, so that's every upload route) at a
    // default of 10MB, REGARDLESS of whether middleware itself reads the
    // body — confirmed directly in node_modules/next/dist/server/
    // body-streams.js: cloneBodyStream() tees the raw request stream,
    // and the SAME truncated copy gets swapped in as the body the route
    // handler itself receives. This silently truncated every
    // PCAP/Windows-Artifact upload over 10MB (both use req.formData()),
    // which fails with "TypeError: Failed to parse body as FormData" /
    // "expected boundary after body" once the multipart body is cut off
    // mid-stream — and would equally truncate RAM Analysis's busboy-based
    // streaming upload past the same 10MB mark, since the cap applies to
    // the underlying stream itself, not just formData()'s own parsing.
    // 600mb covers PCAP's and Windows Artifact Analysis's own 500MB caps
    // with headroom for multipart overhead. This does NOT cover RAM
    // Analysis images larger than 600MB — those still get silently
    // truncated by this same mechanism; raising this further trades
    // directly against server memory (Next buffers up to this much per
    // concurrent upload in memory, which is exactly what RAM's own
    // busboy-streaming design was trying to avoid in the first place).
    middlewareClientMaxBodySize: "600mb",
  },
};

export default nextConfig;
