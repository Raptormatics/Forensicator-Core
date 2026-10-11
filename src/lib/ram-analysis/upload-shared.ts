/**
 * Shared between the legacy single-shot RAM upload route
 * (src/app/api/ram-analysis/uploads/route.ts) and the chunked upload routes
 * (src/app/api/ram-analysis/uploads/chunked/**) so file-type/size validation
 * can't drift between the two.
 */

// Compound extensions (.lime.compressed) aren't representable via
// path.extname(), so extension checks below match by suffix, not by the
// last dot-segment alone.
export const ALLOWED_EXTENSIONS_BY_OS: Record<string, string[]> = {
  windows: [".raw", ".dmp", ".vmem"],
  linux:   [".lime", ".lime.compressed"],
  // AFF4 (.aff4, osxpmem's primary output) isn't supported — this
  // Volatility3 release has no AFF4 layer at all (confirmed against the
  // installed 2.28.0 source, not just a missing optional dependency).
  // macOS's avml-fallback output (.lime.compressed, same LiME format as
  // Linux) is fully supported.
  macos:   [".lime.compressed"],
};

export const ALLOWED_OS_TYPES = Object.keys(ALLOWED_EXTENSIONS_BY_OS);

export const DEFAULT_MAX_BYTES = 64 * 1024 * 1024 * 1024; // 64 GB — dump size equals the source machine's installed RAM

export function getMaxBytes(): number {
  const envVal = Number(process.env.RAM_MAX_UPLOAD_BYTES);
  return envVal > 0 ? envVal : DEFAULT_MAX_BYTES;
}

export function matchedExtension(filename: string, osType: string): string | null {
  const lower = filename.toLowerCase();
  const allowed = ALLOWED_EXTENSIONS_BY_OS[osType] ?? [];
  return allowed.find((ext) => lower.endsWith(ext)) ?? null;
}
