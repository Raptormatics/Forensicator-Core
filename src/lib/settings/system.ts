/**
 * Instance-wide settings, editable from Settings -> General.
 * Singleton row (src/prisma/schema.prisma: SystemSettings) — deliberately
 * narrow. Only settings safe to change live, without a process restart,
 * belong here; see the schema comment for why Redis connection info
 * stays env-var/restart-only instead.
 */
import path from "path";
import { prisma } from "@/lib/db/prisma";
import { decryptSecret } from "@/lib/crypto/secret-box";
import type { AiProvider, AiProviderConfig } from "@/lib/ai/provider";

const SINGLETON_ID = "singleton";

export async function getSystemSettings() {
  return prisma.systemSettings.findUnique({ where: { id: SINGLETON_ID } });
}

/** The instance's configured public URL (e.g. https://forensicator.tesco.com), or null if unset. */
export async function getAppDomain(): Promise<string | null> {
  const settings = await getSystemSettings();
  return settings?.appDomain ?? null;
}

/** DB override > REPORTS_DIR env var > default ./reports-output under the project root. */
export async function getReportsDir(): Promise<string> {
  const settings = await getSystemSettings();
  return (
    settings?.reportsDir ??
    process.env.REPORTS_DIR ??
    path.join(process.cwd(), "reports-output")
  );
}

/**
 * DB override > PCAP_DIR env var > default ./pcap-storage under the project
 * root. Same read-fresh-per-job pattern as getReportsDir() — unlike JSON
 * finding uploads, raw .pcap/.pcapng bytes are kept on disk here so the
 * PCAP worker can re-read them via tshark.
 */
export async function getPcapDir(): Promise<string> {
  const settings = await getSystemSettings();
  return (
    settings?.pcapDir ??
    process.env.PCAP_DIR ??
    path.join(process.cwd(), "pcap-storage")
  );
}

/** DB override > TSHARK_PATH env var > bare "tshark" (resolved via PATH). */
export async function getTsharkPath(): Promise<string> {
  const settings = await getSystemSettings();
  return settings?.tsharkPath ?? process.env.TSHARK_PATH ?? "tshark";
}

/**
 * DB override > RAM_DIR env var > default ./ram-storage under the project
 * root. Same read-fresh-per-job pattern as getPcapDir() — raw memory-image
 * bytes are kept on disk here so the RAM worker can re-read them via
 * Volatility3, once per plugin.
 */
export async function getRamDir(): Promise<string> {
  const settings = await getSystemSettings();
  return (
    settings?.ramDir ??
    process.env.RAM_DIR ??
    path.join(process.cwd(), "ram-storage")
  );
}

/**
 * DB override > VOLATILITY_PATH env var > <APP_DIR>/.venvs/volatility3/bin/vol.
 * Unlike getTsharkPath()'s bare "tshark", Volatility3 lives inside an
 * isolated Python venv (see deploy/provision.sh) rather than on PATH, so the
 * default here is an absolute path, not a bare command name.
 */
export async function getVolatilityPath(): Promise<string> {
  const settings = await getSystemSettings();
  return (
    settings?.volatilityPath ??
    process.env.VOLATILITY_PATH ??
    path.join(process.cwd(), ".venvs", "volatility3", "bin", "vol")
  );
}

/**
 * DB override > VOLATILITY_SYMBOLS_DIR env var > default
 * ./volatility-symbols under the project root. Always resolves to a
 * concrete, always-passed-to-`-s` directory (unlike the tshark/pcap
 * settings' "null means don't override" pattern) for two reasons: (1) it
 * doubles as the write target for analyst-uploaded custom ISF files (see
 * src/app/api/ram-analysis/symbols/route.ts) — those need somewhere
 * concrete to land even on an instance that never touched this setting;
 * (2) Volatility3 still falls back to its own bundled cache and remote
 * symbol-server fetch for anything not found here, so passing an extra
 * (possibly empty) directory via -s is always safe.
 */
export async function getVolatilitySymbolsDir(): Promise<string> {
  const settings = await getSystemSettings();
  return (
    settings?.volatilitySymbolsDir ??
    process.env.VOLATILITY_SYMBOLS_DIR ??
    path.join(process.cwd(), "volatility-symbols")
  );
}

/**
 * DB override > RAM_CHUNK_SIZE_BYTES env var > 40MB default. Chunked RAM
 * uploads (see RamUploadSession) split the source file into pieces no
 * larger than this so any request individually stays under a fronting
 * reverse proxy/tunnel's own body-size cap (e.g. Cloudflare's, which is
 * enforced at its edge and can't be raised via any origin-server config).
 */
export async function getRamChunkSize(): Promise<number> {
  const settings = await getSystemSettings();
  if (settings?.ramChunkSizeBytes && settings.ramChunkSizeBytes > 0) return settings.ramChunkSizeBytes;
  const envVal = Number(process.env.RAM_CHUNK_SIZE_BYTES);
  return envVal > 0 ? envVal : 40 * 1024 * 1024;
}

/** DB override > WIN_ARTIFACTS_DIR env var > default ./winartifacts-storage under the project root. */
export async function getWinArtifactsDir(): Promise<string> {
  const settings = await getSystemSettings();
  return (
    settings?.winArtifactsDir ??
    process.env.WIN_ARTIFACTS_DIR ??
    path.join(process.cwd(), "winartifacts-storage")
  );
}

/**
 * DB override > WIN_ARTIFACTS_PYTHON_PATH env var > <APP_DIR>/.venvs/winartifacts/bin/python3.
 * Windows Artifact Analysis's registry parser (regipy) lives in its own
 * venv, separate from Volatility3's — no runtime relationship between the
 * two toolsets, see deploy/provision.sh. Prefetch parsing does NOT use
 * this venv — see getPrefetchPythonPath() below.
 */
export async function getWinArtifactsPythonPath(): Promise<string> {
  const settings = await getSystemSettings();
  return (
    settings?.winArtifactsPythonPath ??
    process.env.WIN_ARTIFACTS_PYTHON_PATH ??
    path.join(process.cwd(), ".venvs", "winartifacts", "bin", "python3")
  );
}

/**
 * DB override > PREFETCH_PYTHON_PATH env var > bare "python3" (resolved
 * via PATH). Unlike regipy's own pip-installed venv, Prefetch parsing
 * uses pyscca (libyal's libscca Python bindings), installed as the
 * python3-libscca system package (see deploy/provision.sh) — it needs to
 * link against the compiled libscca1 C library, which isn't something a
 * venv's pip install reliably provides, so this resolves to the SYSTEM
 * python3 (same "bare command on PATH" convention as getTsharkPath()),
 * not an isolated venv path like getWinArtifactsPythonPath()/
 * getVolatilityPath().
 */
export async function getPrefetchPythonPath(): Promise<string> {
  const settings = await getSystemSettings();
  return (
    settings?.prefetchPythonPath ??
    process.env.PREFETCH_PYTHON_PATH ??
    "python3"
  );
}

/**
 * Forensicator AI provider config — DB-backed, schema defaults cover an
 * unconfigured instance. Decrypts the stored API key (if any) so callers
 * get something directly usable; never returns aiApiKeyEncrypted itself.
 */
export async function getAiConfig(): Promise<AiProviderConfig & { enabled: boolean }> {
  const settings = await getSystemSettings();
  return {
    enabled: settings?.aiEnabled ?? false,
    provider: (settings?.aiProvider as AiProvider) ?? "ollama",
    host: settings?.aiHost ?? "http://localhost:11434",
    model: settings?.aiModel ?? "mistral:7b-instruct",
    apiKey: settings?.aiApiKeyEncrypted ? decryptSecret(settings.aiApiKeyEncrypted) : null,
  };
}
