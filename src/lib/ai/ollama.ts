/**
 * Thin client for a local Ollama instance. No SDK dependency — Ollama's
 * HTTP API is stable and small enough that plain fetch is simpler than a
 * wrapper package, and it keeps this on the same "no new dependency"
 * footing as the rest of the AI plumbing.
 */

export type OllamaConfig = {
  host: string;
  model: string;
};

export class OllamaError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = "OllamaError";
  }
}

/**
 * Calls POST {host}/api/generate with stream:false and returns the raw
 * response text. Throws OllamaError on network failure, non-2xx, or an
 * empty response — callers decide how to record that against the Finding.
 */
export async function ollamaGenerate(
  config: OllamaConfig,
  prompt: string,
  opts: { timeoutMs?: number; format?: "json" } = {}
): Promise<string> {
  const url = `${config.host.replace(/\/+$/, "")}/api/generate`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs ?? 120_000);

  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: config.model,
        prompt,
        stream: false,
        ...(opts.format ? { format: opts.format } : {}),
      }),
      signal: controller.signal,
    });
  } catch (err) {
    throw new OllamaError(
      `Could not reach Ollama at ${config.host} (model "${config.model}"). Is Ollama running and is the host/model configured correctly in Settings?`,
      err
    );
  } finally {
    clearTimeout(timeout);
  }

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new OllamaError(`Ollama returned ${res.status} ${res.statusText}: ${body.slice(0, 500)}`);
  }

  const data = (await res.json()) as { response?: string };
  if (!data.response || !data.response.trim()) {
    throw new OllamaError("Ollama returned an empty response.");
  }
  return data.response;
}

export type OllamaModelInfo = {
  name: string;
  size: number;
  modifiedAt: string | null;
};

/** GET {host}/api/tags — used by Settings to verify connectivity/model availability. */
export async function ollamaListModels(host: string): Promise<OllamaModelInfo[]> {
  const url = `${host.replace(/\/+$/, "")}/api/tags`;
  const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new OllamaError(`Ollama returned ${res.status} ${res.statusText}`);
  const data = (await res.json()) as { models?: { name: string; size?: number; modified_at?: string }[] };
  return (data.models ?? []).map((m) => ({
    name: m.name,
    size: m.size ?? 0,
    modifiedAt: m.modified_at ?? null,
  }));
}

/** GET {host}/api/version — cheapest possible reachability probe. */
export async function ollamaPing(host: string): Promise<{ ok: boolean; version?: string; error?: string }> {
  try {
    const res = await fetch(`${host.replace(/\/+$/, "")}/api/version`, { signal: AbortSignal.timeout(5_000) });
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    const data = (await res.json()) as { version?: string };
    return { ok: true, version: data.version };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Unreachable" };
  }
}

/** DELETE {host}/api/delete — removes a previously-pulled model. */
export async function ollamaDeleteModel(host: string, model: string): Promise<void> {
  const res = await fetch(`${host.replace(/\/+$/, "")}/api/delete`, {
    method: "DELETE",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new OllamaError(`Failed to delete model "${model}": ${res.status} ${body.slice(0, 300)}`);
  }
}

export type OllamaPullProgress = {
  status: string;
  digest?: string;
  total?: number;
  completed?: number;
};

/**
 * POST {host}/api/pull — streams newline-delimited JSON progress events as
 * Ollama downloads the model's layers. Ollama itself performs and owns the
 * download (to its own models directory); this just consumes the stream
 * and forwards each event to onProgress so the caller can persist/poll it.
 * Resolves once Ollama reports the pull complete ({status:"success"}).
 */
export async function ollamaPullModel(
  host: string,
  model: string,
  onProgress: (progress: OllamaPullProgress) => void
): Promise<void> {
  const res = await fetch(`${host.replace(/\/+$/, "")}/api/pull`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model, stream: true }),
  });

  if (!res.ok || !res.body) {
    const body = await res.text().catch(() => "");
    throw new OllamaError(`Failed to start pull for "${model}": ${res.status} ${body.slice(0, 300)}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let sawSuccess = false;

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) {
      if (!line.trim()) continue;
      let evt: OllamaPullProgress;
      try {
        evt = JSON.parse(line);
      } catch {
        continue;
      }
      if (evt.status === "success") sawSuccess = true;
      onProgress(evt);
    }
  }

  if (!sawSuccess) {
    throw new OllamaError(`Pull for "${model}" ended without a success confirmation from Ollama.`);
  }
}
