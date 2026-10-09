/**
 * Multi-provider LLM completion client for Forensicator AI. Mirrors the
 * free collector's ForensicatorAiClient.ps1 provider support (same
 * provider names, same design: local-first, but commercial APIs are a
 * first-class option for customers who'd rather not run their own LLM).
 *
 * Model management (list/pull/delete pulled weights — see ollama.ts) is
 * Ollama-specific and has no equivalent for hosted commercial APIs, so it
 * stays in ollama.ts; this file is just "send a prompt, get text back"
 * across all providers.
 */
import { ollamaGenerate, OllamaError } from "./ollama";

export type AiProvider = "ollama" | "openai" | "openai_compatible" | "azure_openai" | "anthropic";

export type AiProviderConfig = {
  provider: AiProvider;
  /**
   * Ollama: base URL of the Ollama daemon (e.g. http://localhost:11434).
   * openai_compatible: base URL of the OpenAI-shaped API (no trailing /v1).
   * azure_openai: the FULL chat-completions URL for your deployment,
   *   including ?api-version=... (Azure's URL shape is deployment-based,
   *   not model-based, so there's no clean way to derive it from a plain
   *   host+model pair) — e.g.
   *   https://my-resource.openai.azure.com/openai/deployments/my-gpt4/chat/completions?api-version=2024-06-01
   * openai / anthropic: ignored — their public API endpoint is used.
   */
  host: string;
  model: string;
  apiKey: string | null;
};

export class AiProviderError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = "AiProviderError";
  }
}

const OPENAI_BASE = "https://api.openai.com";
const ANTHROPIC_BASE = "https://api.anthropic.com";

export async function generateAiCompletion(
  config: AiProviderConfig,
  prompt: string,
  opts: { timeoutMs?: number } = {}
): Promise<string> {
  const timeoutMs = opts.timeoutMs ?? 120_000;

  switch (config.provider) {
    case "ollama": {
      try {
        return await ollamaGenerate({ host: config.host, model: config.model }, prompt, { timeoutMs });
      } catch (err) {
        if (err instanceof OllamaError) throw new AiProviderError(err.message, err);
        throw err;
      }
    }

    case "openai":
    case "openai_compatible": {
      const base = (config.provider === "openai" ? OPENAI_BASE : config.host).replace(/\/+$/, "");
      if (!config.apiKey) throw new AiProviderError(`An API key is required for the "${config.provider}" provider.`);
      const data = await postJson(`${base}/v1/chat/completions`, timeoutMs, {
        Authorization: `Bearer ${config.apiKey}`,
      }, {
        model: config.model,
        messages: [{ role: "user", content: prompt }],
      });
      const content = data?.choices?.[0]?.message?.content;
      if (typeof content !== "string" || !content.trim()) {
        throw new AiProviderError("OpenAI-compatible API returned no completion text.");
      }
      return content;
    }

    case "azure_openai": {
      if (!config.host) throw new AiProviderError("azure_openai requires the full deployment chat-completions URL in the host field.");
      if (!config.apiKey) throw new AiProviderError("An API key is required for the \"azure_openai\" provider.");
      const data = await postJson(config.host, timeoutMs, {
        "api-key": config.apiKey,
      }, {
        messages: [{ role: "user", content: prompt }],
      });
      const content = data?.choices?.[0]?.message?.content;
      if (typeof content !== "string" || !content.trim()) {
        throw new AiProviderError("Azure OpenAI returned no completion text.");
      }
      return content;
    }

    case "anthropic": {
      if (!config.apiKey) throw new AiProviderError("An API key is required for the \"anthropic\" provider.");
      const base = (config.host || ANTHROPIC_BASE).replace(/\/+$/, "");
      const data = await postJson(`${base}/v1/messages`, timeoutMs, {
        "x-api-key": config.apiKey,
        "anthropic-version": "2023-06-01",
      }, {
        model: config.model,
        max_tokens: 1024,
        messages: [{ role: "user", content: prompt }],
      });
      const text = data?.content?.[0]?.text;
      if (typeof text !== "string" || !text.trim()) {
        throw new AiProviderError("Anthropic returned no completion text.");
      }
      return text;
    }

    default: {
      const exhaustiveCheck: never = config.provider;
      throw new AiProviderError(`Unknown AI provider: ${exhaustiveCheck}`);
    }
  }
}

async function postJson(
  url: string,
  timeoutMs: number,
  headers: Record<string, string>,
  body: unknown
): Promise<any> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (err) {
    throw new AiProviderError(`Could not reach ${url}. Check the host/endpoint configuration in Settings.`, err);
  } finally {
    clearTimeout(timeout);
  }

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new AiProviderError(`${url} returned ${res.status} ${res.statusText}: ${text.slice(0, 500)}`);
  }
  return res.json();
}

/** Cheap reachability probe used by the Settings > AI page's "Test Connection". */
export async function testAiProviderConnection(config: AiProviderConfig): Promise<{ ok: boolean; error?: string }> {
  try {
    await generateAiCompletion(config, "Reply with the single word: ok", { timeoutMs: 20_000 });
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Unknown error" };
  }
}
