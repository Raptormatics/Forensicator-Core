"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useSession } from "next-auth/react";
import {
  BrainCircuit, CheckCircle2, AlertCircle, Loader2, Trash2, Download,
  Play, Square, PackagePlus, PackageMinus, ShieldOff,
} from "lucide-react";

// Core has no RBAC — the sole user always has full access, same as every
// other instance-level settings page.

const PROVIDERS = [
  { value: "ollama", label: "Ollama (local / self-hosted)" },
  { value: "openai", label: "OpenAI" },
  { value: "openai_compatible", label: "OpenAI-compatible (LM Studio, vLLM, etc.)" },
  { value: "azure_openai", label: "Azure OpenAI / Microsoft Copilot" },
  { value: "anthropic", label: "Anthropic" },
] as const;
type Provider = (typeof PROVIDERS)[number]["value"];

const MODEL_SUGGESTIONS: Record<Provider, string[]> = {
  ollama: ["mistral:7b-instruct", "llama3.1:8b-instruct", "qwen2.5:7b-instruct"],
  openai: ["gpt-4o", "gpt-4o-mini", "gpt-4.1"],
  openai_compatible: [],
  azure_openai: [],
  anthropic: ["claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022"],
};

type AiSettings = {
  aiEnabled: boolean;
  aiProvider: Provider;
  aiHost: string;
  aiModel: string;
  aiApiKeyLast4: string | null;
  hasApiKey: boolean;
  ollamaManaged: boolean;
};

type ModelInfo = { name: string; size: number; modifiedAt: string | null };
type PullStatus = { model: string; status: string; completed: number; total: number; done: boolean; error: string | null };
type ModelsResponse = { models: ModelInfo[]; error: string | null; pull: PullStatus | null };

type ServiceStatus = {
  installed: boolean;
  active: string;
  version: string | null;
  progress: { stage: string; message: string; updatedAt: string } | null;
  lastResult: { success: boolean; action: string; message: string; completedAt: string } | null;
};

function formatBytes(bytes: number): string {
  if (!bytes) return "—";
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(0)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export default function AiSettingsPage() {
  const { data: session } = useSession();
  // Core is single-user/single-role — the sole account always has full access.
  const isAdmin = true;

  const [settings, setSettings] = useState<AiSettings | null>(null);
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");

  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; error?: string } | null>(null);

  const [models, setModels] = useState<ModelsResponse | null>(null);
  const [pullInput, setPullInput] = useState("");
  const [pullBusy, setPullBusy] = useState(false);
  const modelsPollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [service, setService] = useState<ServiceStatus | null>(null);
  const [serviceBusy, setServiceBusy] = useState(false);
  const servicePollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const loadSettings = useCallback(async () => {
    const r = await fetch("/api/settings/ai");
    if (r.ok) setSettings(await r.json());
    setLoading(false);
  }, []);

  const loadModels = useCallback(async () => {
    const r = await fetch("/api/settings/ai/models");
    if (r.ok) setModels(await r.json());
  }, []);

  const loadService = useCallback(async () => {
    const r = await fetch("/api/settings/ai/service");
    if (r.ok) setService(await r.json());
  }, []);

  useEffect(() => { loadSettings(); }, [loadSettings]);

  useEffect(() => {
    if (settings?.aiProvider === "ollama") { loadModels(); loadService(); }
  }, [settings?.aiProvider, loadModels, loadService]);

  // Poll while a pull is in flight.
  useEffect(() => {
    if (!models?.pull || models.pull.done) return;
    modelsPollRef.current = setTimeout(loadModels, 1500);
    return () => { if (modelsPollRef.current) clearTimeout(modelsPollRef.current); };
  }, [models, loadModels]);

  // Poll while a service action is in flight.
  useEffect(() => {
    if (!service?.progress) return;
    servicePollRef.current = setTimeout(loadService, 2000);
    return () => { if (servicePollRef.current) clearTimeout(servicePollRef.current); };
  }, [service, loadService]);

  async function saveSettings() {
    if (!settings) return;
    setError(""); setSaved(false); setSaving(true);
    try {
      const body: Record<string, unknown> = {
        aiEnabled: settings.aiEnabled,
        aiProvider: settings.aiProvider,
        aiHost: settings.aiHost,
        aiModel: settings.aiModel,
        ollamaManaged: settings.ollamaManaged,
      };
      if (apiKeyInput.trim()) body.apiKey = apiKeyInput.trim();
      const r = await fetch("/api/settings/ai", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await r.json();
      if (!r.ok) { setError(data.error ?? "Failed to save settings."); return; }
      setSettings(data);
      setApiKeyInput("");
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch {
      setError("Failed to save settings.");
    } finally {
      setSaving(false);
    }
  }

  async function testConnection() {
    setTesting(true); setTestResult(null);
    try {
      const r = await fetch("/api/settings/ai/test", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          provider: settings?.aiProvider,
          host: settings?.aiHost,
          model: settings?.aiModel,
          apiKey: apiKeyInput.trim() || undefined,
        }),
      });
      setTestResult(await r.json());
    } catch {
      setTestResult({ ok: false, error: "Request failed." });
    } finally {
      setTesting(false);
    }
  }

  async function pullModel() {
    if (!pullInput.trim()) return;
    setPullBusy(true);
    try {
      const r = await fetch("/api/settings/ai/models", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: pullInput.trim() }),
      });
      if (r.ok) { setPullInput(""); loadModels(); }
      else { const d = await r.json().catch(() => ({})); setError(d.error ?? "Failed to start pull."); }
    } finally {
      setPullBusy(false);
    }
  }

  async function deleteModel(name: string) {
    if (!confirm(`Delete model "${name}"? This frees disk space but you'll need to pull it again to use it.`)) return;
    const r = await fetch(`/api/settings/ai/models/${encodeURIComponent(name)}`, { method: "DELETE" });
    if (r.ok) loadModels();
  }

  async function serviceAction(action: "install" | "uninstall" | "start" | "stop") {
    if (action === "uninstall" && !confirm("Uninstall Ollama from this host? Downloaded models are kept unless you also purge them.")) return;
    setServiceBusy(true);
    try {
      const r = await fetch("/api/settings/ai/service", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action }),
      });
      if (r.ok) loadService();
      else { const d = await r.json().catch(() => ({})); setError(d.error ?? `Failed to ${action}.`); }
    } finally {
      setServiceBusy(false);
    }
  }

  if (!isAdmin && !loading) {
    return (
      <div className="mx-auto max-w-2xl px-6 py-16 text-center text-zinc-500">
        <ShieldOff className="mx-auto mb-3 h-8 w-8" />
        Instance admin access required.
      </div>
    );
  }

  if (loading || !settings) return <div className="px-6 py-8 text-sm text-zinc-500">Loading…</div>;

  const isOllama = settings.aiProvider === "ollama";
  const needsApiKey = ["openai", "openai_compatible", "azure_openai", "anthropic"].includes(settings.aiProvider);
  const serviceInProgress = Boolean(service?.progress);

  return (
    <div className="mx-auto max-w-3xl px-6 py-8 space-y-8">
      <div className="flex items-center gap-3">
        <BrainCircuit className="h-5 w-5 text-teal-400" />
        <div>
          <h1 className="text-xl font-bold text-zinc-100">AI Analysis</h1>
          <p className="text-sm text-zinc-500">
            Configure Forensicator AI — analyst-assist finding analysis backed by a local Ollama
            instance or a commercial LLM provider. No model is bundled with the app; nothing runs
            or is downloaded until you enable this and (for Ollama) pull a model below.
          </p>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-900 bg-red-950/50 px-4 py-3">
          <AlertCircle className="h-4 w-4 shrink-0 text-red-400" />
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {/* Master enable + provider */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 space-y-4">
        <label className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-zinc-200">Enable Forensicator AI</p>
            <p className="text-xs text-zinc-500 mt-0.5">Turns on the &quot;Analyze with AI&quot; action on findings and queues background analysis jobs.</p>
          </div>
          <input
            type="checkbox"
            disabled={!isAdmin}
            checked={settings.aiEnabled}
            onChange={(e) => setSettings((s) => (s ? { ...s, aiEnabled: e.target.checked } : s))}
            className="h-5 w-9 shrink-0 accent-teal-500"
          />
        </label>

        <div>
          <label className="mb-1 block text-xs text-zinc-500">Provider</label>
          <select
            disabled={!isAdmin}
            value={settings.aiProvider}
            onChange={(e) => setSettings((s) => (s ? { ...s, aiProvider: e.target.value as Provider } : s))}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30 disabled:opacity-60"
          >
            {PROVIDERS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
          </select>
        </div>

        {isOllama ? (
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              disabled={!isAdmin}
              checked={settings.ollamaManaged}
              onChange={(e) => setSettings((s) => (s ? { ...s, ollamaManaged: e.target.checked, aiHost: e.target.checked ? "http://localhost:11434" : s.aiHost } : s))}
              className="accent-teal-500"
            />
            <span className="text-sm text-zinc-300">Run Ollama on this host (Forensicator installs and manages it)</span>
          </label>
        ) : null}

        {!isOllama || !settings.ollamaManaged ? (
          <div>
            <label className="mb-1 block text-xs text-zinc-500">
              {settings.aiProvider === "azure_openai" ? "Deployment chat-completions URL (including ?api-version=...)" : "Host / Base URL"}
            </label>
            <input
              type="text"
              disabled={!isAdmin}
              value={settings.aiHost}
              onChange={(e) => setSettings((s) => (s ? { ...s, aiHost: e.target.value } : s))}
              placeholder={
                settings.aiProvider === "azure_openai"
                  ? "https://my-resource.openai.azure.com/openai/deployments/my-gpt4/chat/completions?api-version=2024-06-01"
                  : settings.aiProvider === "ollama" ? "http://localhost:11434"
                  : settings.aiProvider === "openai_compatible" ? "https://my-llm-gateway.example.com"
                  : "(uses the provider's default endpoint)"
              }
              className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30 disabled:opacity-60"
            />
          </div>
        ) : null}

        {settings.aiProvider !== "azure_openai" && (
          <div>
            <label className="mb-1 block text-xs text-zinc-500">Model</label>
            <input
              type="text"
              disabled={!isAdmin}
              value={settings.aiModel}
              onChange={(e) => setSettings((s) => (s ? { ...s, aiModel: e.target.value } : s))}
              placeholder="mistral:7b-instruct"
              list="model-suggestions"
              className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30 disabled:opacity-60"
            />
            <datalist id="model-suggestions">
              {MODEL_SUGGESTIONS[settings.aiProvider].map((m) => <option key={m} value={m} />)}
            </datalist>
          </div>
        )}

        {needsApiKey && (
          <div>
            <label className="mb-1 block text-xs text-zinc-500">
              API Key {settings.hasApiKey ? <span className="text-zinc-600">(saved, ending •••{settings.aiApiKeyLast4})</span> : null}
            </label>
            <input
              type="password"
              disabled={!isAdmin}
              value={apiKeyInput}
              onChange={(e) => setApiKeyInput(e.target.value)}
              placeholder={settings.hasApiKey ? "Leave blank to keep the saved key" : "sk-…"}
              className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30 disabled:opacity-60"
            />
          </div>
        )}

        <div className="flex items-center gap-3 pt-1">
          {isAdmin && (
            <button
              onClick={saveSettings}
              disabled={saving}
              className="flex items-center gap-2 rounded-lg bg-teal-700 px-4 py-2 text-sm font-semibold text-white hover:bg-teal-600 disabled:opacity-60"
            >
              {saving && <Loader2 className="h-4 w-4 animate-spin" />}
              {saved && <CheckCircle2 className="h-4 w-4" />}
              {saving ? "Saving…" : saved ? "Saved" : "Save changes"}
            </button>
          )}
          <button
            onClick={testConnection}
            disabled={testing}
            className="flex items-center gap-2 rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-200 hover:bg-zinc-800 disabled:opacity-60"
          >
            {testing ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
            {testing ? "Testing…" : "Test Connection"}
          </button>
          {testResult && (
            <span className={`text-xs ${testResult.ok ? "text-teal-400" : "text-red-400"}`}>
              {testResult.ok ? "✓ Connected — got a real completion back" : `✗ ${testResult.error}`}
            </span>
          )}
        </div>
      </div>

      {/* Local Ollama service management */}
      {isOllama && settings.ollamaManaged && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 space-y-3">
          <h2 className="text-sm font-medium text-zinc-300 uppercase tracking-wide">Local Ollama Service</h2>

          <div className="flex items-center justify-between rounded-md border border-zinc-800 bg-zinc-950/60 px-4 py-3">
            <div className="flex items-center gap-3">
              <span
                className={`inline-block h-2.5 w-2.5 shrink-0 rounded-full ${
                  service?.active === "active" ? "bg-green-400 shadow-[0_0_6px_1px_rgba(74,222,128,0.6)]" :
                  service?.installed ? "bg-zinc-600" : "bg-zinc-700"
                }`}
              />
              <div>
                <p className="text-sm font-medium text-zinc-200">
                  {!service?.installed ? "Not installed" : service.active === "active" ? "Running" : "Stopped"}
                  {service?.version ? <span className="ml-2 text-xs font-normal text-zinc-500">{service.version}</span> : null}
                </p>
                {serviceInProgress && service?.progress ? (
                  <p className="mt-0.5 text-xs text-teal-400">{service.progress.message}</p>
                ) : service?.lastResult && !service.lastResult.success ? (
                  <p className="mt-0.5 text-xs text-red-400">{service.lastResult.message}</p>
                ) : null}
              </div>
            </div>

            <div className="flex items-center gap-2">
              {!service?.installed ? (
                <button
                  onClick={() => serviceAction("install")}
                  disabled={serviceBusy || serviceInProgress}
                  className="flex items-center gap-1.5 rounded bg-teal-600 px-3 py-1.5 text-xs text-white hover:bg-teal-500 disabled:opacity-50"
                >
                  <PackagePlus className="h-3.5 w-3.5" /> Install Ollama
                </button>
              ) : (
                <>
                  {service.active === "active" ? (
                    <button
                      onClick={() => serviceAction("stop")}
                      disabled={serviceBusy || serviceInProgress}
                      className="flex items-center gap-1.5 rounded border border-zinc-700 px-3 py-1.5 text-xs text-zinc-200 hover:bg-zinc-800 disabled:opacity-50"
                    >
                      <Square className="h-3.5 w-3.5" /> Stop
                    </button>
                  ) : (
                    <button
                      onClick={() => serviceAction("start")}
                      disabled={serviceBusy || serviceInProgress}
                      className="flex items-center gap-1.5 rounded bg-teal-600 px-3 py-1.5 text-xs text-white hover:bg-teal-500 disabled:opacity-50"
                    >
                      <Play className="h-3.5 w-3.5" /> Start
                    </button>
                  )}
                  <button
                    onClick={() => serviceAction("uninstall")}
                    disabled={serviceBusy || serviceInProgress}
                    className="flex items-center gap-1.5 rounded border border-red-900 px-3 py-1.5 text-xs text-red-400 hover:bg-red-900/30 disabled:opacity-50"
                  >
                    <PackageMinus className="h-3.5 w-3.5" /> Uninstall
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Model management */}
      {isOllama && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 space-y-3">
          <h2 className="text-sm font-medium text-zinc-300 uppercase tracking-wide">Models on {settings.aiHost}</h2>

          {models?.error && <p className="text-xs text-red-400">{models.error}</p>}

          <div className="flex gap-2">
            <input
              type="text"
              value={pullInput}
              onChange={(e) => setPullInput(e.target.value)}
              placeholder="e.g. mistral:7b-instruct"
              list="model-suggestions"
              className="flex-1 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500/30"
            />
            <button
              onClick={pullModel}
              disabled={pullBusy || !!models?.pull && !models.pull.done}
              className="flex items-center gap-1.5 rounded bg-teal-600 px-3 py-2 text-sm text-white hover:bg-teal-500 disabled:opacity-50"
            >
              <Download className="h-4 w-4" /> Pull
            </button>
          </div>

          {models?.pull && !models.pull.done && (
            <div className="space-y-1 rounded-md border border-teal-800/40 bg-teal-950/20 p-3">
              <div className="flex items-center justify-between text-xs text-teal-300">
                <span>Pulling {models.pull.model} — {models.pull.status}</span>
                {models.pull.total > 0 && (
                  <span>{formatBytes(models.pull.completed)} / {formatBytes(models.pull.total)}</span>
                )}
              </div>
              {models.pull.total > 0 && (
                <div className="h-1.5 overflow-hidden rounded-full bg-zinc-800">
                  <div
                    className="h-full bg-teal-400 transition-all"
                    style={{ width: `${Math.min(100, (models.pull.completed / models.pull.total) * 100)}%` }}
                  />
                </div>
              )}
            </div>
          )}
          {models?.pull?.done && models.pull.error && (
            <p className="text-xs text-red-400">Last pull failed: {models.pull.error}</p>
          )}

          <div className="divide-y divide-zinc-800 rounded-md border border-zinc-800">
            {!models?.models.length ? (
              <p className="p-3 text-sm text-zinc-600">No models pulled yet.</p>
            ) : (
              models.models.map((m) => (
                <div key={m.name} className="flex items-center justify-between px-3 py-2">
                  <div>
                    <p className="text-sm text-zinc-200">{m.name}</p>
                    <p className="text-xs text-zinc-500">{formatBytes(m.size)}{m.modifiedAt ? ` · pulled ${new Date(m.modifiedAt).toLocaleDateString()}` : ""}</p>
                  </div>
                  <button
                    onClick={() => deleteModel(m.name)}
                    className="flex items-center gap-1 text-xs text-zinc-500 hover:text-red-400"
                  >
                    <Trash2 className="h-3.5 w-3.5" /> Delete
                  </button>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
