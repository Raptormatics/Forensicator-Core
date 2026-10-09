/**
 * Forensicator AI worker.
 * Processes jobs from the "forensicator-ai" queue: pulls a Finding, builds
 * a prompt from whatever AI.md sections its stored JSON has, calls Ollama,
 * and writes the parsed result back onto the Finding row.
 */
import { Worker, Job } from "bullmq";
import { getRedisConnection } from "./redis";
import { prisma } from "@/lib/db/prisma";
import { getAiConfig } from "@/lib/settings/system";
import { generateAiCompletion, AiProviderError } from "@/lib/ai/provider";
import { buildFindingPrompt, parseAiResponse } from "@/lib/ai/prompt";
import type { AiEnrichmentJobData } from "./queues";
import type { JsonObject } from "@/types/json";

const AI_QUEUE = "forensicator-ai";

async function processAiAnalysis(job: Job<AiEnrichmentJobData>) {
  const { findingId } = job.data;

  const finding = await prisma.finding.findUnique({ where: { id: findingId } });
  if (!finding) {
    console.warn(`[ai-worker] finding ${findingId} not found, skipping`);
    return;
  }

  const { enabled, ...aiConfig } = await getAiConfig();
  const model = aiConfig.model;

  if (!enabled) {
    await prisma.finding.update({ where: { id: findingId }, data: { aiStatus: "failed" } });
    console.warn(`[ai-worker] Forensicator AI is disabled — skipping finding ${findingId}`);
    return;
  }

  await prisma.finding.update({ where: { id: findingId }, data: { aiStatus: "processing" } });

  try {
    const prompt = buildFindingPrompt(finding.data as JsonObject);
    const raw = await generateAiCompletion(aiConfig, prompt, { timeoutMs: 180_000 });
    const result = parseAiResponse(raw);

    await prisma.finding.update({
      where: { id: findingId },
      data: {
        aiStatus: "complete",
        aiSummary: result.summary,
        // 0-100 scale, matching the upload pipeline's convention for
        // collector-supplied ai_analysis.confidence (see AI.md section 16).
        aiConfidence: result.confidence,
        aiModel: model,
        aiEnrichedAt: new Date(),
        // Merge into the stored JSON so the finding-detail panel can render
        // why_flagged/investigation_questions/recommended_next_steps
        // alongside the plain-text summary, without a schema change.
        data: {
          ...(finding.data as JsonObject),
          ai_analysis: {
            status: "complete",
            summary: result.summary,
            why_flagged: result.whyFlagged,
            investigation_questions: result.investigationQuestions,
            recommended_next_steps: result.recommendedNextSteps,
            confidence: result.confidence,
            model,
            analyzed_at: new Date().toISOString(),
          },
        } as never,
      },
    });

    console.log(`[ai-worker] analyzed finding ${findingId} (${model})`);
  } catch (err) {
    const message = err instanceof AiProviderError ? err.message : err instanceof Error ? err.message : "Unknown error";
    console.error(`[ai-worker] failed to analyze finding ${findingId}:`, message);
    await prisma.finding.update({
      where: { id: findingId },
      data: {
        aiStatus: "failed",
        data: {
          ...(finding.data as JsonObject),
          ai_analysis: {
            status: "failed",
            summary: null,
            error: message,
            model,
            analyzed_at: new Date().toISOString(),
          },
        } as never,
      },
    });
    throw err;
  }
}

export function startAiWorker() {
  const worker = new Worker<AiEnrichmentJobData>(AI_QUEUE, processAiAnalysis, {
    connection: getRedisConnection(),
    // Local CPU inference is single-threaded-ish in practice (one model
    // generation at a time is already saturating), so don't run several
    // analyses concurrently against the same Ollama instance.
    concurrency: 1,
  });
  worker.on("error", (err) => console.error("[ai-worker]", err));
  return worker;
}
