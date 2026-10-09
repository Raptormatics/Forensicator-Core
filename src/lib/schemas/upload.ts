import { z } from "zod";
import { jsonObjectSchema } from "./json";

// ---------------------------------------------------------------------------
// Raw upload-form field passthrough (accepts any JSON object from the form).
// ---------------------------------------------------------------------------
export const uploadMetadataSchema = jsonObjectSchema.default({});

// ---------------------------------------------------------------------------
// Typed schema for metadata.json produced by Live Forensicator.
// All fields are optional so future Forensicator versions can add fields
// without breaking ingestion.
// ---------------------------------------------------------------------------
export const investigationMetadataSchema = z
  .object({
    /** Free-text label for the investigation objective, e.g. "Lateral Movement" */
    title: z.string().optional(),
    investigation_id: z.string().optional(),
    hostname: z.string().optional(),
    username: z.string().optional(),
    operator: z.string().optional(),
    device: z.string().optional(),
    location: z.string().optional(),
    collector_version: z.string().optional(),
    collector_type: z.string().optional(),
    collection_start_time: z.string().optional().nullable(),
    collection_end_time: z.string().optional().nullable(),
    timezone: z.string().optional(),

    os: z
      .object({
        platform: z.string().optional(),
        version: z.string().optional(),
        build: z.string().optional()
      })
      .passthrough()
      .optional(),

    network: z
      .object({
        local_ip: z.array(z.string()).optional(),
        hostname: z.string().optional(),
        domain: z.string().optional()
      })
      .passthrough()
      .optional(),

    /** Investigation hypothesis / attack category tags */
    findingtags: z.array(z.string()).optional(),

    statistics: z
      .object({
        total_detections: z.number().optional(),
        ioc_detections: z.number().optional(),
        critical_detections: z.number().optional(),
        high_detections: z.number().optional(),
        medium_detections: z.number().optional(),
        low_detections: z.number().optional(),
        hash_detections: z.number().optional(),
        sigma_detections: z.number().optional()
      })
      .passthrough()
      .optional()
  })
  // passthrough so unrecognised fields from future collector versions are preserved.
  .passthrough();

export type InvestigationMetadata = z.infer<typeof investigationMetadataSchema>;

export const uploadResponseSchema = z.object({
  investigation: z.object({
    id: z.string(),
    title: z.string(),
    hostname: z.string().nullable(),
    finding_count: z.number(),
    created_at: z.string()
  }),
  findings: z.object({
    total: z.number(),
    by_severity: z.record(z.number()),
    by_category: z.record(z.number())
  })
});
