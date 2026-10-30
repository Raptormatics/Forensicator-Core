"use client";

/**
 * Enterprise slot on the Correlations page — Core stub, renders nothing.
 * The Enterprise overlay replaces this file with its cross-case correlation
 * controls (correlate several cases together, recent background runs).
 * Keep the props identical to the overlay's version.
 */
export type CorrelationEnterprisePanelProps = {
  /** Reload the correlation list after a run finishes. */
  onRunComplete: () => void;
};

export function CorrelationEnterprisePanel(_props: CorrelationEnterprisePanelProps) {
  return null;
}
