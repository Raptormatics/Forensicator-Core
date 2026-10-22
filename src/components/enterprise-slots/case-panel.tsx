"use client";

/**
 * Enterprise slot on the case page — Core stub, renders nothing. The
 * Enterprise overlay replaces this file with its legal hold and archive
 * storage (export / retrieve) controls. Keep the props identical to the
 * overlay's version.
 */
export type CaseEnterprisePanelProps = {
  caseId: string;
  caseStatus: string;
  archived: boolean;
  /** Reload the case page after a change. */
  onChanged: () => void;
};

export function CaseEnterprisePanel(_props: CaseEnterprisePanelProps) {
  return null;
}
