// ─────────────────────────────────────────────────────────────────────────────
// Visual decoder builder — DOM text-selection helpers.
//
// The sample line is rendered as a mix of plain text nodes (unhighlighted
// literal gaps) and <mark> elements (already-tagged spans). These helpers
// recover the ABSOLUTE character offset into the original raw line from
// whatever the browser's native Selection API reports (which is relative to
// individual text nodes, not the whole line) by walking the container's text
// nodes in document order.
// ─────────────────────────────────────────────────────────────────────────────

/** Sum of the length of every text node strictly before `target` within `root`. */
function offsetOfNode(root: Node, target: Node): number {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  let offset = 0;
  let node: Node | null;
  while ((node = walker.nextNode())) {
    if (node === target) return offset;
    offset += node.textContent?.length ?? 0;
  }
  return offset;
}

/**
 * Read the current window selection and, if it's entirely within `container`,
 * return the absolute [start, end) character range into the container's full
 * text content. Returns null for an empty/collapsed selection or one outside
 * the container.
 */
export function getAbsoluteSelectionOffsets(container: HTMLElement): { start: number; end: number } | null {
  const sel = window.getSelection();
  if (!sel || sel.rangeCount === 0 || sel.isCollapsed) return null;

  const range = sel.getRangeAt(0);
  if (!container.contains(range.startContainer) || !container.contains(range.endContainer)) return null;

  const start = offsetOfNode(container, range.startContainer) + range.startOffset;
  const end = offsetOfNode(container, range.endContainer) + range.endOffset;
  if (end <= start) return null;

  return { start: Math.min(start, end), end: Math.max(start, end) };
}

const QUOTE_CHARS = new Set(['"', "'"]);
const BRACKET_PAIRS: [string, string][] = [["[", "]"], ["(", ")"], ["{", "}"]];

export interface BoundaryResult {
  start: number;
  end: number;
  consumedBoundary: boolean;
  quoteChar?: '"' | "'";
  between?: { open: string; close: string };
}

/**
 * Given a raw drag-selection [start,end), detect whether it already
 * includes matching quote/bracket delimiters, or has them immediately
 * adjacent on both sides (in which case the range is extended by one
 * character on each side to consume them). This is what lets the pattern
 * builder slice literal gaps directly from span boundaries without ever
 * double-counting a delimiter as both token edge and separate literal text.
 */
export function normalizeSpanBoundaries(rawLine: string, start: number, end: number): BoundaryResult {
  const first = rawLine[start];
  const last = rawLine[end - 1];

  // Already-included: the drag covered the delimiters themselves.
  if (end - start >= 2 && QUOTE_CHARS.has(first) && first === last) {
    return { start, end, consumedBoundary: false, quoteChar: first as '"' | "'" };
  }
  for (const [open, close] of BRACKET_PAIRS) {
    if (end - start >= 2 && first === open && last === close) {
      return { start, end, consumedBoundary: false, between: { open, close } };
    }
  }

  // Adjacent-but-excluded: only the interior was selected.
  const before = start > 0 ? rawLine[start - 1] : undefined;
  const after = end < rawLine.length ? rawLine[end] : undefined;
  if (before !== undefined && after !== undefined) {
    if (QUOTE_CHARS.has(before) && before === after) {
      return { start: start - 1, end: end + 1, consumedBoundary: true, quoteChar: before as '"' | "'" };
    }
    for (const [open, close] of BRACKET_PAIRS) {
      if (before === open && after === close) {
        return { start: start - 1, end: end + 1, consumedBoundary: true, between: { open, close } };
      }
    }
  }

  return { start, end, consumedBoundary: false };
}
