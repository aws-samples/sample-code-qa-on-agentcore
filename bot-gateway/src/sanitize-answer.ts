/**
 * The ONE text-sanitizing pipeline for agent answers, shared by the live
 * streaming path and the finalize path in index.ts. Historically each path
 * hand-rolled its own copy of this chain and the two drifted (the live path
 * once ran redact BEFORE strip — cross-review P1); this module is the single
 * implementation so the order can't drift again. PURE — no I/O, no state.
 *
 * ORDER CONTRACT (locked by tests/sanitize-answer.test.ts — do not reorder):
 *  1. splitEvidence FIRST, then stripFollowUps on each partition separately.
 *     The reverse order silently LOSES the evidence block whenever the model
 *     emits the 你可能还想问 trailer BEFORE 供研发复核 — stripFollowUps' greedy
 *     `…[\s\S]*$` tail-eat would swallow the evidence too. Splitting evidence
 *     off first confines each extractor to its own partition.
 *  2. redactSensitive runs AFTER stripToolCallLeak / normalizeBlocks /
 *     neutralizeModelLinks on BOTH chains. Stripping a tag can re-join the two
 *     halves of a secret that a `<parameter …>` tag split, so redaction must be
 *     the LAST content-altering pass or the re-joined secret survives to the card.
 *     (HISTORY: the LIVE EVIDENCE lane used to run redact→strip, kept byte-for-byte
 *     "to not change behavior" while only the finalize re-render used the correct
 *     order. AppSec finding 5bf12e05 showed that exemption was reachable and
 *     mechanically demonstrated it: a 32-char token split by `<parameter name=…>`
 *     defeats redact.ts's BARE_TOKEN_RE — which needs 32 CONTIGUOUS chars — and
 *     stripToolCallLeak then re-joins the halves, after redaction has already run.
 *     The lane now matches the contract; the exemption is GONE, not documented.
 *     tests/sanitize-answer.test.ts pins BOTH lanes with a tag-split secret, because
 *     the pre-existing evidence-lane test used a CONTIGUOUS secret that passed under
 *     either order and therefore could never fail on the inversion.)
 *  3. clampForCard runs AFTER strip/redact in each chain, so the size cap
 *     measures the (near-)final visible text — a clamp before redact/strip
 *     would measure text that later shrinks, or worse, cut a secret in half so
 *     redaction misses it. It is the last step of the live chain; the finalize
 *     tail additionally runs normalizeBlocks after it (additive newlines only —
 *     it can neither reveal clamped-away text nor move a secret across the
 *     redaction boundary).
 *  4. neutralizeModelLinks runs BEFORE redactSensitive, alongside the other
 *     content-altering passes. It rewrites `[t](u)` → `t（u）` and drops `<at …>`,
 *     which CHANGES CHARACTER ADJACENCY — exactly the property contract #2 exists
 *     to protect — so it must not run after redaction. See neutralize-links.ts for
 *     why the rewrite (rather than escaping or an allowlist) and why fenced code is
 *     exempt. (AppSec finding 32c8dabb.)
 *
 * Mode split (live is incremental/mid-stream, finalize is terminal):
 *  - "live": the WHOLE chain in one call — the live path has no unique
 *    intermediate steps. Body: split → stripFollowUps → stripPreamble (falling
 *    back to the raw text when stripping leaves nothing, so a partial frame
 *    never blanks) → normalizeBlocks → stripToolCallLeak → redactSensitive →
 *    clampForCard. Evidence: the live-panel lane (see the exception above).
 *  - "final": the shared FRONT half only (split → stripFollowUps → stripPreamble).
 *    finalize then does its unique middle (shapeBody disclaimers, leak-dominance
 *    check + conditional stripToolCallLeak, clarification override) and feeds
 *    each partition through renderFinalText for the terminal
 *    redact → clamp → normalize tail.
 */

import { splitEvidence } from "./extract-evidence";
import { stripFollowUps } from "./extract-followups";
import { stripPreamble } from "./strip-preamble";
import { stripToolCallLeak } from "./strip-toolcall-leak";
import { normalizeBlocks } from "./normalize-blocks";
import { neutralizeModelLinks } from "./neutralize-links";
import { redactSensitive } from "./redact";

// Per-field caps for the card body. A Feishu interactive card has a total
// body-size limit; the finalize step rebuilds the WHOLE card in one PUT
// (conclusion + reasoning panel + evidence), so an over-long conclusion or a
// huge echoed config table in the evidence could push the PUT past the limit →
// CardKit 400s the request. That failure is SWALLOWED by the serial CardWriter
// (a dropped write must never wedge the queue), so the card would silently stay
// stuck mid-stream (header blue "正在分析…", no footer) — the exact frozen-card
// failure the design forbids. Clamp each field well under the limit BEFORE the
// PUT so finalize always fits and lands. The agent's max_turns + prompt normally
// keep answers short; this is the backstop for a pathological long answer /
// large evidence dump. The live per-frame PUT clamps to the same cap.
export const MAX_CARD_BODY_CHARS = 9000;     // conclusion (prose; charts/tables are separate)
export const MAX_CARD_EVIDENCE_CHARS = 9000; // 供研发复核 citations block

export function clampForCard(text: string, max: number): string {
  if (text.length <= max) return text;
  // Cut on a line boundary when one is near the limit so we don't slice mid-markup,
  // and append a clear truncation marker (the dev-review panel still carries the
  // file:line citations, so a research can read the full source there).
  const head = text.slice(0, max);
  const nl = head.lastIndexOf("\n");
  const cut = nl > max - 400 ? head.slice(0, nl) : head;
  return `${cut}\n\n_（内容较长，已截断；完整依据见“供研发复核”或直接查阅源码）_`;
}

export interface SanitizedAnswer {
  /** live: fully cleaned display body (may be whitespace-only — caller shows a
   *  placeholder). final: the evidence-free body after the shared front half,
   *  BEFORE shapeBody/leak handling/redaction (finalize's own middle steps). */
  body: string;
  /** live: fully cleaned, trimmed evidence for the live dev-review panel ("" when
   *  none). final: the raw evidence partition (follow-up trailer stripped),
   *  before leak-strip/redaction. */
  evidence: string;
}

export type SanitizeMode = "live" | "final";

/**
 * Sanitize an agent answer for card display. See the file header for the exact
 * per-mode chain and the order contract.
 */
export function sanitizeAnswerText(text: string, opts: { mode: SanitizeMode }): SanitizedAnswer {
  // Shared front half — order contract #1: split evidence FIRST, then strip the
  // follow-up trailer from EACH partition (it commonly follows 供研发复核 too).
  const split = splitEvidence(text);
  const body = stripFollowUps(split.body);
  const evidence = stripFollowUps(split.evidence);

  if (opts.mode === "final") {
    // Front half only: finalize runs its unique middle (shapeBody, leak checks,
    // clarify) on these partitions, then renderFinalText for the terminal tail.
    return { body: stripPreamble(body), evidence };
  }

  // ── live mode: the whole chain ──
  // Body: fall back to the RAW text when stripping left nothing (a frame that is
  // still only a follow-up trailer must not blank the typewriter). stripPreamble
  // drops a leaked planning preamble so the typewriter shows 结论先行;
  // normalizeBlocks (additive newlines only) repairs jammed ###/--- live;
  // stripToolCallLeak scrubs raw <invoke> XML from the MCP-init-race failure;
  // neutralizeModelLinks (order contract #4) demotes model-emitted links/images/
  // mentions to text. Then — order contract #2 — redact LAST, and — #3 — clamp at
  // the very end so a runaway-long stream can't 400 the per-frame PUT (coalesced →
  // silently dropped → typewriter appears to freeze). finalize re-clamps independently.
  const liveBody = clampForCard(
    redactSensitive(
      neutralizeModelLinks(stripToolCallLeak(normalizeBlocks(stripPreamble(body.length > 0 ? body : text)))),
    ),
    MAX_CARD_BODY_CHARS,
  );
  // Evidence (live dev-review panel): SAME order as the body — strip, neutralize, then
  // redact LAST (order contract #2). This lane previously ran redact→strip, preserved
  // byte-for-byte for compatibility; AppSec finding 5bf12e05 showed a `<parameter>`-split
  // secret survives that ordering because the strip pass re-joins the halves after
  // redaction has already run. Clamped too: the finalize re-render clamps this element,
  // and an unclamped live evidence dump can 400 the per-frame PUT for the same reason
  // the body is clamped.
  const liveEvidence = evidence.trim()
    ? clampForCard(
        redactSensitive(neutralizeModelLinks(stripToolCallLeak(evidence))),
        MAX_CARD_EVIDENCE_CHARS,
      ).trim()
    : "";
  return { body: liveBody, evidence: liveEvidence };
}

/**
 * Terminal render pass for a FINALIZED card field (body or evidence), applied
 * after finalize's unique middle steps: neutralizeModelLinks (order contract #4 —
 * it changes character adjacency, so it must precede redaction), redactSensitive
 * (order contract #2 — after any stripping upstream), then clampForCard (an
 * over-long field must never push the single finalize PUT past Feishu's card-size
 * limit), then normalizeBlocks (repairs block markers; additive newlines only, so
 * it can't move a secret across the redaction boundary — safe to run after redact).
 *
 * Both card sinks are covered here: finalize re-renders the conclusion AND the
 * 供研发复核 evidence element through this function, so the link/mention
 * neutralisation applies to the terminal card as well as to the live frames.
 */
export function renderFinalText(text: string, maxChars: number): string {
  return normalizeBlocks(clampForCard(redactSensitive(neutralizeModelLinks(text)), maxChars));
}
