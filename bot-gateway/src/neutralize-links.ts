/**
 * Neutralize CLICKABLE and AUTO-LOADING constructs in MODEL-GENERATED answer text
 * before it is rendered into a CardKit `markdown` element. PURE — no I/O, no state.
 *
 * WHY THIS EXISTS (AppSec finding 32c8dabb). `cardkit-client.ts` renders the user's
 * QUESTION through a `plain_text` tag and its header comment calls that echo
 * "(injection-safe)", with the correct reasoning that plain_text never interprets
 * markdown so no escaping is needed. The ANSWER travels a different route: it is
 * rendered with `tag: "markdown"` at six-plus sinks, and by the project's own threat
 * model (T5) it is untrusted MODEL output derived from untrusted REPOSITORY content.
 * The hardening stopped at the sink whose input was obviously user-typed; this module
 * covers the sink whose input arrives untrusted by a longer path.
 *
 * WHAT THE MECHANISM IS, and what it is NOT. Content in an indexed repo steers the
 * answer to emit `[看这里](https://attacker/?q=<snippet>)` or a spoofed
 * `<at id="ou_…">`, which renders clickable to EVERY member of the chat. CardKit is
 * Feishu's card renderer, not a browser DOM, so there is NO script path here — the
 * risk is click-through exfiltration and mention spoofing, not code execution.
 *
 * WHY IMAGES ARE HANDLED FIRST AND UNCONDITIONALLY. The finding's severity hinged on
 * one fact its author could not check from source: whether CardKit auto-loads
 * `![](url)`. If it does, the click requirement disappears and this becomes a
 * NO-INTERACTION exfiltration channel — the strongest form of the class. Rather than
 * make our defence depend on an unverified renderer behaviour, we degrade image
 * markdown to text ALWAYS. That is correct under both answers, so the open question
 * changes nothing about this code. (An answer about source code has no legitimate
 * reason to embed a remote image, so the cost of being wrong in this direction is nil.)
 *
 * WHY REWRITE RATHER THAN ESCAPE OR ALLOWLIST.
 *  - NOT backslash-escaping: `cardkit-client.ts:31-32` established that CardKit is not
 *    CommonMark, so escaping "would make the common case worse". That reasoning holds
 *    here and rules the approach out.
 *  - NOT a target allowlist (permit code.amazon.com, degrade the rest): an allowlist
 *    has to be maintained and drifts. A link→text rewrite has no ongoing cost.
 *  - So: keep the visible text AND the URL, drop only the CLICKABILITY. A citation
 *    stays fully readable — `[foo.ts:12](https://code.amazon.com/…)` becomes
 *    `foo.ts:12 (https://code.amazon.com/…)` — which matters because the 供研发复核
 *    evidence panel legitimately cites code URLs and a reviewer must still be able to
 *    read them.
 *
 * FENCED CODE IS EXEMPT, and that is a product requirement rather than a concession.
 * This product's answers quote source code, and quoted code can legitimately contain
 * `[x](y)` (a markdown file in the indexed repo, a docstring, a link in a comment).
 * Rewriting inside a fence would corrupt the very artifact the user asked to see, and
 * a fence is not a clickable construct in the first place — CardKit renders its
 * contents literally. So we split on fences and transform only the prose partitions.
 *
 * ReDoS: every pattern is a single bounded, negated char-class terminated by a
 * required literal it cannot consume. No nested quantifier, no unbounded run next to
 * a literal — the two failure shapes this package has been bitten by before
 * (strip-toolcall-leak.ts's `\**`, redact.ts's lookahead stack). Answer text is
 * model-authored from indexed repo content and the live typewriter re-runs the whole
 * accumulated string every throttle tick, so a quadratic pattern here would be a
 * remotely reachable stall of the single-threaded event loop.
 */

/**
 * Fenced code block (``` or ~~~), bounded so a huge block cannot scan to EOF.
 *
 * A CLOSING fence is REQUIRED. The first version accepted `$` as an alternative terminator, which
 * meant a model could open a fence, never close it, and place every remaining construct in the
 * answer inside the exemption — links, images, autolinks and mentions all passed through
 * untouched to the end of the text. An unterminated tail is now treated as prose instead.
 * Consequence, accepted deliberately: while the live answer is still streaming, a code block is
 * unterminated by definition, so its contents are neutralized until the closing fence arrives and
 * the finalize pass restores them. Briefly rewriting markdown inside a partial code block is a
 * cosmetic artifact; exempting the rest of the answer is a security hole.
 */
const FENCE_RE = /(^|\n)[ \t]*(?:```|~~~)[^\n]{0,200}\n[\s\S]{0,20000}?\n[ \t]*(?:```|~~~)[ \t]*(?=\n|$)/g;

/**
 * Markdown link / image. The leading `!` distinguishes an image. Label and target are
 * both bounded negated classes; the target additionally excludes whitespace so a
 * stray `(` in prose cannot start a 2000-char scan.
 */
const LINK_RE = /(!?)\[([^\]\n]{0,500})\]\(\s*([^)\s]{0,2000})\s*\)/g;

/**
 * Bare autolink — CardKit renders this clickable too.
 *
 * Written to the CommonMark autolink grammar rather than to an approximation of it, because every
 * approximation this file has tried was wrong in one direction or the other:
 *
 *  - `(?:https?|ftp)://` was too NARROW. It missed `<mailto:…>`, `<tel:…>`, `<javascript:…>` and the
 *    real `<data:text/html,…>` shape, all of which are valid autolinks and all of which render
 *    clickable. Coverage for them was bolted onto the postcondition sweep instead of onto this
 *    pattern, which is how the sweep ended up doing a job it cannot do safely (see below).
 *  - A bare `<[a-z][a-z0-9+.-]*:` prefix probe was too WIDE, and shipped as a real regression: with
 *    no closing `>` required and a single-character scheme accepted, it fired on ordinary text.
 *    `if a<b:` became `if a（b:`.
 *
 * The grammar settles both. An autolink is `<scheme:rest>` where the scheme is 2-32 characters
 * starting with a letter, `rest` contains no whitespace, `<` or `>`, and the closing `>` is
 * MANDATORY. So `if a<b:` is not an autolink twice over — a one-character scheme and no terminator
 * — and needs no special case to be left alone. `<xsl:template>` IS matched, and that is correct
 * rather than collateral: CommonMark reads it as an autolink too, so a renderer may well make it
 * clickable. Quoted code keeps it verbatim via the fence and code-span exemptions.
 *
 * The length bound is LOAD-BEARING for complexity, not decoration. `[^<>\s]+` looks linear but is
 * only linear per match ATTEMPT: on input carrying many `<scheme:` starts and no closing `>`, every
 * start scans to the end of the string, which is O(n²) overall. The bound keeps each attempt
 * constant, so the whole pass stays linear. Padding past the bound therefore cannot be fixed by
 * removing it — that trades a bypass for a ReDoS. The postcondition sweep closes the bypass with a
 * FIXED-LENGTH match that never scans for a terminator.
 */
const AUTOLINK_RE = /<([a-z][a-z0-9+.-]{1,31}:[^<>\s]{1,2000})>/gi;

/**
 * Feishu mention tag. The asker's own mention is emitted by the composer in its OWN
 * markdown element from a platform-supplied open_id (cardkit-client.ts:34-40 explains
 * why that one needs no escaping) — that argument covers the COMPOSER's element and
 * does not transfer to an id the MODEL emitted, which is what this strips.
 */
// Bounded for the same complexity reason as AUTOLINK_RE above; the sweep closes the padding bypass.
const AT_TAG_RE = /<\/?at\b[^>]{0,300}>/gi;

// TWO probe families, deliberately NOT one shared constant. Revision 5 unified them after the fast
// path had drifted NARROWER than the sweep, which made the sweep unreachable for the schemes it had
// just been widened to catch. Unifying fixed that but asserted the wrong invariant: these two probes
// have opposite correctness requirements, so they cannot be the same pattern.
//
//   FAST PATH — may be WIDER than needed, must never be narrower. It only decides whether to run the
//   transform at all. Too wide costs one wasted pass over the text and changes nothing; too narrow
//   returns clickable text verbatim. So it errs wide on purpose.
//
//   SWEEP — must be PRECISE. It rewrites characters, so anything it over-matches is corrupted
//   output. A prefix probe here shipped as a live regression: `if a<b:` became `if a（b:`.
//
// The invariant that actually holds is CONTAINMENT, fast path ⊇ sweep ∪ transform — not equality.
const ANY_SCHEME_AUTOLINK = /<[a-z][a-z0-9+.-]*:/i;
const ANY_AT_TAG = /<\/?at\b/i;

// SWEEP probes. Each matches ONLY the case the transform's bounded pattern cannot reach: a construct
// whose interior RUNS PAST the transform's length bound. That is the entire residual — a construct
// within the bound is handled above, and one past it is exactly what the bound gives up on.
//
// The `{2000}` / `{300}` here are EXACT, not ranges: this is a fixed-length lookahead, so it costs a
// constant per position and cannot go quadratic the way a `[^>\s]*` terminator search would. And
// because it demands 2000 (or 300) consecutive interior characters, no plain prose or inline code
// can trip it — `if a<b:`, `x<y: int`, `<Note:` and `<xsl:` all fail it immediately.
//
// Only the opening `<` is rewritten, via lookahead: breaking the bracket is enough, since an
// autolink needs a matched `<…>` pair to render at all.
//
// Accepted imprecision, stated rather than hidden: a 2000-character run of non-space characters with
// no closing `>` is not an autolink and is still defanged. That shape does not occur in prose.
const AUTOLINK_OVERLONG = /<[a-z][a-z0-9+.-]{1,31}:[^<>\s]{2000}/i;
const AUTOLINK_OVERLONG_G = /<(?=[a-z][a-z0-9+.-]{1,31}:[^<>\s]{2000})/gi;
const AT_TAG_OVERLONG = /<\/?at\b[^>]{300}/i;
const AT_TAG_OVERLONG_G = /<(?=\/?at\b[^>]{300})/gi;

function neutralizeOnce(s: string): string {
  return s
    // Image first: drop the `!` so it can never be fetched, and keep alt + url as text.
    // Then plain links: keep the label, demote the target to a parenthesised literal.
    .replace(LINK_RE, (_m, bang: string, label: string, target: string) => {
      const text = label.trim();
      const url = target.trim();
      if (bang === "!") {
        // An image carries no useful label most of the time; name it explicitly so a
        // reader can tell something was removed rather than silently losing content.
        return text ? `[图片已移除：${text}]（${url}）` : `[图片已移除]（${url}）`;
      }
      if (!text) return `（${url}）`;
      return `${text}（${url}）`;
    })
    .replace(AUTOLINK_RE, (_m, url: string) => `（${url}）`)
    .replace(AT_TAG_RE, "");
}

/**
 * NESTED CONSTRUCTS. `LINK_RE`'s label class permits `!` and `[`, so for `[![a](i.png)](u)` the
 * label captured is `![a` and one pass yields `![a（i.png）](u)` — which is once again a VALID
 * markdown image, with `u` as its target. A single pass therefore converted a nested construct
 * into a live one, defeating the unconditional image rule.
 *
 * Rather than attempt a full markdown parser, iterate to a fixed point with a hard bound (nesting
 * deeper than this is not a rendering concern, it is a malformed-input concern) and then assert the
 * postcondition: no `](` and no image marker may survive. The final sweep is what makes the
 * guarantee unconditional instead of best-effort.
 */
const MAX_NEUTRALIZE_PASSES = 4;

function neutralizeProse(s: string): string {
  let out = s;
  for (let i = 0; i < MAX_NEUTRALIZE_PASSES; i++) {
    const next = neutralizeOnce(out);
    if (next === out) break;
    out = next;
  }
  // Postcondition sweep. If anything clickable survived the bounded loop (deeper nesting, or a
  // shape the transform's patterns cannot express), defang it structurally.
  //
  // Each probe below is paired with the defang directly beneath it, on purpose. The FIRST version
  // covered only `![` and `](`, which left the sweep's guarantee narrower than the transform it is
  // supposed to backstop: AUTOLINK_RE and AT_TAG_RE were length-bounded, so padding a URL or an
  // attribute run past the bound made the pattern miss and NOTHING downstream defanged it — a
  // clickable link, or a live spoofable mention, straight through. The bounds STAY (removing them
  // turns each pattern quadratic on input with many unterminated starts — measured at 15.9× on the
  // linearity test, against a 4× linear baseline). Closing the bypass is this sweep's job, and it
  // can do it safely because every defang below is a fixed-length prefix match that never scans for
  // a terminator. A probe without a matching defang here is the drift this file has already been
  // bitten by four times.
  if (/!\[/.test(out) || out.includes("](")) {
    out = out.replace(/!\[/g, "[").replace(/\]\(/g, "]（");
  }
  // Any scheme, and now only the residual the bound gives up on — via a fixed-length lookahead, so
  // this cannot corrupt ordinary text the way the previous prefix probe did.
  if (AUTOLINK_OVERLONG.test(out)) {
    out = out.replace(AUTOLINK_OVERLONG_G, "（");
  }
  // Both the opening and the closing form; `</at` does not match `<at\b`, which was one of the
  // earlier gaps in the fast-path discriminator.
  if (AT_TAG_OVERLONG.test(out)) {
    out = out.replace(AT_TAG_OVERLONG_G, "（");
  }
  return out;
}

/**
 * Inline code span. Exempt for exactly the reason a fence is: CardKit renders its contents
 * literally, so nothing inside is clickable, and this product's answers are full of quoted code.
 *
 * Without this exemption the module corrupted the single most common thing this product emits.
 * `` `arr[i](x)` `` came out as `` `arri（x）` `` because LINK_RE reads `[i](x)` as a markdown link —
 * that one is the TRANSFORM over-matching, not the sweep, so tightening the sweep does not reach it;
 * only the exemption does. Comparison operators in a code span were mangled by the sweep on top of
 * that.
 *
 * A CLOSING run of the same length is REQUIRED, for the reason FENCE_RE learned the hard way: if an
 * unterminated opener were honoured, a model could emit one backtick and exempt every construct in
 * the rest of the answer. Unterminated means "not a code span", so it stays prose. Single line only —
 * CommonMark permits a code span to span lines, but accepting that would let one stray backtick
 * swallow paragraphs, and a code span spread over lines is not a shape this product's answers use.
 */
const CODE_SPAN_RE = /(`{1,3})(?!`)[^\n]{0,2000}?\1(?!`)/g;

/**
 * Apply the prose transform to everything EXCEPT inline code spans. Called per non-fenced partition,
 * so the exemption nests inside the fence walk rather than competing with it.
 */
function neutralizeOutsideCodeSpans(s: string): string {
  if (!s.includes("`")) return neutralizeProse(s);
  let out = "";
  let last = 0;
  for (const m of s.matchAll(CODE_SPAN_RE)) {
    const start = m.index ?? 0;
    out += neutralizeProse(s.slice(last, start));
    out += m[0]; // code span verbatim
    last = start + m[0].length;
  }
  out += neutralizeProse(s.slice(last));
  return out;
}

/**
 * Neutralize clickable/auto-loading constructs in model-generated text, leaving
 * fenced code untouched. Idempotent on already-neutralized text (the rewritten forms
 * match none of the patterns).
 */
export function neutralizeModelLinks(text: string): string {
  if (!text) return text;
  // Fast path: nothing clickable at all. These probes must be WIDER than everything below them — the
  // transform AND the sweep — because a miss here returns the text verbatim and neither layer runs.
  // Three such gaps have existed: `<ftp://…>` (AUTOLINK_RE accepted ftp, the old probe tested only
  // https?), a closing-only `</at>` (AT_TAG_RE accepts it, `<at\b` does not match `</at`), and a
  // non-http scheme such as `<gopher://…>`, which silently voided a widening two layers down. Being
  // too wide here is harmless by construction: it costs one pass that finds nothing to do.
  if (!text.includes("](")
    && !ANY_AT_TAG.test(text)
    && !ANY_SCHEME_AUTOLINK.test(text)) return text;

  // Walk the fences, transforming only what sits BETWEEN them.
  let out = "";
  let last = 0;
  for (const m of text.matchAll(FENCE_RE)) {
    const start = m.index ?? 0;
    out += neutralizeOutsideCodeSpans(text.slice(last, start));
    out += m[0]; // fence verbatim
    last = start + m[0].length;
  }
  out += neutralizeOutsideCodeSpans(text.slice(last));
  return out;
}
