/**
 * promptpurify — structural prompt firewall.
 *
 * Philosophy (DOMPurify, honestly ported):
 *   • Whitelist/parse  -> impossible for natural language. We instead change
 *     REPRESENTATION (L2 nonce fencing) so untrusted text has no authority.
 *   • Deterministic    -> L1 normalize + L2 structure are pure & idempotent.
 *   • Context-aware    -> L3 sink policy (the HTML-body vs attr vs URL analog).
 *   • No false safety  -> there is NO `.safe` boolean. Semantic jailbreaks
 *     (persona/fiction/crescendo) are FLAGGED, never cleared. Documented gap.
 */
import type {
  ChatMessage,
  InspectReport,
  MessageParts,
  Profile,
  PurifyConfig,
  Risk,
  Sink,
} from "./types.js";
import { normalize, normalizationModified } from "./normalize.js";
import { BUILTIN_RULES, runTripwires } from "./rules.js";
import { buildMessages, defuseTemplateTokens } from "./structure.js";

export * from "./types.js";
export { buildMessages } from "./structure.js";

const DEFAULTS: Required<
  Omit<PurifyConfig, "extraRules" | "sink" | "classifier" | "classifierThreshold">
> = {
  profile: "balanced",
  stripTemplateTokens: true,
  maxLength: 0,
};

// L3 — per-sink policy. trusted_instruction keeps its authority; everything
// else is treated as inert data and template tokens are defused.
function sinkPolicy(sink: Sink): {
  fold: boolean;
  defuse: boolean;
  blockInstructionShape: boolean;
  canonWs: boolean;
} {
  switch (sink) {
    case "trusted_instruction":
      return { fold: false, defuse: false, blockInstructionShape: false, canonWs: false };
    case "untrusted_data":
    case "tool_output":
    case "rag_chunk":
      return { fold: true, defuse: true, blockInstructionShape: true, canonWs: true };
  }
}

export function createPromptPurify(config: PurifyConfig = {}) {
  const cfg = { ...DEFAULTS, ...config };
  const rules = [...BUILTIN_RULES, ...(config.extraRules ?? [])];

  /** DOMPurify-parity: dirty string in, normalized string out (L1 + defuse). */
  function sanitize(dirty: string, opts: { sink?: Sink } = {}): string {
    if (cfg.profile === "off") return dirty;
    const sink = opts.sink ?? config.sink ?? "untrusted_data";
    const pol = sinkPolicy(sink);
    const { text } = normalize(dirty, {
      foldHomoglyphs: pol.fold,
      canonicalizeWhitespace: pol.canonWs,
      maxLength: cfg.maxLength,
    });
    return pol.defuse
      ? defuseTemplateTokens(text, cfg.stripTemplateTokens)
      : text;
  }

  /** Full L1+L2+L3+L4 with an honest verdict + risk report. */
  function inspect(
    dirty: string,
    opts: { sink?: Sink } = {},
  ): InspectReport {
    const sink = opts.sink ?? config.sink ?? "untrusted_data";
    const pol = sinkPolicy(sink);

    const { text: normalized, report } = normalize(dirty, {
      foldHomoglyphs: pol.fold,
      canonicalizeWhitespace: pol.canonWs,
      maxLength: cfg.maxLength,
    });
    const text = pol.defuse
      ? defuseTemplateTokens(normalized, cfg.stripTemplateTokens)
      : normalized;

    // Tripwires run on the PRE-defuse text: defuse is a mitigation that
    // strips the very evidence (chat-template/role tokens) the rules look
    // for, so scanning the defused text made role-token-spoof a dead rule
    // for exactly the untrusted sinks where it matters. Detection must see
    // the original threat; the returned `text` stays defused (safe).
    const risks: Risk[] =
      cfg.profile === "off" ? [] : runTripwires(normalized, rules);

    const modified = normalizationModified(report) || text !== normalized;

    // "blocked" is reserved for HARD structural violations: untrusted text
    // carrying instruction-shaped attacks into a sink that must stay inert.
    const hardStructural =
      pol.blockInstructionShape &&
      risks.some(
        (r) =>
          r.severity === "high" &&
          (r.rule === "instruction-override" ||
            r.rule === "role-token-spoof" ||
            r.rule === "role-reassignment" ||
            r.rule === "system-prompt-leak"),
      );

    const verdict: InspectReport["verdict"] = hardStructural
      ? "blocked"
      : risks.length > 0
        ? "flagged"
        : "clean-structural"; // structural only — NOT "safe"

    return { text, risks, modified, normalization: report, verdict, sink };
  }

  /**
   * L5 — deterministic inspect THEN optional probabilistic classifier.
   * The classifier only ADDS a semantic risk; it never clears one and
   * never yields a `.safe`. A structural "blocked" stays blocked.
   */
  async function inspectAsync(
    dirty: string,
    opts: { sink?: Sink } = {},
  ): Promise<InspectReport> {
    const base = inspect(dirty, opts);
    const clf = config.classifier;
    if (!clf || cfg.profile === "off") return base;

    let result;
    try {
      result = await clf(base.text, { sink: base.sink });
    } catch {
      // Classifier failure must not produce a false sense of safety:
      // surface it as an info risk, keep the deterministic verdict.
      return {
        ...base,
        risks: [
          ...base.risks,
          {
            rule: "classifier-error",
            message: "L5 classifier failed; semantic check NOT performed.",
            severity: "info",
          },
        ],
      };
    }

    // v3 VAL-CALIBRATED default operating point. Re-derived on the
    // seed-1337 `val` split ONLY (n=2121; scripts/sweep-val.mjs): argmax
    // L5a recall s.t. val benign-FPR <= 0.029 (the prior cascade's val
    // ceiling — no FP regression), tie-break max(recall-FPR) then larger
    // threshold. The frozen `test` and the UNSEEN benchmark were NOT read
    // during selection. Chosen = 0.445 (val recall 0.825, val benign-FPR
    // 0.0275, Wilson-95% CI [0.0210, 0.0359]). See training/V3_RESULTS.md
    // "v3 SHIPPED — val-calibrated threshold".
    //
    // HONESTY-PRESERVING: this is the SAME single `classifierThreshold`
    // constant the code already consumed; ZERO fusion-logic bytes changed.
    // Lowering it can only ADD a semantic risk, never clear one — the
    // `verdict === "blocked"` carry-forward below is unchanged, so a
    // structural block still stays blocked, and a missing/failed model
    // still becomes a `classifier-error` info risk (never false-safe).
    // NON-CLASSIFIER USERS ARE BYTE-UNAFFECTED: with no classifier wired,
    // inspectAsync returns `base` at the `if (!clf …)` guard ABOVE, before
    // this constant is ever read.
    const threshold = cfg.classifierThreshold ?? 0.445;
    if (result.score < threshold) return base;

    const risks: Risk[] = [
      ...base.risks,
      {
        rule: "semantic-jailbreak",
        message: `Classifier flagged likely injection/jailbreak (score=${result.score.toFixed(
          2,
        )}${result.label ? `, label=${result.label}` : ""}).`,
        severity: result.score >= 0.95 ? "high" : "warn",
      },
    ];
    return {
      ...base,
      risks,
      verdict: base.verdict === "blocked" ? "blocked" : "flagged",
    };
  }

  return {
    sanitize,
    inspect,
    inspectAsync,
    buildMessages,
    profile: cfg.profile as Profile,
  };
}

/** Default instance — `import { promptpurify } from "promptpurify"`. */
export const promptpurify = createPromptPurify();

/**
 * Output-side guard (category G). Strips/declaws exfiltration sinks the
 * model may have been tricked into emitting: auto-rendered markdown images
 * and tracking links pointing at external URLs.
 */
export function purifyOutput(
  modelText: string,
  opts: { allowHosts?: string[] } = {},
): { text: string; removed: number } {
  let removed = 0;
  const allow = new Set((opts.allowHosts ?? []).map((h) => h.toLowerCase()));

  const allowed = (url: string): boolean => {
    try {
      return allow.has(new URL(url).host.toLowerCase());
    } catch {
      return false;
    }
  };

  // Neutralize markdown images: ![alt](http...) -> `[image removed]`
  let text = modelText.replace(
    /!\[[^\]]*\]\(\s*(https?:\/\/[^)\s]+)[^)]*\)/gi,
    (m, url: string) => {
      if (allowed(url)) return m;
      removed++;
      return "[image removed: external exfil sink]";
    },
  );

  // Defang query-string tracking links: [t](http://x/?leak=..) -> plain text
  text = text.replace(
    /\[([^\]]+)\]\(\s*(https?:\/\/[^)\s]*\?[^)]*)\)/gi,
    (m, label: string, url: string) => {
      if (allowed(url)) return m;
      removed++;
      return `${label} (link removed)`;
    },
  );

  return { text, removed };
}

export type { ChatMessage, MessageParts };
