/**
 * L5a → L5b confidence-gated CASCADE.
 *
 * Implements the APPROVED routing as a single `Classifier` (the existing
 * src/index.ts hook): the caller already ran L1 normalize + L4 tripwires and
 * passes ALREADY-SANITIZED text (Classifier contract). Here we:
 *
 *   1. L5a fast logistic (existing, sub-ms, zero-dep) -> s_a
 *   2. EARLY EXIT:
 *        s_a < allowBelow (default 0.05)  ⇒ ALLOW  — return s_a, L5b NOT run
 *        s_a > blockAbove (default 0.95)  ⇒ BLOCK  — return s_a, L5b NOT run
 *      Most real traffic is confidently benign or blatant and exits here
 *      (cheap). L5b only fires on the AMBIGUOUS MIDDLE band.
 *   3. AMBIGUOUS: run L5b (our distilled tiny transformer) -> s_b, then a
 *      CONFIDENCE-GATED union fusion:
 *        w     = clamp((s_a - allowBelow) / (0.5 - allowBelow), 0, 1)
 *        score = min(1, s_a + (1 - s_a) * s_b * gate * w)
 *      Properties (all honest, all enforced here):
 *        • Monotone in s_a and s_b, and >= s_a ALWAYS — L5b can only
 *          ESCALATE, never lower L5a's signal (a probabilistic model must
 *          never *clear*).
 *        • The L5b lift is GATED by how suspicious L5a already is: near the
 *          allow floor (w→0) L5b barely moves the score, so a benign input
 *          that merely grazes the band is NOT dragged to a block by a noisy
 *          transformer (this is what keeps benign FPR flat — incl. the
 *          inherited teacher weakness on "ignore the previous email…").
 *        • Once L5a is genuinely uncertain (s_a ≥ 0.5, w=1) L5b gets full
 *          weight and adds real lift on the semantic/paraphrase slice L5a
 *          alone scores too low to flag.
 *
 * HONESTY (unchanged from L5a; restated):
 *   • Returns the EXISTING ClassifierResult shape (+ non-breaking diagnostics
 *     stage/confidence/reason, exactly as L5aResult already does).
 *   • Plugs into createPromptPurify({ classifier: createL5Cascade() }) with
 *     ZERO changes to inspectAsync honesty fusion.
 *   • If L5b is unavailable (no onnxruntime-node / no artifact) the cascade
 *     RE-THROWS so the EXISTING classifier-error path in inspectAsync turns
 *     it into an `info` risk. Degraded — NEVER false-safe. We deliberately do
 *     NOT swallow it and silently return the L5a score, because on the
 *     ambiguous band a missing semantic check must be surfaced, not hidden.
 *   • Advisory only; never clears a structural block (enforced by the
 *     existing fusion — this file only produces numbers).
 */
import type { Classifier, ClassifierResult, Sink } from "../types.js";
import { BUILTIN_RULES, runTripwires } from "../rules.js";
import { extractFeatures } from "./features.js";
import { score as scoreVec, reason } from "./scorer.js";
import { L5A_VERSION } from "./weights.gen.js";
import {
  createL5bRunner,
  L5bUnavailableError,
  type L5bRunner,
  type L5bOptions,
} from "./transformer.js";
import { createL5cRunner, type L5cRunner } from "./l5c.js";
import { createL5dRunner, type L5dRunner } from "./l5d.js";
import { createL5eRunner, type L5eRunner } from "./l5e.js";

export interface L5CascadeOptions extends L5bOptions {
  /**
   * SHIPPED DEFAULT = false ⇒ L5a-ONLY tier ("fast"): L5b is NOT invoked,
   * even on the ambiguous band; the cascade returns the calibrated L5a
   * score directly. This is the coherent shipped v3 configuration.
   *
   * WHY OFF BY DEFAULT (honest): v3 ships a REAL-DATA-trained L5a
   * (`l5a-v3-real-*`). The committed L5b ONNX is still SYNTHETIC-distilled
   * (the real redistill is host-blocked — see training/V3_RESULTS.md §4).
   * The cascade's confidence-gated fusion was calibrated against the OLD
   * synthetic L5a's score distribution; pairing real-L5a with the
   * mismatched synthetic L5b is PROVEN-INCOHERENT (it over-fires on the
   * curated hard-negatives — V3_RESULTS.md §3). So the DEFAULT path is
   * L5a-only and fully coherent: honesty contract intact (never clears a
   * block — enforced by src/index.ts fusion, unchanged), structural blocks
   * stay blocked, and a missing/disabled L5b is NEVER a false-safe because
   * L5a alone always produces a real advisory score on every input.
   *
   * Set `enableL5b: true` to OPT IN to the experimental L5a→L5b cascade
   * (synthetic L5b; only sensible once a matched real L5b is redistilled).
   */
  enableL5b?: boolean;
  /**
   * STAGE-5 OPT-IN: use the strictly-from-scratch L5c model (random-init
   * Transformer + train-fit byte-BPE, NO pretrained weights of any kind)
   * as the ambiguous-band escalator INSTEAD of the distilled L5b. Default
   * false. Requires `enableL5b: true` to take effect (it shares the exact
   * same confidence-gated escalation path; only the runner differs). The
   * SHIPPED L5a-only default and src/index.ts honesty fusion are
   * UNCHANGED. Honesty contract identical: probabilistic, advisory only,
   * never clears a structural block, never `.safe`.
   */
  l5cFromScratch?: boolean;
  /**
   * STAGE-7 OPT-IN: use the "intelligent" L5d model
   * (`distilbert-base-multilingual-cased`, Apache-2.0, fine-tuned on our
   * full seeded leakage-free corpus) as the ambiguous-band escalator
   * INSTEAD of L5b/L5c. Default false. Requires `enableL5b: true` to take
   * effect (it shares the EXACT same confidence-gated escalation path;
   * only the runner differs). Takes precedence over `l5cFromScratch` if
   * both are set. The SHIPPED L5a-only default and src/index.ts honesty
   * fusion are UNCHANGED. Honesty contract identical: probabilistic,
   * advisory only, never clears a structural block, never `.safe`.
   */
  l5dIntelligent?: boolean;
  /**
   * STAGE-9 OPT-IN: use the "100% OURS" L5e model — OUR OWN ELECTRA-small
   * self-pretrained from random init (no teacher, no downloaded weights)
   * on permissive open corpora + OUR own 32k WordPiece, fine-tuned on our
   * seeded leakage-free corpus — as the ambiguous-band escalator INSTEAD
   * of L5b/L5c/L5d. Default false. Requires `enableL5b: true` to take
   * effect (it shares the EXACT same confidence-gated escalation path;
   * only the runner differs). Takes precedence over `l5dIntelligent` /
   * `l5cFromScratch` if multiple are set. The SHIPPED L5a-only default and
   * src/index.ts honesty fusion are UNCHANGED. Honesty contract identical:
   * probabilistic, advisory only, never clears a structural block, never
   * `.safe`. See training/PRETRAIN_PLAN.md + training/INTEGRATION.md.
   */
  l5eOwn?: boolean;
  /**
   * s_a strictly below this ⇒ confident ALLOW, L5b skipped. Default 0.15
   * (below the in-repo corpus positive-class minimum ≈0.146; the bulk of
   * benign mass sits at L5a p50 ≈0.086 and early-exits cleanly here).
   * Only meaningful when `enableL5b` is true.
   */
  allowBelow?: number;
  /** s_a strictly above this ⇒ confident BLOCK, L5b skipped. Default 0.95. */
  blockAbove?: number;
  /** Outer weight on the L5b term in the gated-union fusion. Default 1. */
  l5bGate?: number;
  /** Attach the human reason string (non-breaking). Default true. */
  withReason?: boolean;
  /**
   * Test/observability hook: invoked with the routing decision on every
   * call. NOT part of the contract; never affects the score.
   */
  onRoute?: (r: L5RouteInfo) => void;
}

export type L5Stage = "l5a-allow" | "l5a-block" | "l5b-escalated";

export interface L5RouteInfo {
  stage: L5Stage;
  /** L5a fast score. */
  l5a: number;
  /** L5b score, only present when escalated. */
  l5b?: number;
  /** Whether L5b actually ran this call. */
  l5bInvoked: boolean;
}

/** Extra (non-breaking) diagnostics carried alongside ClassifierResult. */
export interface L5CascadeResult extends ClassifierResult {
  reason?: string;
  version?: string;
  /** Which cascade stage produced the score (advisory diagnostic). */
  stage?: L5Stage;
  /** Routing confidence detail (advisory diagnostic). */
  route?: L5RouteInfo;
}

/**
 * Build the cascading `Classifier`. The L5b runner is created lazily on the
 * first ambiguous input (no startup cost / no failure for callers whose
 * traffic all early-exits at L5a).
 */
export function createL5Cascade(opts: L5CascadeOptions = {}): Classifier {
  const enableL5b = opts.enableL5b === true;
  const allowBelow = opts.allowBelow ?? 0.15;
  const blockAbove = opts.blockAbove ?? 0.95;
  const gate = opts.l5bGate ?? 1;
  const withReason = opts.withReason !== false;

  const useL5e = opts.l5eOwn === true;
  const useL5d = !useL5e && opts.l5dIntelligent === true;
  const useL5c = !useL5e && !useL5d && opts.l5cFromScratch === true;
  let runnerPromise: Promise<
    L5bRunner | L5cRunner | L5dRunner | L5eRunner
  > | null = null;
  const getRunner = () =>
    (runnerPromise ??= useL5e
      ? createL5eRunner(opts)
      : useL5d
        ? createL5dRunner(opts)
        : useL5c
          ? createL5cRunner(opts)
          : createL5bRunner(opts));

  return async (
    text: string,
    _ctx: { sink: Sink },
  ): Promise<L5CascadeResult> => {
    // Sanitized text in (Classifier contract). Recover L4 fired ids — SAME
    // runtime path as L5a, no train/serve skew.
    const fired = runTripwires(text, BUILTIN_RULES).map((r) => r.rule);
    const { vec } = extractFeatures(text, fired);
    const sA = scoreVec(vec);

    // ---- SHIPPED DEFAULT: L5a-only tier -----------------------------------
    // L5b disabled (default). Return the calibrated real-data L5a score
    // directly — a complete advisory signal. No L5b is constructed, so a
    // missing/synthetic ONNX artifact is irrelevant and CANNOT cause a
    // false-safe (L5a always scores). Honesty fusion in src/index.ts
    // (unchanged) still guarantees this never clears a structural block.
    // Stage keyed on the 0.5 positive-class boundary (advisory diagnostic).
    if (!enableL5b) {
      const stage: L5Stage = sA >= 0.5 ? "l5a-block" : "l5a-allow";
      const route: L5RouteInfo = { stage, l5a: sA, l5bInvoked: false };
      opts.onRoute?.(route);
      const res: L5CascadeResult = {
        score: sA,
        label: sA >= 0.5 ? "INJECTION" : "SAFE",
        version: `cascade(${L5A_VERSION};l5a-only)`,
        stage,
        route,
      };
      if (withReason) res.reason = reason(vec);
      return res;
    }

    // ---- early-exit gating (opt-in L5b path only) -------------------------
    if (sA < allowBelow || sA > blockAbove) {
      const stage: L5Stage = sA < allowBelow ? "l5a-allow" : "l5a-block";
      const route: L5RouteInfo = { stage, l5a: sA, l5bInvoked: false };
      opts.onRoute?.(route);
      const res: L5CascadeResult = {
        score: sA,
        label: sA >= 0.5 ? "INJECTION" : "SAFE",
        version: `cascade(${L5A_VERSION})`,
        stage,
        route,
      };
      if (withReason) res.reason = reason(vec);
      return res;
    }

    // ---- ambiguous middle band: escalate to L5b ---------------------------
    // A failure here (missing onnxruntime / artifact) is RE-THROWN so the
    // existing inspectAsync catch turns it into a classifier-error info
    // risk. We must NOT silently fall back to s_a on the band where the
    // semantic check actually matters — that would be a false-safe.
    let runner: L5bRunner | L5cRunner | L5dRunner | L5eRunner;
    try {
      runner = await getRunner();
    } catch (e) {
      runnerPromise = null; // allow retry on a later call
      if (e instanceof L5bUnavailableError) throw e;
      throw new L5bUnavailableError("L5b runner init failed", e);
    }
    const sB = await runner.score(text);

    // Confidence-gated union: monotone, always >= sA (never clears), and the
    // L5b lift is suppressed near the allow floor so a noisy transformer
    // cannot drag a barely-suspicious benign input into a block.
    const w = Math.max(
      0,
      Math.min(1, (sA - allowBelow) / (0.5 - allowBelow)),
    );
    const fused = Math.min(1, sA + (1 - sA) * sB * gate * w);
    const route: L5RouteInfo = {
      stage: "l5b-escalated",
      l5a: sA,
      l5b: sB,
      l5bInvoked: true,
    };
    opts.onRoute?.(route);
    const res: L5CascadeResult = {
      score: fused,
      label: fused >= 0.5 ? "INJECTION" : "SAFE",
      version: `cascade(${L5A_VERSION}+${runner.version})`,
      stage: "l5b-escalated",
      route,
    };
    if (withReason)
      res.reason = `l5a=${sA.toFixed(2)} l5b=${sB.toFixed(2)} | ${reason(vec)}`;
    return res;
  };
}
