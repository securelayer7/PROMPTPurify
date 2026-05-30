/**
 * L5a — context-aware prompt-injection scorer. OUR model (our features, our
 * trained weights), pure TS, zero deps, sub-millisecond, offline, in-process.
 *
 * It conforms EXACTLY to the existing `Classifier` contract in src/index.ts:
 *   (text, { sink }) => { score, label? }
 * so `createPromptPurify({ classifier: createL5aClassifier() })` plugs into
 * the existing `inspectAsync` honesty fusion with ZERO changes to index.ts.
 *
 * Honesty contract (enforced by the existing fusion, restated here):
 *   • PROBABILISTIC — paraphrase-evadable, false +/- exist.
 *   • ADVISORY ONLY — it ADDS a risk; it never clears one.
 *   • The caller passes ALREADY-SANITIZED text (Classifier contract). L5a
 *     does NOT recompute L1. It re-runs ONLY the L4 tripwires on that
 *     sanitized text to recover the fired-rule-id features (no train/serve
 *     skew: scripts/train-l5a.mjs uses this same path).
 */
import type { Classifier, ClassifierResult, Sink } from "../types.js";
import { BUILTIN_RULES, runTripwires } from "../rules.js";
import { extractFeatures } from "./features.js";
import { score as scoreVec, reason } from "./scorer.js";
import { L5A_VERSION } from "./weights.gen.js";

export interface L5aOptions {
  /**
   * If true, also returns the human reason string on the result under a
   * non-breaking extra field. Default true. Never affects the contract.
   */
  withReason?: boolean;
}

/** Extra (non-breaking) diagnostics carried alongside ClassifierResult. */
export interface L5aResult extends ClassifierResult {
  /** Top contributing features (advisory diagnostics only). */
  reason?: string;
  /** Model version that produced the score. */
  version?: string;
}

/**
 * Build a `Classifier` backed by the trained L5a model. Drop into
 * `createPromptPurify({ classifier: createL5aClassifier() })`.
 */
export function createL5aClassifier(opts: L5aOptions = {}): Classifier {
  const withReason = opts.withReason !== false;
  return (text: string, _ctx: { sink: Sink }): L5aResult => {
    // Sanitized text in (per Classifier contract). Recover L4 fired ids.
    const fired = runTripwires(text, BUILTIN_RULES).map((r) => r.rule);
    const { vec } = extractFeatures(text, fired);
    const s = scoreVec(vec);
    const result: L5aResult = {
      score: s,
      label: s >= 0.5 ? "INJECTION" : "SAFE",
      version: L5A_VERSION,
    };
    if (withReason) result.reason = reason(vec);
    return result;
  };
}

/**
 * Internal: sanitized text -> { vec, fired, names } using the EXACT runtime
 * path (same runTripwires + extractFeatures the Classifier uses). Exported
 * so scripts/train-l5a.mjs has zero train/serve skew without widening the
 * core public API. Not part of the supported surface.
 */
export function _featurize(sanitizedText: string): {
  vec: number[];
  names: string[];
  fired: string[];
} {
  const fired = runTripwires(sanitizedText, BUILTIN_RULES).map((r) => r.rule);
  const { vec, names } = extractFeatures(sanitizedText, fired);
  return { vec, names, fired };
}

export { extractFeatures } from "./features.js";
export { score, reason, standardize } from "./scorer.js";
export { L5A_VERSION } from "./weights.gen.js";

// L5b distilled transformer + the L5a→L5b confidence-gated cascade (v2).
// Opt-in: only this subpath touches ONNX; core stays zero-dep + model-free.
export {
  createL5Cascade,
  type L5CascadeOptions,
  type L5CascadeResult,
  type L5RouteInfo,
  type L5Stage,
} from "./cascade.js";
export {
  createL5bRunner,
  L5bUnavailableError,
  type L5bOptions,
  type L5bRunner,
} from "./transformer.js";
// STAGE-5 strictly-from-scratch L5c (opt-in only; see cascade
// `l5cFromScratch`). Shipped default + src/index.ts fusion UNCHANGED.
export {
  createL5cRunner,
  type L5cOptions,
  type L5cRunner,
} from "./l5c.js";
// STAGE-7 "intelligent" L5d: fine-tuned pretrained Apache-2.0 backbone
// (distilbert-base-multilingual-cased). Opt-in only (cascade
// `l5dIntelligent`). Shipped L5a-only default + src/index.ts honesty
// fusion UNCHANGED. See training/RESEARCH.md + training/INTEGRATION.md.
export {
  createL5dRunner,
  type L5dOptions,
  type L5dRunner,
} from "./l5d.js";
// STAGE-9 "100% OURS" L5e: OUR OWN ELECTRA-small self-pretrained from
// random init (no teacher, no downloaded weights) on permissive open
// corpora + OUR own 32k WordPiece, fine-tuned on our seeded leakage-free
// corpus. Opt-in only (cascade `l5eOwn`). Shipped L5a-only default +
// src/index.ts honesty fusion UNCHANGED. See training/PRETRAIN_PLAN.md +
// training/INTEGRATION.md.
export {
  createL5eRunner,
  type L5eOptions,
  type L5eRunner,
} from "./l5e.js";
