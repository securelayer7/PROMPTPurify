/**
 * L5a — zero-dep logistic scorer over the standardized feature vector.
 *
 * Honest: this is a linear model. score = sigmoid(w · z + b) where z is the
 * shipped-mean/std standardized feature vector. It is PROBABILISTIC and
 * advisory; the honesty fusion in src/index.ts guarantees it never clears a
 * structural block and never produces a `.safe` verdict.
 */
import {
  L5A_WEIGHTS,
  L5A_INTERCEPT,
  L5A_MEAN,
  L5A_STD,
  L5A_FEATURE_NAMES,
} from "./weights.gen.js";

function sigmoid(x: number): number {
  if (x >= 0) return 1 / (1 + Math.exp(-x));
  const e = Math.exp(x);
  return e / (1 + e);
}

/** Standardize with the shipped mean/std (zero-variance guard). */
export function standardize(vec: number[]): number[] {
  return vec.map((v, i) => {
    const sd = L5A_STD[i] || 1;
    return (v - (L5A_MEAN[i] ?? 0)) / sd;
  });
}

/** Injection/jailbreak probability in [0,1]. */
export function score(vec: number[]): number {
  const z = standardize(vec);
  let s = L5A_INTERCEPT;
  for (let i = 0; i < L5A_WEIGHTS.length; i++)
    s += (L5A_WEIGHTS[i] ?? 0) * (z[i] ?? 0);
  return sigmoid(s);
}

/**
 * Human-readable top-3 contributing features (signed standardized
 * contribution w_i * z_i). For the `semantic-jailbreak` risk message.
 */
export function reason(vec: number[]): string {
  const z = standardize(vec);
  const contribs = L5A_WEIGHTS.map((w, i) => ({
    name: L5A_FEATURE_NAMES[i] ?? `f${i}`,
    c: w * (z[i] ?? 0),
  }))
    .filter((x) => Number.isFinite(x.c) && x.c > 0)
    .sort((a, b) => b.c - a.c)
    .slice(0, 3);
  if (contribs.length === 0) return "no positive contributing feature";
  return contribs
    .map((x) => `${x.name} (+${x.c.toFixed(2)})`)
    .join(", ");
}
