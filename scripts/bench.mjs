#!/usr/bin/env node
/**
 * Public benchmark script.
 *
 *   node scripts/bench.mjs                              # uses the shipped frozen eval slice
 *   node scripts/bench.mjs path/to/your.jsonl          # score your own data
 *   node scripts/bench.mjs --threshold 0.95            # pick a threshold (default 0.95)
 *   node scripts/bench.mjs --behavior <name>           # filter to a single behavior tag
 *   node scripts/bench.mjs --by-behavior               # per-behavior breakdown
 *
 * Input JSONL: one object per line, {"text": "...", "y": 0|1, "behavior"?: "..."}
 *   y=1 attack, y=0 benign.
 *
 * Output: recall / FPR / per-tier counts. With --by-behavior, also per-class
 * recall sorted by sample count.
 *
 * Reproducible by anyone who clones the repo.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

let createL5eRunner;
try {
  ({ createL5eRunner } = require("../dist/l5/index.cjs"));
} catch (e) {
  console.error(
    "ERROR: dist/ not built. Run `npm run build` first, then re-run bench.\n",
  );
  process.exit(1);
}

const __dir = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dir, "..");
const MODEL_DIR = path.join(ROOT, "models", "l5e");
const DEFAULT_INPUT = path.join(
  ROOT,
  "training",
  "FROZEN_EVAL_SCORED.jsonl",
);

function parseArgs(argv) {
  const args = {
    input: DEFAULT_INPUT,
    threshold: 0.95,
    behavior: null,
    byBehavior: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--threshold" || a === "-t") {
      args.threshold = Number(argv[++i]);
    } else if (a === "--behavior" || a === "-b") {
      args.behavior = argv[++i];
    } else if (a === "--by-behavior") {
      args.byBehavior = true;
    } else if (a === "--help" || a === "-h") {
      console.log(
        "usage: node scripts/bench.mjs [path.jsonl]\n" +
          "       [--threshold 0.95] [--behavior <name>] [--by-behavior]",
      );
      process.exit(0);
    } else if (!a.startsWith("-")) {
      args.input = a;
    }
  }
  return args;
}

function* readJsonl(p) {
  const txt = fs.readFileSync(p, "utf8");
  for (const line of txt.split(/\r?\n/)) {
    const s = line.trim();
    if (!s) continue;
    yield JSON.parse(s);
  }
}

function fmt(n, d = 2) {
  return (n * 100).toFixed(d) + "%";
}

async function main() {
  const { input, threshold, behavior, byBehavior } = parseArgs(process.argv);
  console.log(
    `bench: input=${path.relative(ROOT, input)} threshold=${threshold}` +
      (behavior ? ` behavior=${behavior}` : "") +
      (byBehavior ? " mode=by-behavior" : ""),
  );

  const t0 = Date.now();
  const guard = await createL5eRunner({ modelDir: MODEL_DIR });
  console.log(`bench: model loaded in ${Date.now() - t0} ms\n`);

  let nAtk = 0;
  let nBen = 0;
  let blockedAtk = 0;
  let blockedBen = 0;
  let advAtk = 0;
  let advBen = 0;
  const latencies = [];
  // behavior -> { n, blocked, y }
  const perBehavior = new Map();

  for (const row of readJsonl(input)) {
    const y = row.y ?? (row.ground_truth === "attack" || row.ground_truth === "harmful" ? 1 : 0);
    const t = row.text;
    if (typeof t !== "string") continue;
    const b = row.behavior ?? "(untagged)";
    if (behavior && b !== behavior) continue;
    const t1 = Date.now();
    const score = await guard.score(t);
    latencies.push(Date.now() - t1);
    const blocked = score >= threshold;
    const advisory = !blocked && score >= 0.85;
    if (y === 1) {
      nAtk++;
      if (blocked) blockedAtk++;
      if (advisory) advAtk++;
    } else {
      nBen++;
      if (blocked) blockedBen++;
      if (advisory) advBen++;
    }
    if (byBehavior) {
      const e = perBehavior.get(b) ?? { n: 0, blocked: 0, y };
      e.n += 1;
      if (blocked) e.blocked += 1;
      e.y = y;
      perBehavior.set(b, e);
    }
  }

  const recall = nAtk ? blockedAtk / nAtk : 0;
  const fpr = nBen ? blockedBen / nBen : 0;
  const advRate = nBen ? advBen / nBen : 0;
  latencies.sort((a, b) => a - b);
  const p50 = latencies[Math.floor(latencies.length * 0.5)] ?? 0;
  const p95 = latencies[Math.floor(latencies.length * 0.95)] ?? 0;

  console.log("                attacks (y=1)   benign (y=0)");
  console.log(`  blocked       ${String(blockedAtk).padStart(13)}   ${String(blockedBen).padStart(12)}`);
  console.log(`  advisory      ${String(advAtk).padStart(13)}   ${String(advBen).padStart(12)}`);
  console.log(`  pass          ${String(nAtk - blockedAtk - advAtk).padStart(13)}   ${String(nBen - blockedBen - advBen).padStart(12)}`);
  console.log(`  total         ${String(nAtk).padStart(13)}   ${String(nBen).padStart(12)}\n`);

  console.log(`attack recall  (block tier):  ${fmt(recall)}`);
  console.log(`benign FPR     (block tier):  ${fmt(fpr)}`);
  console.log(`benign advisory rate         :  ${fmt(advRate)}`);
  console.log(`latency p50 / p95            :  ${p50} ms / ${p95} ms`);

  if (byBehavior) {
    console.log("\nper-behavior (y=1 → recall, y=0 → FPR), top 20 by n:");
    const rows = [...perBehavior.entries()]
      .map(([k, v]) => ({ k, ...v, rate: v.n ? v.blocked / v.n : 0 }))
      .sort((a, b) => b.n - a.n)
      .slice(0, 20);
    for (const r of rows) {
      const tag = r.y === 1 ? "atk" : "ben";
      console.log(`  ${tag}  n=${String(r.n).padStart(3)}  ${fmt(r.rate).padStart(7)}   ${r.k}`);
    }
  }

  if (input === DEFAULT_INPUT && !behavior && !byBehavior) {
    console.log(
      "\nNote: the shipped eval slice is deliberately hard (curated " +
        "borderline cases). Run with --by-behavior for per-class detail.",
    );
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
