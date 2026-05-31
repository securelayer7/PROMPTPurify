# Benchmarks

How we compare promptpurify to OSS prompt-injection guardrails on the
same inputs with the same scoring code. **Reproducible** — see
[REPRODUCE.md](REPRODUCE.md).

## Threat model

promptpurify is a **prompt-injection guardrail**: untrusted user input
or retrieved data trying to overwrite the system instruction,
exfiltrate secrets, or hijack tool calls.

It is **not**:

- A jailbreak / harmful-content detector (HarmBench, JailbreakBench,
  HELM-Safety measure that — different threat model).
- An agentic-harm detector (AgentHarm measures multi-step tool abuse;
  pair us with per-tool scoping).
- A general LLM-robustness benchmark (PromptBench measures task
  accuracy under perturbation, not safety).

If you see a "guardrail benchmark" number quoted at you, the first
question is which of those it actually measures.

## Methodology

- **Threshold-neutral.** Every model evaluated at its own published
  default. No model brings its own preferred harness.
- **Same inputs, same scoring code.** A single bench script loads
  each model and scores the same JSONL inputs.
- **Held-outs are real held-outs.** Hash-bucketed splits; the
  evaluation slices were never seen by our model at training time.
  The OSS baselines may have seen the same upstream public data, so
  treat shared-corpus rows as "comparable on the same eval" rather
  than "unseen by everyone".

## Comparison

We benchmark against the OSS baselines named in
[`training/CORPUS_LICENSES.json`](../training/CORPUS_LICENSES.json) on
the same inputs with the same scoring code. The headline tradeoff: an
order-of-magnitude smaller model that runs on CPU, in-process, at
competitive recall and false-positive rates.

Reproduce in two commands:

```bash
node scripts/bench.mjs                  # promptpurify on the eval slice
python3 scripts/bench_oss.py            # OSS baselines on the same slice
```

Full recipe: [REPRODUCE.md](REPRODUCE.md).

## Results

Same eval slice (`training/FROZEN_EVAL_SCORED.jsonl`, 791 attacks /
132 benigns), same scoring code (`scripts/bench_oss.py`), each model
at its published default threshold and at a cross-model neutral
`0.5`.

Header arrows show the direction of merit (recall higher = better,
FPR lower = better). Per cell: ↑ = top-tier on this axis, ↓ =
bottom-tier, blank = mid.

| Model | recall@default ↑ | FPR@default ↓ | recall@0.5 ↑ | FPR@0.5 ↓ |
|---|---:|---:|---:|---:|
| **promptpurify** | **83.94% ↑** | **10.61% ↑** | **87.10% ↑** | **12.88% ↑** |
| ProtectAI v2 | 40.71% ↓ | 43.18% ↓ | 40.71% ↓ | 43.18% ↓ |
| deepset | 97.22% ↑ | 59.85% ↓ | 97.22% ↑ | 59.85% ↓ |
| fmops | 100.00% ↑ | 100.00% ↓ | 100.00% ↑ | 100.00% ↓ |
| Meta Prompt-Guard | 67.00% | 88.64% ↓ | 67.00% | 88.64% ↓ |
| Meta Prompt-Guard-2 | 12.77% ↓ | 1.52% ↑ | 12.77% ↓ | 1.52% ↑ |

`promptpurify` is the only row with ↑ on every column. `fmops` "wins"
recall by predicting positive for every input — its FPR ↓ shows it's
mis-calibrated, not skilled. `Meta Prompt-Guard-2` flips the trade:
nearly-zero FPR at the cost of catching ~1 in 8 attacks.

How to read this:

- `promptpurify` ships at `0.95`; everything else ships at `0.5`.
- Lower FPR than every other model except Prompt-Guard-2, which buys
  its low FPR by recalling only 12.77% of attacks (≈1 in 8).
- Higher recall than ProtectAI v2, Prompt-Guard, and Prompt-Guard-2
  on this slice. `deepset` reaches higher recall but at ~6x the FPR
  (60% of benigns blocked); for most production traffic that's worse,
  not better.
- `fmops` predicts the positive class for every input on this slice.
  Treat the row as evidence the model is mis-calibrated for this
  distribution, not as a real recall claim.
- `Meta Prompt-Guard` is a 3-class model; we score it as
  `P(INJECTION) + P(JAILBREAK)` (see `scripts/bench_oss.py`).

The slice is deliberately hard — curated borderline cases, not a
naturally-distributed sample. Numbers should be read as "relative
behavior at the decision boundary", not as production recall on your
traffic. Pick a threshold against your own data ([Operating
points](#operating-points)).

## Operating points

The right threshold depends on **your** traffic mix, not ours.
Default ships at `0.95`. Score 1K of your real user messages, look at
the recall/FPR curve, pick the threshold that matches your tolerance
for false-positives vs missed attacks.

## What this benchmark does *not* claim

- Not a multilingual claim for the long tail — calibrate per language
  for your traffic.
- Not a multi-turn claim — single-turn scoring.
- Not a "zero false positives" claim — some benign messages will be
  blocked at any threshold.
- Not a guarantee — probabilistic model. No `.safe` boolean.

## Reproduce

```bash
git clone https://github.com/securelayer7/PROMPTPurify
cd promptpurify
npm install onnxruntime-node
node scripts/bench.mjs
```

Full step-by-step including OSS-baseline comparison:
[REPRODUCE.md](REPRODUCE.md). Sample-data scope:
[SAMPLE-DATA.md](SAMPLE-DATA.md).
