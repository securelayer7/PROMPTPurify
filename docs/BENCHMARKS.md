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
python3 scripts/bench_oss.py            # ProtectAI / deepset / fmops on the same slice
```

Full recipe: [REPRODUCE.md](REPRODUCE.md).

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
