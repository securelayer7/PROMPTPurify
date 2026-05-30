# Reproduce the benchmark

Re-run the comparison on your box. No cloud credits, no GPU.

## Prerequisites

```
node    >= 18
python  >= 3.10
git
```

## 1. Get the model

```bash
git clone https://github.com/securelayer7/PROMPTPurify
cd promptpurify
npm install
```

The model and tokenizer are bundled in the repo's model directory — the
bench script knows where to find them. The public eval slice lives at
`training/FROZEN_EVAL_SCORED.jsonl`.

## 2. Smoke-test the model

```bash
node scripts/bench.mjs
```

Re-scores the eval slice with the shipped ONNX and prints the recall /
FP breakdown.

## 3. Compare against OSS guardrails

```bash
pip install transformers torch
python3 scripts/bench_oss.py
```

Downloads ProtectAI v2, deepset, fmops on first run (~470 MB total,
cached after). Scores them on the same JSONL as step 2 and prints a
side-by-side table — promptpurify vs OSS at each model's default
threshold and at a cross-model neutral `0.5`.

CPU-only; ~3–5 minutes the first time.

## 4. Score your own data

The simplest integration test — does it work on *your* traffic?

```bash
# Make a JSONL: one {"text": "...", "y": 0|1} per line
node scripts/bench.mjs my_traffic.jsonl
```

Pick the threshold that lands in the recall / FP region you can live
with. Default ships at `0.95`.

## Trouble?

| Symptom | Likely cause |
|---|---|
| `Cannot find module 'onnxruntime-node'` | `npm install onnxruntime-node` |
| Hugging Face downloads fail | Set `HF_HUB_ENABLE_HF_TRANSFER=0` or supply `HF_TOKEN` |
| Apple-Silicon ONNX error | Update `onnxruntime-node` to ≥1.19 |
| Numbers don't match | Confirm threshold is `0.95` and you're running the shipped artifact (the bench script picks it up automatically — don't repoint it) |
