# Sample data

What ships in this repo for benchmarking, what doesn't, and why.

## TL;DR

| File | What it is |
|---|---|
| `training/FROZEN_EVAL_SCORED.jsonl` | Public eval slice — mixed benign + attack inputs already scored. Lets anyone reproduce our numbers without retraining. |
| `training/CORPUS_LICENSES.json` | Public benchmark datasets and OSS baseline models we evaluate against, with licenses. |
| `scripts/bench.mjs` | Re-scores the eval slice against the shipped ONNX. One command. |
| `scripts/bench_oss.py` | Scores the same inputs against ProtectAI / deepset / fmops. Side-by-side table. |

Raw datasets are not redistributed; fetch them from their upstream URLs.

## What we deliberately *don't* ship

- **No raw datasets.** Fetch the benchmark sources yourself; see
  [`training/CORPUS_LICENSES.json`](../training/CORPUS_LICENSES.json).
- **No teacher weights.** Built from scratch.
- **No customer data.** No data from any customer system has ever been
  used for training or evaluation.

## How to get the model

**Recommended — release tarball + checksum:**

```bash
TAG=v0.0.1
curl -L -o promptpurify-model.tar.gz \
  https://github.com/securelayer7/PROMPTPurify/releases/download/$TAG/promptpurify-model.tar.gz
curl -L -o promptpurify-model.tar.gz.sha256 \
  https://github.com/securelayer7/PROMPTPurify/releases/download/$TAG/promptpurify-model.tar.gz.sha256
sha256sum -c promptpurify-model.tar.gz.sha256   # MUST print "OK"
tar xzf promptpurify-model.tar.gz                # extracts to ./models/l5e/
```

The release tarball is cosign-signed with keyless Sigstore; verify
with `cosign verify-blob --bundle promptpurify-model.tar.gz.cosign.bundle`.

**Alternative — Hugging Face Hub mirror:**

```bash
huggingface-cli download Securelayer7/promptpurify --local-dir models/l5e
```

**Alternative — clone the repo** (for benchmarking / contributing):

```bash
git clone https://github.com/securelayer7/PROMPTPurify
cd promptpurify && shasum -a 256 -c models/l5e/SHA256SUMS
```

## Why the model isn't in the npm tarball

- Keeps `npm install promptpurify` tiny (~50 KB).
- Lets you version the model independently of the SDK.
- Browser bundle stays ONNX-free — no 14 MB shipped to every visitor.

## Reproduce in one command

```bash
git clone https://github.com/securelayer7/PROMPTPurify
cd promptpurify
npm install onnxruntime-node
node scripts/bench.mjs
```

Full step-by-step: [REPRODUCE.md](REPRODUCE.md).
