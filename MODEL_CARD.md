---
license: mit
language:
  - en
library_name: onnx
pipeline_tag: text-classification
tags:
  - prompt-injection
  - jailbreak
  - llm-security
  - guardrail
  - onnx
metrics:
  - recall
  - false_positive_rate
---

# promptpurify model card

**Tiny prompt-injection detector. ~14 MB. CPU. Built from scratch by
[SecureLayer7](https://securelayer7.net).**

## Intended use

Single-turn classification of untrusted text into `benign` vs
`prompt-injection`. Sits between user input (or a retrieved RAG chunk,
or a tool output) and your LLM call. Outputs a probability score; you
decide the threshold and the policy.

```ts
import { createL5eRunner } from "promptpurify/l5";
const guard = await createL5eRunner();
const score = await guard.score(userMessage);
if (score >= 0.95) return refusal();
```

Full integration patterns: [docs/QUICKSTART.md](docs/QUICKSTART.md).

## At a glance

| | |
|---|---|
| Type | ONNX transformer classifier |
| Size on disk | **~14 MB (INT8)** |
| Inference | CPU, single-digit ms |
| Runtime | `onnxruntime-node` (optional peer) |
| Network | **None.** In-process. |

## Training

Built from scratch by SecureLayer7 on curated internal corpora.

## Evaluation

Benchmarked against public datasets and OSS baselines. Comparison and
methodology: [docs/BENCHMARKS.md](docs/BENCHMARKS.md). Reproducibility:
[docs/REPRODUCE.md](docs/REPRODUCE.md). Bench script
`scripts/bench.mjs` re-scores the shipped public eval slice with this
exact model artifact.

## Out of scope

- Single-turn scoring only — pair with conversation-level monitoring.
- Content moderation (toxicity, hate, CSAM, self-harm) — pair with a
  content classifier.
- Authentication and tool-scope enforcement are application
  responsibilities, not the model's.

See [docs/HONEST-LIMITS.md](docs/HONEST-LIMITS.md).

## Bias

The model is English-strongest. Operators serving multilingual traffic
should calibrate the threshold per language. The model has no access
to user identity, account state, or conversation history.

## License

MIT for both the SDK and the model weights.

Public datasets we evaluate against (and the OSS baseline models we
compare to) carry their own upstream licenses — see
[`training/CORPUS_LICENSES.json`](training/CORPUS_LICENSES.json).

## Integrity verification

Every model artifact is checksummed. Verify before extracting:

```bash
sha256sum -c models/l5e/SHA256SUMS
```

The release tarball is additionally cosign-signed with keyless
Sigstore.

## Distribution mirrors

| Mirror | URL |
|---|---|
| GitHub Releases | `https://github.com/securelayer7/PROMPTPurify/releases` |
| Hugging Face Hub | [`Securelayer7/promptpurify`](https://huggingface.co/Securelayer7/promptpurify) |

## Contact

- Security disclosures: [`SECURITY.md`](SECURITY.md) →
  `info@securelayer7.net`
- General: [GitHub Issues](https://github.com/securelayer7/PROMPTPurify/issues)

## Acknowledgments

Name and design philosophy inspired by
[DOMPurify](https://github.com/cure53/DOMPurify) by [Cure53](https://cure53.de).
Thanks to **Mario Heiderich** for suggesting the name.
