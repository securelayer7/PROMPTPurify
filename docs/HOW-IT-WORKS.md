# How it works

promptpurify has two halves: a **deterministic structural firewall**
(no ML) and the **promptpurify model** (ML).

```
                 ┌────────────────────────────┐
 user input  ──▶ │  Structural firewall        │
                 │   1. Unicode normalize       │  deterministic
                 │   2. Structure / fencing     │  deterministic
                 │   3. Sink policy             │  deterministic
                 │   4. Tripwire regex          │  deterministic, advisory
                 │                              │
                 │  promptpurify model          │  ML, advisory + block
                 └──────────────┬─────────────┘
                                ▼
                         your LLM call
                                │
                                ▼
                 ┌────────────────────────────┐
 model output ──▶│  purifyOutput()             │  deterministic
                 └────────────────────────────┘
```

## Structural firewall

### 1. Unicode normalize

Strips zero-width and bidi smuggling, folds NFKC styles and weaponized
homoglyphs to Latin, collapses combining-mark stacks, decodes
regional-indicator stego, applies a per-sink length cap.

Deterministic. Idempotent. No model, no network.

### 2. Structure / fencing

The real DOMPurify analog and the layer most apps under-use.

- **Per-call nonce fence** wraps each untrusted region.
- **Forged chat-template tokens** (`<|im_start|>`, `[INST]`, `<<SYS>>`,
  `<|system|>`, …) inside user text get neutralized at fence
  boundaries.
- **Role separation** is enforced at the API call — untrusted text is
  never in the `system` role.

This is what gives `buildMessages()` its teeth — see
[QUICKSTART Pattern 3](QUICKSTART.md#pattern-3--structural-firewall-for-rag--tool-using-agents).

### 3. Sink policy

Different contexts get different rules — the HTML world figured this
out 20 years ago (body vs attribute vs URL all escape differently).

| Sink | Use |
|---|---|
| `trusted_instruction` | Your own system prompt |
| `untrusted_data` | User chat message |
| `tool_output` | Function-call return value |
| `rag_chunk` | Retrieved doc / web snippet (strictest) |

### 4. Tripwire regex

Known jailbreak shapes. **Flags, doesn't block by default.** Weak by
design — useful for logging / rate-limiting / honeypots, never to make
a safety claim.

## The promptpurify model

A small ONNX classifier trained from scratch by SecureLayer7. Catches
what regex can't.

| | |
|---|---|
| Type | ONNX transformer classifier |
| Size on disk | ~14 MB (INT8) |
| Inference | CPU, single-digit ms |
| Runtime | `onnxruntime-node` (optional peer; absent ⇒ graceful degrade) |
| Network | None. In-process. |
| Training | Built from scratch on curated internal corpora. |
| Evaluation | See [`training/CORPUS_LICENSES.json`](../training/CORPUS_LICENSES.json) for benchmark sources. |

Benchmark numbers and methodology: [BENCHMARKS.md](BENCHMARKS.md).

## Output guard

`purifyOutput()` runs on the *model's* response. Strips
markdown-image URLs and clickable tracking links to hosts not on
`allowHosts` — the two common silent-exfil vectors.

Deterministic, idempotent, sub-millisecond.

## Out of scope

- Multi-turn auditing — pair with conversation-level monitoring.
- Content moderation — different tool.
- Guarantees — natural language has no formal grammar.

See [HONEST-LIMITS.md](HONEST-LIMITS.md).
