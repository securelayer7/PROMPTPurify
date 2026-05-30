# Quickstart

Three integration patterns. Pick what matches your threat. Most chat
apps want **Pattern 2** (the model guard) + **Pattern 3** (structural
firewall) together.

## Install

```bash
# SDK only — Patterns 1 & 3 work right after this
npm i promptpurify

# Add the model for Pattern 2 (chat-injection guard):
npm i onnxruntime-node
curl -L -o promptpurify-model.tar.gz \
  https://github.com/securelayer7/PROMPTPurify/releases/download/v0.0.1/promptpurify-model.tar.gz
curl -L -o promptpurify-model.tar.gz.sha256 \
  https://github.com/securelayer7/PROMPTPurify/releases/download/v0.0.1/promptpurify-model.tar.gz.sha256
sha256sum -c promptpurify-model.tar.gz.sha256   # MUST print "OK"
tar xzf promptpurify-model.tar.gz                # extracts to ./models/l5e/
```

| Component | Required for |
|---|---|
| `promptpurify` (npm) | Everything. Zero deps. ESM + CJS + browser IIFE. ~7 KB structural core. |
| `onnxruntime-node` (npm) | The model (Pattern 2). Optional peer. |
| `models/l5e/` (release tarball) | The model (Pattern 2). ~14 MB ONNX + tokenizer. Excluded from the npm tarball on purpose — verify SHA256 before extracting. |

The browser IIFE carries **zero** ONNX bytes — structural-only on
purpose.

---

## Pattern 1 — sanitize a string

`dirty → clean`, deterministic, sub-millisecond.

```ts
import { promptpurify } from "promptpurify";

const clean = promptpurify.sanitize(userInput, { sink: "untrusted_data" });
```

Inspect with reasons:

```ts
const r = promptpurify.inspect(userInput, { sink: "rag_chunk" });
// r.verdict: "clean-structural" | "flagged" | "blocked"
// r.risks:   [{ rule, message, severity, span }]
```

`clean-structural` means **structurally inert**, not "safe".

---

## Pattern 2 — model guard (recommended for chat apps)

The trained ONNX model. Catches what regex can't.

```ts
import { createL5eRunner } from "promptpurify/l5";

const guard = await createL5eRunner(); // default modelDir = "./models/l5e"

app.post("/chat", async (req, res) => {
  const score = await guard.score(req.body.message);
  if (score >= 0.95) return res.json({ blocked: true });    // hard block
  if (score >= 0.85) auditQueue.push({ score, msg: req.body.message });
  const reply = await yourLLM.complete(req.body.message);
  res.json({ reply });
});
```

`0.95` is the shipped default. Calibrate for your traffic — see
[BENCHMARKS.md](BENCHMARKS.md#operating-points).

The guard runs **in-process**. No sidecar, no HTTP, no network call.

---

## Pattern 3 — structural firewall (for RAG / tool-using agents)

Where untrusted input must coexist with trusted instructions.
Deterministic, no model, role-separated, nonce-fenced.

```ts
import { buildMessages, purifyOutput } from "promptpurify";

const messages = buildMessages({
  system: "You are a support bot.",
  user:   userInput,
  data:   [{ label: "kb_article", content: retrievedDoc, sink: "rag_chunk" }],
});
// -> role-separated, nonce-fenced. Feed straight to a chat API.

const llm = await openai.chat.completions.create({ model, messages });

// Output side: strip exfiltration sinks
const { text } = purifyOutput(llm.choices[0].message.content, {
  allowHosts: ["cdn.myapp.com"],
});
```

---

## Combined (typical production setup)

```ts
import { buildMessages, purifyOutput } from "promptpurify";
import { createL5eRunner } from "promptpurify/l5";

const guard = await createL5eRunner();

app.post("/chat", async (req, res) => {
  // Pattern 2 — model-driven block
  const score = await guard.score(req.body.message);
  if (score >= 0.95) return res.json({ blocked: true });

  // Pattern 3 — structural firewall around the LLM call
  const messages = buildMessages({
    system: SYSTEM_PROMPT,
    user:   req.body.message,
    data:   await ragSearch(req.body.message),
  });
  const llm = await openai.chat.completions.create({ model, messages });

  // Output exfil guard
  const { text } = purifyOutput(llm.choices[0].message.content);
  res.json({ reply: text, guard_score: score });
});
```

---

## Browser drop-in (structural only)

```html
<script src="https://unpkg.com/promptpurify/dist/promptpurify.browser.global.js"></script>
<script>
  const clean = PromptPurify.promptpurify.sanitize(userInput);
  const r     = PromptPurify.promptpurify.inspect(userInput);
</script>
```

The model is **not** in the browser bundle — run it server-side.

---

## Where to go next

- [HOW-IT-WORKS.md](HOW-IT-WORKS.md)
- [BENCHMARKS.md](BENCHMARKS.md)
- [HONEST-LIMITS.md](HONEST-LIMITS.md)
