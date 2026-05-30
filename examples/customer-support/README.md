# PayLine Support — promptpurify sample app

A fintech customer-support chatbot, guarded by promptpurify.
Demonstrates the **3-line integration** that protects any LLM chat
application from prompt-injection — running entirely on CPU,
in-process, no extra network hop.

## What it shows

- Prompt-injection guard sits between user input and your LLM
- CPU inference, no GPU, no separate service
- Drop-in: works alongside any LLM provider (Groq, OpenAI, Anthropic,
  local)
- Real measurements — see latency + score on every reply in the UI

## Run

```bash
cd examples/customer-support
npm install
GROQ_API_KEY=gsk_... node server.mjs
# open http://localhost:8787
```

Without `GROQ_API_KEY` the LLM call is stubbed — the guard still runs,
so you can see scoring and blocking behavior without an API key.

## The 3-line integration

```js
import { createL5eRunner } from "promptpurify/l5";

const guard = await createL5eRunner();

// In your /chat handler:
const score = await guard.score(userMessage);
if (score >= 0.85) return refusal();          // BLOCK
const reply = await yourLLM.complete(userMessage);  // PASS
```

## Try it

The right panel has one-click test prompts — both benign and attack.
Watch the `score` + `BLOCKED|ALLOWED` pill on each reply.

## How to adjust

- **Threshold** in `server.mjs` → `BLOCK_THRESHOLD`. `0.85` is a
  reasonable starting point for chat apps; calibrate for your traffic.
- **System prompt** in `server.mjs` → `SYSTEM_PROMPT`. Adapt for your
  domain.
- **LLM provider** in `server.mjs` — swap Groq for OpenAI, Anthropic,
  or any chat-completions API.
