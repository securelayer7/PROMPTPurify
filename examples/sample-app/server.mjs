// Minimal promptpurify sample app — a /chat endpoint guarded by the model.
//
// Run:
//   npm install
//   node server.mjs                            # works offline (LLM stubbed)
//   GROQ_API_KEY=gsk_... node server.mjs       # calls Groq (OpenAI-compatible)
//   open http://localhost:8787
//
// What it shows:
//   1. promptpurify loads the model in-process from ./models/l5e/
//   2. Every /chat request is scored before the LLM is called.
//   3. Score >= 0.95 → blocked. Score >= 0.85 → flagged. Else → passed.
//
// Replace the LLM block with whatever provider you use.
import express from "express";
import { createL5eRunner } from "promptpurify/l5";

const PORT = process.env.PORT || 8787;
const BLOCK_THRESHOLD = 0.95;
const FLAG_THRESHOLD = 0.85;
const GROQ_KEY = process.env.GROQ_API_KEY;
const MODEL = process.env.GROQ_MODEL || "llama-3.3-70b-versatile";

const guard = await createL5eRunner();
console.log("promptpurify loaded");

const app = express();
app.use(express.json({ limit: "64kb" }));
app.use(express.static("public"));

app.post("/chat", async (req, res) => {
  const userMessage = String(req.body?.message ?? "");
  if (!userMessage) return res.status(400).json({ error: "empty message" });

  const t0 = Date.now();
  const score = await guard.score(userMessage);
  const guard_ms = Date.now() - t0;

  if (score >= BLOCK_THRESHOLD) {
    return res.json({
      blocked: true,
      score,
      guard_ms,
      reply: "Blocked by promptpurify (suspected prompt injection).",
    });
  }
  const flagged = score >= FLAG_THRESHOLD;

  const reply = await callLLM(userMessage);
  res.json({ blocked: false, flagged, score, guard_ms, reply });
});

async function callLLM(userMessage) {
  if (!GROQ_KEY) {
    return `[stubbed — no GROQ_API_KEY set] You said: ${userMessage.slice(0, 120)}`;
  }
  const r = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${GROQ_KEY}`,
    },
    body: JSON.stringify({
      model: MODEL,
      max_tokens: 256,
      messages: [
        { role: "system", content: "You are a helpful assistant. Reply briefly." },
        { role: "user", content: userMessage },
      ],
    }),
  });
  if (!r.ok) return `[LLM error ${r.status}]`;
  const j = await r.json();
  return (j.choices?.[0]?.message?.content || "").trim();
}

app.listen(PORT, () => console.log(`http://localhost:${PORT}`));
