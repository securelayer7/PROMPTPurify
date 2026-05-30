# Honest limits

A tool, not a guarantee. Read this before shipping.

## No `.safe` boolean

Natural language has no formal grammar. promptpurify returns:

- A **deterministic verdict** for the structural layers
  (`clean-structural` / `flagged` / `blocked`)
- A **score** (0–1) from the model

You decide the threshold and the policy.

## What it doesn't do

- **Multi-turn auditing.** Single-turn scoring. Pair with conversation-
  level monitoring for the full picture.
- **Content moderation.** Toxicity / hate / CSAM / self-harm are
  out-of-scope. Use a content classifier alongside.
- **Authentication.** It cannot prove who the user is. Don't trust
  identity claims that appear in prompt text.
- **Tool-scope enforcement.** A guardrail is not a substitute for
  least-privilege tool design.

## False positives exist

The model is probabilistic. At any threshold, some benign messages will
be blocked. Build an escape valve: a softer advisory tier, an
"edit-and-retry" UX, or a review queue. Per-threshold operating points
are in [BENCHMARKS.md](BENCHMARKS.md#operating-points).

## Reporting

Found something promptpurify misses? See
[SECURITY.md](../SECURITY.md). Every reproducible bypass we receive
informs the next training run.
