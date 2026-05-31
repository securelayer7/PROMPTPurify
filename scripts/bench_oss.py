#!/usr/bin/env python3
"""
Cross-model benchmark — scores the same public eval slice
(training/FROZEN_EVAL_SCORED.jsonl) against OSS prompt-injection
guardrails AND against promptpurify (via its precomputed `score`
field).

Usage:
    pip install transformers torch
    python3 scripts/bench_oss.py

Output: per-model recall / FPR at the model's default threshold and
at a cross-model neutral 0.5.

No internal paths, no GPU required (CPU is fine but slow for the
larger DeBERTa models). Downloads each model from Hugging Face on
first run; cached locally after that.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

try:
    import torch
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        pipeline,
    )
except ImportError:
    print(
        "ERROR: requires `transformers` and `torch`.\n"
        "Install:  pip install transformers torch",
        file=sys.stderr,
    )
    sys.exit(1)


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = ROOT / "training" / "FROZEN_EVAL_SCORED.jsonl"


@dataclass
class ModelSpec:
    name: str
    hf_id: str
    injection_label: str
    default_threshold: float
    sum_attack_labels: tuple = ()
    notes: str = ""


OSS_MODELS: list[ModelSpec] = [
    ModelSpec(
        name="ProtectAI v2",
        hf_id="protectai/deberta-v3-base-prompt-injection-v2",
        injection_label="INJECTION",
        default_threshold=0.5,
    ),
    ModelSpec(
        name="deepset",
        hf_id="deepset/deberta-v3-base-injection",
        injection_label="INJECTION",
        default_threshold=0.5,
    ),
    ModelSpec(
        name="fmops",
        hf_id="fmops/distilbert-prompt-injection",
        injection_label="INJECTION",
        default_threshold=0.5,
    ),
    ModelSpec(
        name="Meta Prompt-Guard",
        hf_id="meta-llama/Prompt-Guard-86M",
        injection_label="INJECTION",
        default_threshold=0.5,
        sum_attack_labels=("INJECTION", "JAILBREAK"),
        notes="3-class; positive = P(INJECTION) + P(JAILBREAK)",
    ),
    ModelSpec(
        name="Meta Prompt-Guard-2",
        hf_id="meta-llama/Llama-Prompt-Guard-2-86M",
        injection_label="LABEL_1",
        default_threshold=0.5,
        notes="LABEL_1 = injection class",
    ),
]


def load_rows(path: Path) -> list[dict]:
    rows = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def score_with_pipeline(spec: ModelSpec, texts: list[str]) -> list[float]:
    """Run the HF model, return P(injection) for each text."""
    print(f"  loading {spec.hf_id} ...", flush=True)
    t0 = time.time()
    tok = AutoTokenizer.from_pretrained(spec.hf_id)
    model = AutoModelForSequenceClassification.from_pretrained(spec.hf_id)
    clf = pipeline(
        "text-classification",
        model=model,
        tokenizer=tok,
        truncation=True,
        device=-1,  # CPU
        return_all_scores=True,
        top_k=None,
    )
    print(f"  loaded in {time.time()-t0:.1f}s; scoring {len(texts)} rows...", flush=True)

    scores: list[float] = []
    BATCH = 16
    for i in range(0, len(texts), BATCH):
        batch = [t[:4000] for t in texts[i : i + BATCH]]
        outputs = clf(batch)
        for out in outputs:
            if spec.sum_attack_labels:
                wanted = {l.upper() for l in spec.sum_attack_labels}
                inj = sum(
                    o["score"] for o in out if o["label"].upper() in wanted
                )
            else:
                inj = next(
                    (
                        o["score"]
                        for o in out
                        if o["label"].upper() == spec.injection_label.upper()
                    ),
                    None,
                )
                if inj is None:
                    inj = max(o["score"] for o in out)
            scores.append(float(inj))
    return scores


def metrics(scores: list[float], labels: list[int], threshold: float) -> dict:
    tp = fp = tn = fn = 0
    for s, y in zip(scores, labels):
        pred = 1 if s >= threshold else 0
        if y == 1 and pred == 1:
            tp += 1
        elif y == 1 and pred == 0:
            fn += 1
        elif y == 0 and pred == 1:
            fp += 1
        else:
            tn += 1
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"recall": recall, "fpr": fpr, "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def fmt_pct(x: float) -> str:
    return f"{x*100:5.2f}%"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    ap.add_argument(
        "--skip-oss",
        action="store_true",
        help="Skip downloading/scoring OSS models; print promptpurify numbers only.",
    )
    args = ap.parse_args()

    rows = load_rows(args.input)
    texts = [r["text"] for r in rows]
    labels = [
        r.get("y")
        if r.get("y") is not None
        else (1 if r.get("ground_truth") in ("attack", "harmful") else 0)
        for r in rows
    ]
    n_atk = sum(labels)
    n_ben = len(labels) - n_atk
    print(f"loaded {len(rows)} rows ({n_atk} attacks, {n_ben} benigns) from {args.input.relative_to(ROOT)}")

    results: list[tuple[str, dict, dict]] = []

    pp_scores = [float(r["score"]) for r in rows if "score" in r]
    if len(pp_scores) == len(rows):
        results.append(
            (
                "promptpurify",
                metrics(pp_scores, labels, 0.95),
                metrics(pp_scores, labels, 0.5),
            )
        )

    if not args.skip_oss:
        for spec in OSS_MODELS:
            try:
                scores = score_with_pipeline(spec, texts)
                results.append(
                    (
                        spec.name,
                        metrics(scores, labels, spec.default_threshold),
                        metrics(scores, labels, 0.5),
                    )
                )
            except Exception as e:
                print(f"  FAILED for {spec.name}: {e}", file=sys.stderr)

    print()
    print("model              | recall@default | FPR@default | recall@0.5 | FPR@0.5")
    print("-" * 78)
    for name, at_default, at_half in results:
        print(
            f"{name:18s} | {fmt_pct(at_default['recall'])}         | {fmt_pct(at_default['fpr'])}      "
            f"| {fmt_pct(at_half['recall'])}     | {fmt_pct(at_half['fpr'])}"
        )

    print()
    print("Notes:")
    print(" - `recall@default` uses each model's published / production threshold.")
    print(" - `@0.5` is a cross-model neutral threshold for comparability.")
    print(" - promptpurify default = 0.95.")


if __name__ == "__main__":
    main()
