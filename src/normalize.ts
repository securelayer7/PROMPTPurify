/**
 * L1 — mechanical normalization. The true DOMPurify analog: finite,
 * deterministic, idempotent transforms that strip the places payloads hide.
 * No judgment, no model. Either a codepoint is in a dangerous class or not.
 */
import type { NormalizationReport } from "./types.js";
import { foldStyles } from "./styles.js";

// Zalgo (F4). Two-pronged, both deterministic:
//  1. ANY mark following a Latin-script letter/digit — post-NFKC Latin is
//     fully precomposed (café, Việt are single codepoints), so a STANDALONE
//     trailing combining mark is never legitimate, even one. Kills Latin
//     zalgo. The base class spans ASCII + Latin-1/Extended (À-ɏ) + Latin
//     Extended Additional (Ḁ-ỿ): a 2+ mark zalgo NFKC-composes its first
//     mark onto the base (i+̀ -> ì) and leaves the rest as residue after a
//     now-NON-ASCII Latin char — an ASCII-only base class would miss that.
//     Legit accented words carry no standalone marks post-NFKC, so untouched.
//  2. Remaining runs of >=3 stacked marks — heavy non-Latin zalgo, while
//     legit scripts (Arabic harakat, Indic matras, Vietnamese) use <=2.
const ZALGO_LATIN = /([0-9A-Za-zÀ-ɏḀ-ỿ])\p{M}+/gu;
const ZALGO_RUN = /\p{M}{3,}/gu;
// Combining mark with no legit base: at string start or after whitespace.
// No real script starts a cluster with a bare mark — pure stego/zalgo residue.
const ZALGO_ORPHAN = /(^|\s)\p{M}+/gu;

// Variation selectors (emoji-stego payload channel): VS1-16 + Supplement.
const VARIATION_SELECTORS = /[︀-️]|[\u{E0100}-\u{E01EF}]/gu;

// Zero-width & invisible: ZWSP/ZWNJ/ZWJ, BOM/ZWNBSP, word joiner,
// soft hyphen, Mongolian vowel separator.
const ZERO_WIDTH = /[​-‍﻿⁠­᠎]/g;

// Bidi controls — LRE/RLE/PDF/LRO/RLO/LRI/RLI/FSI/PDI + ALM/LRM/RLM.
//
// WHY strip-only, NO logical-order reversal (P4RS3LT0NGV3 BIDI transform):
// The Plinius RLO trick stores the payload in CORRECT logical order in memory
// and uses RLO purely so a HUMAN sees it reversed (visual deception of a
// reviewer). The LLM tokenizer reads the logical (memory) byte order — i.e.
// the real payload — and the control char itself is inert to it. So stripping
// the control leaves exactly what the model already saw: the true payload,
// fully exposed to the downstream tripwires. Reversing the run would instead
// FABRICATE a string nobody supplied (benign "erongi" -> "ignore"), is
// non-idempotent on mixed-direction text, and would actively CORRUPT genuine
// RTL content (Arabic/Hebrew rely on the Bidi algorithm, not literal order:
// "مرحبا بالعالم", "שלום עולם" must pass through byte-identical). Strip-only
// is the deterministic, non-corrupting, idempotent choice; report.bidiStripped
// already records the tampering for the audit trail.
const BIDI = /[‪-‮⁦-⁩‎‏؜]/g;

// Unicode Tags block (U+E0000–E007F): invisible ASCII smuggling channel.
const TAG_CHARS = /[\u{E0000}-\u{E007F}]/gu;

// Common Cyrillic / Greek homoglyphs -> Latin. Small high-signal subset;
// not exhaustive (impossible) — folds the confusables actually weaponized.
// F5: curated visual-confusables (NOT block-fold — that would mangle legit
// Russian/Greek/Armenian text; folding only triggers for untrusted sinks,
// OFF for trusted_instruction, so legit "привет мир"/"Ελλάδα"/"մարդ" pass).
// High-signal subset actually weaponized for keyword spoofing. Cherokee/
// Coptic remain a documented partial gap; Armenian now covered below.
const HOMOGLYPHS: Record<string, string> = {
  // Cyrillic lowercase
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
  "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ո": "n",
  "ѵ": "v", "ԛ": "q", "ԝ": "w", "ɡ": "g", "ｍ": "m", "ḅ": "b",
  // Parseltongue confusables module weaponizes these to spoof EN keywords
  // (e.g. "ігпоге"->"ignore"). Per-Unicode-confusables mapping.
  "г": "r", "п": "n", "и": "u", "к": "k", "т": "t", "м": "m", "н": "H",
  "л": "n", "ь": "b", "ы": "bl", "з": "3",
  // Cyrillic uppercase
  "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H",
  "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "У": "Y",
  "Ѕ": "S", "І": "I", "Ј": "J", "Ԛ": "Q", "Ԝ": "W", "Ғ": "F",
  "Ё": "E", "Ӏ": "I",
  // Greek
  "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "υ": "u",
  "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I",
  "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
  "Υ": "Y", "Χ": "X", "ϲ": "c", "Ϲ": "C", "ɑ": "a",
  // More lowercase Greek per-Unicode-confusables (confusables.txt) used to
  // spoof EN keywords. Only single-Latin-letter confusables; ambiguous
  // shapes (σ, λ, φ) deliberately omitted to avoid mangling legit Greek.
  "ι": "i", "γ": "y", "ω": "w", "ε": "e", "κ": "k", "η": "n",
  // Parseltongue confusables module weaponizes Armenian to spoof EN
  // keywords. Per-Unicode-confusables.txt mapping; only chars with a
  // documented single-Latin-letter confusable. Legit Armenian never reaches
  // here — fold is OFF for the trusted_instruction sink. Cherokee/Coptic
  // remain the documented partial gap. (ո->n already mapped above.)
  "օ": "o", "ս": "u", "ց": "g", "հ": "h", "ք": "p",
  // Armenian uppercase confusables (Unicode-attested Latin lookalikes).
  "Օ": "O", "Ս": "U", "Ո": "N", "Տ": "S",
};

// Range covers Greek/Coptic + Armenian + Cyrillic + Cyrillic-Supplement +
// a few Latin IPA / fullwidth lookalikes; the range is only a fast prefilter
// — ONLY chars explicitly present in HOMOGLYPHS are folded, so widening the
// range cannot mangle unmapped legit Armenian/Greek/Cyrillic letters.
function foldHomoglyphs(s: string): { out: string; count: number } {
  let count = 0;
  const out = s.replace(/[ɐ-ʯͰ-ϿԱ-ֈЀ-ԯａ-ｚ]/g, (ch) => {
    const m = HOMOGLYPHS[ch];
    if (m !== undefined) {
      count++;
      return m;
    }
    return ch;
  });
  return { out, count };
}

function countMatches(s: string, re: RegExp): number {
  const m = s.match(re);
  return m ? m.length : 0;
}

export function normalize(
  input: string,
  opts: {
    foldHomoglyphs?: boolean;
    collapseWhitespace?: boolean;
    /**
     * Aggressive whitespace canonicalization — defeats whitespace
     * steganography (space/tab bit-encoding). Tabs->space, ALL horizontal
     * runs ->1 space, strip trailing line whitespace, >=3 newlines ->2.
     * For untrusted/data sinks only (would mangle pasted code in trusted).
     */
    canonicalizeWhitespace?: boolean;
    maxLength?: number;
  } = {},
): { text: string; report: NormalizationReport } {
  const report: NormalizationReport = {
    unicodeNormalized: false,
    zeroWidthStripped: 0,
    bidiStripped: 0,
    tagCharsStripped: 0,
    homoglyphsFolded: 0,
    combiningStripped: 0,
    variationSelectorsStripped: 0,
    stylesFolded: 0,
    whitespaceCollapsed: false,
    truncated: false,
  };

  let s = input;

  // 1. Canonical Unicode form — collapses compatibility/spoofing variants
  //    (folds Math Bold/Italic/Fraktur, Fullwidth/vaporwave, etc.).
  const nfkc = s.normalize("NFKC");
  report.unicodeNormalized = nfkc !== s;
  s = nfkc;

  // 2. Strip invisible smuggling channels.
  report.zeroWidthStripped = countMatches(s, ZERO_WIDTH);
  s = s.replace(ZERO_WIDTH, "");

  report.bidiStripped = countMatches(s, BIDI);
  s = s.replace(BIDI, "");

  report.tagCharsStripped = countMatches(s, TAG_CHARS);
  s = s.replace(TAG_CHARS, "");

  report.variationSelectorsStripped = countMatches(s, VARIATION_SELECTORS);
  s = s.replace(VARIATION_SELECTORS, "");

  let combiningRemoved = 0;
  s = s.replace(ZALGO_LATIN, (_m, base: string) => {
    combiningRemoved += _m.length - base.length;
    return base;
  });
  s = s.replace(ZALGO_RUN, (m) => {
    combiningRemoved += m.length;
    return "";
  });
  s = s.replace(ZALGO_ORPHAN, (_m, lead: string) => {
    combiningRemoved += _m.length - lead.length;
    return lead;
  });
  report.combiningStripped = combiningRemoved;

  // 3a. Fold non-NFKC style transforms (small-caps, regional-indicator,
  //     upside-down) that the model reads but keyword filters do not.
  const fs = foldStyles(s);
  s = fs.text;
  report.stylesFolded = fs.folded;

  // 3. Fold weaponized homoglyphs (opt-in aggressive — default on).
  if (opts.foldHomoglyphs !== false) {
    const f = foldHomoglyphs(s);
    s = f.out;
    report.homoglyphsFolded = f.count;
  }

  // 4. Whitespace. Aggressive mode defeats whitespace steganography
  //    (space/tab bit-encoding survives a mere >=3 collapse).
  if (opts.canonicalizeWhitespace) {
    const before = s;
    s = s
      .replace(/\t/g, " ") // tab/space encoding -> uniform
      .replace(/[^\S\r\n]{2,}/g, " ") // ALL horizontal runs -> 1
      .replace(/[^\S\r\n]+$/gm, "") // trailing line whitespace (bit channel)
      .replace(/\n{3,}/g, "\n\n"); // blank-line encoding
    report.whitespaceCollapsed = s !== before;
  } else if (opts.collapseWhitespace !== false) {
    const before = s;
    s = s.replace(/[^\S\r\n]{3,}/g, "  ").replace(/\n{4,}/g, "\n\n\n");
    report.whitespaceCollapsed = s !== before;
  }

  // 5. Length cap (context-flood mitigation).
  if (opts.maxLength && opts.maxLength > 0 && s.length > opts.maxLength) {
    s = s.slice(0, opts.maxLength);
    report.truncated = true;
  }

  return { text: s, report };
}

export function normalizationModified(r: NormalizationReport): boolean {
  return (
    r.unicodeNormalized ||
    r.zeroWidthStripped > 0 ||
    r.bidiStripped > 0 ||
    r.tagCharsStripped > 0 ||
    r.homoglyphsFolded > 0 ||
    r.combiningStripped > 0 ||
    r.variationSelectorsStripped > 0 ||
    r.stylesFolded > 0 ||
    r.whitespaceCollapsed ||
    r.truncated
  );
}
