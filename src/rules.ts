/**
 * L4 — tripwire rules. These FLAG, they do not clean. A match means
 * "looks like a known attack shape"; absence means *nothing*. Paraphrase
 * trivially evades — that is expected and documented, not a bug.
 */
import type { Risk, TripwireRule } from "./types.js";
import { TEMPLATE_TOKENS } from "./structure.js";

// F1: gap matchers must allow '.' and newline (period/newline insertion was
// a trivial bypass). Bounded + lazy => no catastrophic backtracking.
const GAP = (n: number) => `[\\s\\S]{0,${n}}?`;

export const BUILTIN_RULES: TripwireRule[] = [
  {
    id: "instruction-override",
    severity: "high",
    message: "Attempts to override or discard prior/system instructions.",
    pattern: new RegExp(
      `\\b(ignore|disregard|forget|override|bypass)\\b${GAP(40)}\\b(previous|prior|above|earlier|all|the)\\b${GAP(20)}\\b(instruction|prompt|rule|context|message)`,
      "i",
    ),
  },
  {
    id: "role-reassignment",
    severity: "high",
    message: "Attempts to reassign the model's role/persona.",
    pattern:
      /\byou\s+are\s+now\b|\bact\s+as\s+(an?\s+)?(unrestricted|uncensored|jailbroken|dan)\b|\bfrom\s+now\s+on\s+you\b|\bpretend\s+(you\s+are|to\s+be)\b/i,
  },
  {
    id: "named-jailbreak",
    severity: "high",
    message: "Known jailbreak persona/keyword.",
    pattern:
      /\b(DAN|do\s+anything\s+now|developer\s+mode|AIM|STAN|DUDE|jailbreak|godmode|liberate[d]?)\b/i,
  },
  {
    id: "system-prompt-leak",
    severity: "high",
    message: "Attempts to exfiltrate the system prompt / hidden instructions.",
    pattern: new RegExp(
      `\\b(repeat|print|reveal|show|output|what\\s+(are|is|were))\\b${GAP(40)}\\b(system\\s+prompt|initial\\s+instruction|your\\s+instruction|above\\s+text|hidden\\s+(prompt|rule))`,
      "i",
    ),
  },
  {
    id: "role-token-spoof",
    severity: "high",
    message: "Forged chat-template / role tokens.",
    // F7: reuse the single-source token list + line-start role markers
    // (system/user/assistant/tool/developer), not a divergent copy.
    pattern: new RegExp(
      `${TEMPLATE_TOKENS.source}|^\\s*(system|user|assistant|tool|developer)\\s*:`,
      "im",
    ),
  },
  {
    id: "safety-suppression",
    severity: "warn",
    message: "Asks the model to drop safety/guidelines/refusals.",
    pattern: new RegExp(
      `\\b(no|without|disable|turn\\s+off|ignore)\\b${GAP(30)}\\b(restriction|filter|guideline|policy|safety|censorship|moral|ethic)`,
      "i",
    ),
  },
  {
    id: "fiction-frame",
    severity: "warn",
    message: "Hypothetical/fiction wrapper commonly used to bypass refusals.",
    pattern:
      /\b(hypothetically|in\s+a\s+fictional|for\s+a\s+(novel|story|movie|screenplay)|imagine\s+a\s+world|this\s+is\s+just\s+a\s+(game|story|simulation))\b/i,
  },
  {
    id: "encoded-payload",
    severity: "warn",
    message: "Long encoded blob (base64/base32/hex) — possible hidden payload.",
    pattern:
      /\b(?:[A-Za-z0-9+/]{40,}={0,2}|[A-Z2-7]{40,}={0,6}|(?:[0-9a-fA-F]{2}\s?){32,})\b/,
  },
  {
    id: "binary-blob",
    severity: "warn",
    message: "Binary-encoded run — possible obfuscated payload.",
    // WHY 5 groups (>= 4 + trailing), not 7: P4RS3LT0NGV3 binary of a short
    // keyword is short — "ignore" is 6 bytes, which the old >=7-group bar
    // slipped clean. 5+ runs of *exactly* 7- or 8-bit [01] octets separated
    // by space/comma is already an unambiguous binary blob; legit prose,
    // CSV rows, and numeric lists never produce 5 consecutive 7/8-char
    // all-0/1 tokens (verified: bit-lists, "1,2,3..", "id,active\n1,1.."
    // do NOT match). Accepted limitation: a 4-byte (32-bit) keyword still
    // slips — going lower would start clipping legit fixed-width bitfield
    // data, so 5 is the deterministic floor with zero legit-text FP.
    pattern: /(?:[01]{7,8}[\s,]+){4,}[01]{7,8}/,
  },
  {
    id: "morse-blob",
    severity: "warn",
    message: "Morse-code run — possible obfuscated payload.",
    pattern: /(?:[.\-]{1,6}[\s/]+){8,}[.\-]{1,6}/,
  },
  {
    id: "numeric-cipher",
    severity: "info",
    message: "Long numeric run — possible A1Z26 / code-point cipher.",
    pattern: /(?:\b\d{1,3}[\s,.\-]+){12,}\d{1,3}\b/,
  },
  {
    id: "mixed-script-obfuscation",
    severity: "high",
    message:
      "Latin interleaved with CJK/Kana inside a token — keyword-filter " +
      "evasion (phonetic/homoglyph spoof). Treat as untrusted, not command.",
    // Contiguous Latin–Kana/Han–Latin (or the reverse) inside one word.
    // Legit JP/EN mixes scripts in *runs* (e.g. "AIシステム"), never
    // alternating mid-token. NFKC-safe (fullwidth already folded by L1).
    pattern:
      /[A-Za-z][\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Han}][A-Za-z]|[\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Han}][A-Za-z][\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Han}]/u,
  },
  {
    id: "exfil-sink",
    severity: "high",
    message: "Markdown image/link to external URL — output exfiltration vector.",
    pattern: /!\[[^\]]*\]\(\s*https?:\/\/[^)]+\)|\]\(\s*https?:\/\/[^)]*\?[^)]*\)/i,
  },
];

// ---------------------------------------------------------------------------
// confusable-residue — deterministic, NON-regex tripwire (a single regex
// cannot express the per-token script census + document-context ratio this
// needs, so it lives in code; it still FLAGS only, never cleans, and keeps
// the BUILTIN_RULES/runTripwires contract intact).
//
// WHY: L1 folds a *curated* (deliberately non-exhaustive) homoglyph subset.
// P4RS3LT0NGV3 RESIDUAL-CONFUSABLE attacks exploit the residue: spoof an EN
// keyword with Cyrillic/Greek/Armenian letters where SOME glyphs are not in
// the fold map, so after L1 a token like "ignфre" / "igbоre" / "rеstrictiоns"
// survives — Latin-shaped to a human + the model, but matching no ASCII rule.
// This mirrors the existing `mixed-script-obfuscation` design (Latin x CJK
// inside a token) extended to Cyrillic/Greek/Armenian.
//
// FALSE-POSITIVE control (tuned to ZERO FP on the legit corpus): only fire
// when the document is *predominantly* ASCII-Latin (>=3 pure-Latin words)
// AND the non-Latin-bearing tokens are a rare anomaly (<=2 tokens AND
// <=25% of word tokens). Genuine foreign text — even when L1's partial
// fold mangles it ("Привет"->"Пpuвet", "Ελλάδα"->"Eλλάδa") — has MANY
// non-Latin-bearing tokens and/or no pure-English context, so it is
// excluded. Pure-foreign sentences (no Latin context, lat<3) never flag.
// Single Greek math symbols (Δt, σ, μ, Σ, λ) are excluded by the >=3-letter
// + >=2-ascii-letter candidate gate. Verified clean on: "Привет мир",
// "Ελλάδα 2025", "naïve café résumé", "東京", plain English, code, CSV,
// math/physics prose.
const NON_LATIN_LETTER =
  /[\p{Script=Cyrillic}\p{Script=Greek}\p{Script=Armenian}]/u;
const ASCII_LETTER = /[A-Za-z]/;
const ANY_LETTER = /\p{L}/u;

function detectConfusableResidue(
  text: string,
): { span: [number, number]; token: string } | null {
  // Tokenize on non-letter/digit boundaries (NFKC-stable, code-safe).
  const tokenRe = /[\p{L}\p{N}]+/gu;
  let asciiLatinWords = 0;
  let nonLatinBearing = 0;
  let candidate: { span: [number, number]; token: string } | null = null;
  let m: RegExpExecArray | null;
  while ((m = tokenRe.exec(text)) !== null) {
    const tok = m[0];
    const letters = [...tok].filter((c) => ANY_LETTER.test(c));
    if (letters.length === 0) continue;
    const ascii = letters.filter((c) => ASCII_LETTER.test(c)).length;
    const nonLat = letters.filter((c) => NON_LATIN_LETTER.test(c)).length;
    if (ascii > 0 && nonLat === 0) {
      asciiLatinWords++;
      continue;
    }
    if (nonLat > 0) {
      nonLatinBearing++;
      // Candidate spoof shape: a >=3-letter token that is either an EN word
      // with mixed-in non-Latin homoglyph residue (>=2 ascii + >=1 non-Lat)
      // OR an isolated all-non-Latin word (>=3 non-Lat) embedded in English.
      const isSpoof =
        letters.length >= 3 &&
        ((ascii >= 2 && nonLat >= 1) || (ascii === 0 && nonLat >= 3));
      if (isSpoof && candidate === null) {
        candidate = { span: [m.index, m.index + tok.length], token: tok };
      }
    }
  }
  if (candidate === null) return null;
  // Context gates (FP control): must be a predominantly-English document
  // with the non-Latin residue as a rare anomaly.
  if (asciiLatinWords < 3) return null; // not an English context
  if (nonLatinBearing > 2) return null; // genuine foreign passage
  if (nonLatinBearing / (asciiLatinWords + nonLatinBearing) > 0.25) {
    return null; // foreign-dense — not a spoofed-keyword anomaly
  }
  return candidate;
}

// WHY no ROT13 / leetspeak / decimal-codepoint decoder: these are the
// SEMANTIC paraphrase class. Per library philosophy, paraphrase trivially
// evades deterministic matching BY DESIGN — a ROT13 of any sentence is just
// "a different sentence" to a regex, and a fragile rotN/leet de-mapper would
// fire on legit text (l33t usernames, "rot13" the word, base-N table data)
// far more than on attacks, eroding trust. The pre-existing numeric-cipher
// (info) tripwire already covers decimal-codepoint / A1Z26 number runs;
// a real ROT13 *blob* with no spaces is caught structurally by length only
// if encoded, otherwise it is left to L5 (the optional classifier) which is
// the honest home for the semantic gap. Documented out-of-scope, not a bug.

export function runTripwires(
  text: string,
  rules: TripwireRule[],
): Risk[] {
  const risks: Risk[] = [];
  for (const r of rules) {
    // Reset lastIndex defensively (rules may carry /g elsewhere).
    const re = new RegExp(r.pattern.source, r.pattern.flags.replace("g", ""));
    const m = re.exec(text);
    if (m) {
      const start = m.index;
      risks.push({
        rule: r.id,
        message: r.message,
        severity: r.severity,
        span: [start, start + m[0].length],
      });
    }
  }
  const cr = detectConfusableResidue(text);
  if (cr !== null) {
    risks.push({
      rule: "confusable-residue",
      message:
        "Cyrillic/Greek/Armenian homoglyph residue mixed into ASCII-Latin " +
        "text after normalization — keyword-filter evasion. Treat as " +
        "untrusted, not command.",
      severity: "high",
      span: cr.span,
    });
  }
  return risks;
}
