/**
 * L5a — feature extraction (pure, zero-dep, deterministic).
 *
 * Honest framing: this is OUR model — our features, our trained weights. It is
 * a learned CALIBRATOR sitting on top of the deterministic L1–L4 signals, not
 * an oracle. It is PROBABILISTIC: paraphrase-evadable, advisory-only, and it
 * NEVER clears a structural block (the honesty fusion in src/index.ts enforces
 * that — this file only produces numbers).
 *
 * Critical invariant: NO train/serve skew. `scripts/train-l5a.mjs` imports
 * THIS exact function to build the training matrix, so the production feature
 * vector is bit-identical to the one the weights were fit on.
 *
 * All features are computed on already-L1-sanitized text (the existing
 * Classifier contract passes sanitized text), plus the L4 fired-rule ids.
 */

// Override / instruction-suppression verbs (the imperative attack core).
const OVERRIDE_VERBS =
  /\b(ignore|disregard|forget|override|bypass|reveal|print|repeat|pretend|act|leak|expose|dump|exfiltrate)\b/gi;

// Targets an override verb tends to point at in an injection.
const OVERRIDE_TARGETS =
  /\b(instruction|instructions|prompt|prompts|rule|rules|system|context|guideline|guidelines|directive|directives)\b/gi;

// Line-start role marker (chat-template role spoof in plain text).
const ROLE_LINE = /^\s*(system|user|assistant|tool|developer)\s*:/gim;

// Single source of truth for chat-template tokens (mirror of structure.ts —
// kept local so this file stays zero-import and bundles into ./l5 alone).
const TEMPLATE_TOKENS_RE =
  /<\|(?:im_start|im_end|system|user|assistant|endoftext|eot_id|bos|eos|begin_of_text|start_header_id|end_header_id|channel)\|>|\[\/?INST\]|\[\/?SYS\]|<<\/?SYS>>|<\/?s>|<\/?(?:start|end)_of_turn>|(?:\r?\n){1,2}(?:Human|Assistant|System)\s*:/gi;

// Second-person directive openers ("you are now", "from now on you", ...).
const SECOND_PERSON =
  /\b(you\s+are(\s+now)?|you\s+will|you\s+must|from\s+now\s+on\s+you|act\s+as|pretend\s+(you|to))\b/gi;

// Fiction / hypothetical framing n-grams (refusal-bypass wrapper).
const FICTION_FRAME =
  /\b(hypothetically|in\s+a\s+fictional|for\s+a\s+(novel|story|movie|screenplay|play)|imagine\s+a\s+world|this\s+is\s+just\s+a\s+(game|story|simulation)|let'?s\s+role[\s-]?play|in\s+this\s+story)\b/gi;

// Negation immediately before a safety/guard word ("no restrictions", ...).
const NEGATION_NEAR_SAFETY =
  /\b(no|not|without|never|disable|drop|skip|ignore|forget)\b[\s\S]{0,24}?\b(restriction|restrictions|filter|filters|guideline|guidelines|policy|policies|safety|rule|rules|refus(?:e|al)|guard|limit|limits|moral|ethic)/gi;

const URL_RE = /\bhttps?:\/\/[^\s)]+/i;

// Latin letter / non-Latin letter classes for the script-mix feature.
const NON_LATIN_LETTER =
  /[\p{Script=Cyrillic}\p{Script=Greek}\p{Script=Armenian}\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Arabic}\p{Script=Hebrew}]/u;
const ASCII_LETTER = /[A-Za-z]/;

const TOKEN_RE = /[\p{L}\p{N}]+/gu;

// L4 rule -> coarse family. The "distinct families fired" count is the
// single highest-signal feature: it turns L5a into a calibrator over the
// deterministic detectors instead of a from-scratch judge.
const RULE_FAMILY: Record<string, string> = {
  "instruction-override": "override",
  "role-reassignment": "persona",
  "named-jailbreak": "persona",
  "system-prompt-leak": "leak",
  "role-token-spoof": "spoof",
  "safety-suppression": "safety",
  "fiction-frame": "fiction",
  "encoded-payload": "encoded",
  "binary-blob": "encoded",
  "morse-blob": "encoded",
  "numeric-cipher": "encoded",
  "mixed-script-obfuscation": "script",
  "confusable-residue": "script",
  "exfil-sink": "exfil",
};

function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of freq.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function countMatches(s: string, re: RegExp): number {
  const m = s.match(re);
  return m ? m.length : 0;
}

function minTokenDistance(tokens: string[]): number {
  // Min word-gap between any override verb and any override target. A small
  // distance ("ignore the previous instructions") is a strong injection
  // signal; far-apart benign co-occurrence is not.
  const verbIdx: number[] = [];
  const tgtIdx: number[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = (tokens[i] ?? "").toLowerCase();
    if (/^(ignore|disregard|forget|override|bypass|reveal|print|repeat|pretend|act|leak|expose|dump|exfiltrate)$/.test(t))
      verbIdx.push(i);
    if (/^(instruction|instructions|prompt|prompts|rule|rules|system|context|guideline|guidelines|directive|directives)$/.test(t))
      tgtIdx.push(i);
  }
  if (verbIdx.length === 0 || tgtIdx.length === 0) return 1; // normalized "far"
  let min = Infinity;
  for (const v of verbIdx)
    for (const g of tgtIdx) min = Math.min(min, Math.abs(v - g));
  // Squash to 0..1 (0 = adjacent/very close, ->1 = far). 1/(1+d).
  return 1 / (1 + min);
}

function longestRun(s: string, re: RegExp): number {
  let max = 0;
  let m: RegExpExecArray | null;
  const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
  while ((m = g.exec(s)) !== null) {
    if (m[0].length > max) max = m[0].length;
    if (m.index === g.lastIndex) g.lastIndex++;
  }
  return max;
}

export interface FeatureResult {
  vec: number[];
  names: string[];
}

/**
 * Extract the L5a feature vector. Order is FROZEN — weights.gen.ts indexes
 * by position. Adding a feature is a model retrain + version bump.
 */
export function extractFeatures(
  text: string,
  firedRuleIds: string[],
): FeatureResult {
  const tokens = text.match(TOKEN_RE) ?? [];
  const tokenCount = tokens.length || 1;
  const chars = [...text];
  const len = chars.length || 1;

  // Script census.
  let asciiBearing = 0;
  let nonLatinBearing = 0;
  for (const tok of tokens) {
    if (NON_LATIN_LETTER.test(tok)) nonLatinBearing++;
    else if (ASCII_LETTER.test(tok)) asciiBearing++;
  }

  let upper = 0;
  let letters = 0;
  let punct = 0;
  for (const ch of chars) {
    if (/[A-Za-z]/.test(ch)) {
      letters++;
      if (ch >= "A" && ch <= "Z") upper++;
    } else if (/[!-/:-@[-`{-~]/.test(ch)) punct++;
  }

  const families = new Set<string>();
  for (const id of firedRuleIds) {
    const f = RULE_FAMILY[id];
    if (f) families.add(f);
  }

  // base64-charset longest contiguous run (encoded-payload smell).
  const b64Run = longestRun(text, /[A-Za-z0-9+/=]+/);

  const meanTokLen =
    tokens.reduce((a, t) => a + t.length, 0) / tokenCount;

  // ----- FROZEN feature order -----
  const feats: [string, number][] = [
    // WHY: high char entropy = encoded/obfuscated payload, not prose.
    ["char_entropy", shannonEntropy(text)],
    // WHY: forged role markers per 100 tokens = chat-template spoof attempt.
    [
      "role_token_density",
      ((countMatches(text, TEMPLATE_TOKENS_RE) +
        countMatches(text, ROLE_LINE)) /
        tokenCount) *
        100,
    ],
    // WHY: density of imperative override verbs distinguishes commands from prose.
    [
      "override_verb_ratio",
      countMatches(text, OVERRIDE_VERBS) / tokenCount,
    ],
    // WHY: verb sitting RIGHT NEXT TO an instruction noun is the injection core;
    // far-apart benign co-occurrence ("ignore the email ... the invoice rules")
    // scores low — this is the hard-negative discriminator.
    ["override_target_proximity", minTokenDistance(tokens)],
    // WHY: Latin keyword spoofed with foreign glyphs in an English doc.
    ["script_mix_frac", nonLatinBearing / (asciiBearing + nonLatinBearing || 1)],
    // WHY: very short / very long inputs have different base rates.
    ["log_len", Math.log10(1 + len)],
    // WHY: token count, mild prior.
    ["token_count_log", Math.log10(1 + tokenCount)],
    // WHY: long mean token length = blob/encoded run, not words.
    ["mean_token_len", meanTokLen],
    // WHY: SHOUTING / all-caps directives correlate with override attempts.
    ["uppercase_ratio", letters ? upper / letters : 0],
    // WHY: punctuation-heavy = code/cipher/markdown sink, shifts base rate.
    ["punct_ratio", punct / len],
    // WHY: a long non-space run is an encoded blob (base64/hex/binary).
    ["longest_nonspace_run", longestRun(text, /\S+/) / 80],
    // WHY: "no restrictions / drop the rules" — safety-suppression phrasing.
    [
      "negation_near_safety",
      countMatches(text, NEGATION_NEAR_SAFETY) / tokenCount,
    ],
    // WHY: "you are now / from now on you" — persona-reassignment grammar.
    [
      "second_person_density",
      (countMatches(text, SECOND_PERSON) / tokenCount) * 10,
    ],
    // WHY: fiction/hypothetical wrapper is a known refusal-bypass frame.
    ["fiction_frame_hits", countMatches(text, FICTION_FRAME)],
    // WHY: number of DISTINCT L4 families fired — the dominant calibration
    // signal; makes L5a a learned fusion over the deterministic detectors.
    ["l4_families_fired", families.size],
    // WHY: a URL is an exfil channel and shifts injection prior upward.
    ["has_url", URL_RE.test(text) ? 1 : 0],
    // WHY: long base64-charset run = embedded encoded payload.
    ["b64_run_norm", b64Run / 60],
    // WHY: total fired rule count (intensity, not just breadth).
    ["l4_rule_count", firedRuleIds.length],
  ];

  return {
    names: feats.map((f) => f[0]),
    vec: feats.map((f) => (Number.isFinite(f[1]) ? f[1] : 0)),
  };
}
