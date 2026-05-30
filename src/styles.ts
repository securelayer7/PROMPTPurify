/**
 * L1 style-fold — defeats P4RS3LT0NGV3-class "Unicode style" transforms that
 * NFKC does NOT fold but the model still reads as plain letters.
 *
 * NFKC already folds: Mathematical Bold/Italic/Fraktur/Double-struck/
 * Monospace/Sans, Fullwidth (vaporwave), most circled/parenthesized,
 * super/subscript. Those need no table here.
 *
 * NFKC does NOT fold these (real distinct codepoints) — so "ɪɢɴᴏʀᴇ",
 * "🇮🇬🇳🇴🇷🇪", "ǝɹouƃı" sail past keyword detection. We fold them.
 */

// U+1D00.. Latin Letter Small Capital block (subset Parseltongue uses).
const SMALL_CAPS: Record<string, string> = {
  "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ꜰ": "f",
  "ɢ": "g", "ʜ": "h", "ɪ": "i", "ᴊ": "j", "ᴋ": "k", "ʟ": "l",
  "ᴍ": "m", "ɴ": "n", "ᴏ": "o", "ᴘ": "p", "ǫ": "q", "ꞯ": "q",
  "ʀ": "r", "ꜱ": "s", "ᴛ": "t", "ᴜ": "u", "ᴠ": "v",
  "ᴡ": "w", "ʏ": "y", "ᴢ": "z",
};

// Parenthesized Latin small letters U+249C..U+24B5 ((a)..(z)).
// IMPORTANT: NFKC runs upstream of foldStyles and already expands these
// to the literal 3-char form "(i)(g)(n)(o)(r)(e)" — so a codepoint table
// would never match here. Instead collapse a RUN of >=2 adjacent
// single-letter "(x)" groups (with no separators) back to "x". A lone
// "(a)" (legit in code/prose) is left intact; only the contiguous
// per-letter-parenthesized keyword pattern — which has no real-text use —
// is folded. Idempotent: output has no "(x)(y)" run to re-match.
const PAREN_LETTER_RUN = /(?:\([A-Za-z]\)){2,}/g;
function foldParenthesizedRun(s: string): { out: string; n: number } {
  let n = 0;
  const out = s.replace(PAREN_LETTER_RUN, (m) => {
    const letters = m.replace(/[()]/g, "");
    n += m.length - letters.length; // count the stripped parens
    return letters;
  });
  return { out, n };
}

// Negative-squared (white-on-black) Latin U+1F170..U+1F189 (🅰..🆉).
// NFKC leaves these untouched (distinct emoji-ish codepoints), so
// "🅸🅶🅽🅾🆁🅴" sails past keyword detection. Fold to lowercase ASCII.
const NEGATIVE_SQUARED: Record<string, string> = (() => {
  const t: Record<string, string> = {};
  for (let i = 0; i < 26; i++) {
    t[String.fromCodePoint(0x1f170 + i)] = String.fromCharCode(0x61 + i);
  }
  return t;
})();

// Upside-down (flipped) — reverse of the common bijection.
const UPSIDE_DOWN: Record<string, string> = {
  "ɐ": "a", "q": "b", "ɔ": "c", "p": "d", "ǝ": "e", "ɟ": "f",
  "ƃ": "g", "ɥ": "h", "ᴉ": "i", "ɾ": "j", "ʞ": "k", "l": "l",
  "ɯ": "m", "u": "n", "o": "o", "d": "p", "b": "q", "ɹ": "r",
  "s": "s", "ʇ": "t", "n": "u", "ʌ": "v", "ʍ": "w", "x": "x",
  "ʎ": "y", "z": "z",
  "ı": "i", // dotless i — common 'i' bypass glyph
};

function foldTable(s: string, table: Record<string, string>): { out: string; n: number } {
  let n = 0;
  let out = "";
  for (const ch of s) {
    const m = table[ch];
    if (m !== undefined) {
      n++;
      out += m;
    } else {
      out += ch;
    }
  }
  return { out, n };
}

// Regional Indicator Symbols U+1F1E6..U+1F1FF -> A..Z (flag-letter trick).
function foldRegionalIndicators(s: string): { out: string; n: number } {
  let n = 0;
  const out = s.replace(/[\u{1F1E6}-\u{1F1FF}]/gu, (ch) => {
    n++;
    return String.fromCharCode(
      0x41 + ((ch.codePointAt(0) as number) - 0x1f1e6),
    );
  });
  return { out, n };
}

// Distinctly-flipped glyphs with NO normal-text use. Presence of one of
// these in a token is the trigger to treat the whole flipped run as
// upside-down text.
const FLIPPED_ONLY = /[ǝɟƃɥɯɹʇʌʍʎɐɔʞᴉ]/u;

/**
 * Upside-down text is glyph-flipped AND character-order-reversed:
 * "ignore" -> "ǝɹouƃı". We fold the GLYPHS back ("ǝɹouƃı" -> "erongi") but
 * deliberately do NOT reverse character/word order.
 *
 * WHY no order reversal (regression post-mortem): there is no content-only
 * deterministic rule that can tell "this run is upside-down text" from "a
 * benign word that happens to contain a flipped glyph" (looʞ, ǝmail) — the
 * discriminator is intent, which patterns cannot see. A blind whole-span
 * reverse scrambles word order on per-word-flipped payloads (turning a
 * detectable injection back into an UNdetectable one — a self-inflicted
 * bypass) and silently corrupts benign tokens. A per-token reverse still
 * corrupts the benign case. Both trade one documented limitation for a
 * worse, silent one. So: glyph-fold only. The keyword may stay scrambled
 * ("erongi"); reconstructing reversed text is a SEMANTIC judgement and
 * belongs to the L5 intelligence layer, not L1 mechanical normalization.
 * Honest-about-limits > clever-but-wrong.
 *
 * Deterministic, idempotent (folded output has no FLIPPED_ONLY glyph).
 */
function foldUpsideDown(s: string): { out: string; n: number } {
  return foldTable(s, UPSIDE_DOWN);
}

/** Fold all non-NFKC style transforms. Returns total chars folded. */
export function foldStyles(input: string): { text: string; folded: number } {
  let folded = 0;
  let s = input;

  const sc = foldTable(s, SMALL_CAPS);
  s = sc.out;
  folded += sc.n;

  const par = foldParenthesizedRun(s);
  s = par.out;
  folded += par.n;

  const ns = foldTable(s, NEGATIVE_SQUARED);
  s = ns.out;
  folded += ns.n;

  const ri = foldRegionalIndicators(s);
  s = ri.out;
  folded += ri.n;

  // Upside-down: glyph-fold ONLY (no order reversal — see foldUpsideDown).
  if (FLIPPED_ONLY.test(s)) {
    const ud = foldUpsideDown(s);
    s = ud.out;
    folded += ud.n;
  }

  return { text: s, folded };
}
