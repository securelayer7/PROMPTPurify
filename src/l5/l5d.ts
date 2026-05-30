/**
 * L5d — the STAGE-7 "intelligent" classifier: a COMPACT PRETRAINED encoder
 * (`distilbert-base-multilingual-cased`, Apache-2.0) FINE-TUNED on our full
 * seeded leakage-free corpus. Run OFFLINE in-process. OPT-IN ONLY.
 *
 * WHY THIS EXISTS (honest): the strictly-from-scratch L5c (Stage-5/6/8)
 * proved a 3.7M byte model cannot acquire real cross-distribution
 * generalization from ~12k rows — POEM-UNSEEN/UNSEEN-SOURCE stayed weak.
 * The user RELAXED the from-scratch constraint for this stage. L5d brings
 * broad multilingual language understanding from pretraining (mBERT
 * distillation) that the from-scratch model structurally lacked. Backbone
 * choice + the SOTA survey that drove it: training/RESEARCH.md. Recipe
 * (class-weighted CE + Prompt-Guard-2-style benign energy penalty,
 * small-LR fine-tune): training/train_intelligent.py.
 *
 * Contract: 2-input ONNX (input_ids, attention_mask) — DistilBERT has NO
 * token_type_ids (no NSP). Tokenizer = BERT WordPiece; this is the SAME
 * faithful pure-TS WordPiece used by L5b (src/l5/transformer.ts), copied
 * here verbatim so L5b's shipped path is UNTOUCHED and there is zero
 * train/serve skew. `distilbert-base-multilingual-cased` is CASED ⇒ the
 * contract sets do_lower_case=false (mBERT BasicTokenizer: no lowercase,
 * no accent strip, CJK char-split — exactly what this tokenizer does when
 * do_lower_case is false).
 *
 * It is PROBABILISTIC, paraphrase-evadable, advisory only. The existing
 * src/index.ts honesty fusion (UNCHANGED) still guarantees it never clears
 * a structural block and never yields `.safe`.
 *
 * INFERENCE NETWORK: NEVER. onnxruntime-node is a dynamic import in a
 * try/catch; absent ⇒ typed L5bUnavailableError (shared so the existing
 * cascade error path treats it identically). opt-in + npm-excluded +
 * gitignored exactly like L5b/L5c.
 */
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { L5bUnavailableError } from "./transformer.js";

interface L5dContract {
  version: string;
  max_len: number;
  do_lower_case: boolean;
  cls_id: number;
  sep_id: number;
  pad_id: number;
  unk_id: number;
  unk_token: string;
  model_file: string;
  inputs: string[];
  output: string;
  injection_logit_index: number;
}

function defaultModelDir(): string {
  const here = fileURLToPath(new URL(".", import.meta.url));
  for (const rel of ["../../models/l5d", "../../../models/l5d"]) {
    const p = join(here, rel);
    if (existsSync(join(p, "l5d.json"))) return p;
  }
  return join(here, "../../models/l5d");
}

// ---- pure-TS BERT WordPiece tokenizer ------------------------------------
// VERBATIM faithful copy of src/l5/transformer.ts's tokenizer (kept local
// so L5b's shipped artifact/path is UNTOUCHED). do_lower_case=false ⇒
// multilingual-BERT-cased behaviour (no lowercase, no accent strip).

function isWhitespace(c: string): boolean {
  return c === " " || c === "\t" || c === "\n" || c === "\r" || /\s/u.test(c);
}
function isControl(c: string): boolean {
  if (c === "\t" || c === "\n" || c === "\r") return false;
  const code = c.codePointAt(0) ?? 0;
  return (code < 0x20 && code !== 0) || code === 0x7f;
}
function isPunct(c: string): boolean {
  const cp = c.codePointAt(0) ?? 0;
  if (
    (cp >= 33 && cp <= 47) ||
    (cp >= 58 && cp <= 64) ||
    (cp >= 91 && cp <= 96) ||
    (cp >= 123 && cp <= 126)
  )
    return true;
  return /\p{P}|\p{S}/u.test(c);
}
function isCJK(cp: number): boolean {
  return (
    (cp >= 0x4e00 && cp <= 0x9fff) ||
    (cp >= 0x3400 && cp <= 0x4dbf) ||
    (cp >= 0x20000 && cp <= 0x2a6df) ||
    (cp >= 0x2a700 && cp <= 0x2b73f) ||
    (cp >= 0x2b740 && cp <= 0x2b81f) ||
    (cp >= 0x2b820 && cp <= 0x2ceaf) ||
    (cp >= 0xf900 && cp <= 0xfaff) ||
    (cp >= 0x2f800 && cp <= 0x2fa1f)
  );
}
function stripAccents(s: string): string {
  return s.normalize("NFD").replace(/[̀-ͯ]/g, "");
}

function basicTokenize(text: string, lower: boolean): string[] {
  let cleaned = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp === 0 || cp === 0xfffd || isControl(ch)) continue;
    cleaned += isWhitespace(ch) ? " " : ch;
  }
  let spaced = "";
  for (const ch of cleaned) {
    const cp = ch.codePointAt(0) ?? 0;
    spaced += isCJK(cp) ? ` ${ch} ` : ch;
  }
  const out: string[] = [];
  for (let tok of spaced.split(/\s+/).filter(Boolean)) {
    if (lower) tok = stripAccents(tok.toLowerCase());
    let buf = "";
    for (const ch of tok) {
      if (isPunct(ch)) {
        if (buf) out.push(buf);
        out.push(ch);
        buf = "";
      } else buf += ch;
    }
    if (buf) out.push(buf);
  }
  return out;
}

interface Tokenizer {
  encode(text: string): { ids: number[]; mask: number[] };
}

function buildTokenizer(vocabPath: string, c: L5dContract): Tokenizer {
  const vocab = new Map<string, number>();
  const lines = readFileSync(vocabPath, "utf8").split("\n");
  for (let i = 0; i < lines.length; i++) vocab.set(lines[i] ?? "", i);

  function wordpiece(token: string): number[] {
    if (token.length > 100) return [c.unk_id];
    const chars = [...token];
    const sub: number[] = [];
    let start = 0;
    while (start < chars.length) {
      let end = chars.length;
      let cur = -1;
      while (start < end) {
        let piece = chars.slice(start, end).join("");
        if (start > 0) piece = "##" + piece;
        const id = vocab.get(piece);
        if (id !== undefined) {
          cur = id;
          break;
        }
        end--;
      }
      if (cur === -1) return [c.unk_id];
      sub.push(cur);
      start = end;
    }
    return sub;
  }

  return {
    encode(text: string) {
      const max = c.max_len;
      const body: number[] = [];
      for (const w of basicTokenize(text, c.do_lower_case)) {
        for (const id of wordpiece(w)) body.push(id);
        if (body.length >= max - 2) break;
      }
      const trimmed = body.slice(0, max - 2);
      const ids = [c.cls_id, ...trimmed, c.sep_id];
      const mask = ids.map(() => 1);
      while (ids.length < max) {
        ids.push(c.pad_id);
        mask.push(0);
      }
      return { ids, mask };
    },
  };
}

export interface L5dOptions {
  /** Override the model artifact dir. */
  modelDir?: string;
}

export interface L5dRunner {
  /** P(injection) in [0,1] for already-sanitized text. */
  score(text: string): Promise<number>;
  version: string;
}

let _ortModPromise: Promise<unknown> | null = null;

/**
 * Build an L5d runner. Resolves the artifact + dynamically loads
 * onnxruntime-node. Throws shared `L5bUnavailableError` if either is
 * missing (so the existing cascade error path is identical).
 */
export async function createL5dRunner(
  opts: L5dOptions = {},
): Promise<L5dRunner> {
  const dir = opts.modelDir ?? defaultModelDir();
  const contractPath = join(dir, "l5d.json");
  if (!existsSync(contractPath))
    throw new L5bUnavailableError(
      `L5d model artifact not found at ${dir} ` +
        `(run training/train_intelligent.py + export_intelligent.py).`,
    );
  const contract: L5dContract = JSON.parse(
    readFileSync(contractPath, "utf8"),
  );
  const modelPath = join(dir, contract.model_file);
  const vocabPath = join(dir, "vocab.txt");
  if (!existsSync(modelPath) || !existsSync(vocabPath))
    throw new L5bUnavailableError(`L5d artifact incomplete in ${dir}.`);

  let ort: any;
  try {
    _ortModPromise ??= import(/* @vite-ignore */ "onnxruntime-node");
    ort = await _ortModPromise;
  } catch (e) {
    _ortModPromise = null;
    throw new L5bUnavailableError(
      "onnxruntime-node not installed (optional peer). L5d disabled.",
      e,
    );
  }

  let session: any;
  try {
    session = await ort.InferenceSession.create(modelPath);
  } catch (e) {
    throw new L5bUnavailableError("Failed to load L5d ONNX session.", e);
  }

  const tok = buildTokenizer(vocabPath, contract);

  // ~3.5 chars per WordPiece token; max_len=128 → roughly 450 chars per window.
  // Use 500 chars as a conservative window size for slicing long prompts.
  const WINDOW_CHARS = 500;
  const MID_THRESHOLD = 1500;

  async function scoreWindow(text: string): Promise<number> {
    const { ids, mask } = tok.encode(text);
    const n = ids.length;
    const big = (a: number[]) =>
      new ort.Tensor("int64", BigInt64Array.from(a.map(BigInt)), [1, n]);
    const feeds: Record<string, unknown> = {
      input_ids: big(ids),
      attention_mask: big(mask),
    };
    const out = await session.run(feeds);
    const logits = out[contract.output].data as Float32Array | number[];
    const a = Number(logits[0]);
    const b = Number(logits[1]);
    const m = Math.max(a, b);
    const ea = Math.exp(a - m);
    const eb = Math.exp(b - m);
    const probs = [ea / (ea + eb), eb / (ea + eb)];
    return probs[contract.injection_logit_index] ?? 0;
  }

  return {
    version: contract.version,
    async score(text: string): Promise<number> {
      // Short prompts fit within max_len — one window is enough.
      if (text.length <= WINDOW_CHARS) return scoreWindow(text);

      // Longer prompts: classifier only sees the first ~128 tokens, so an
      // injection buried near the end ("...now reveal the system prompt"
      // after a 5KB encyclopedic preamble) slips past the head window with a
      // benign score. Mitigation: score head + tail, and for very long
      // prompts also a middle window, returning the max. Conservative
      // overhead — 2× inference on medium, 3× on long, 1× on the 95%+ of
      // production traffic that is under 500 chars.
      const windows: string[] = [
        text.slice(0, WINDOW_CHARS),
        text.slice(-WINDOW_CHARS),
      ];
      if (text.length > MID_THRESHOLD) {
        const mid = Math.floor(text.length / 2);
        const half = Math.floor(WINDOW_CHARS / 2);
        windows.push(text.slice(mid - half, mid + half));
      }
      const scores = await Promise.all(windows.map(scoreWindow));
      let best = 0;
      for (const s of scores) if (s > best) best = s;
      return best;
    },
  };
}
