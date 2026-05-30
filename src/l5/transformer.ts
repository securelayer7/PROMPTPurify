/**
 * L5b — OUR OWN distilled tiny transformer, run OFFLINE in-process.
 *
 * WHAT THIS IS (honest): a ~41M-param `prajjwal1/bert-medium`-class student
 * (8 layers / hidden 512) we trained by KNOWLEDGE DISTILLATION from an open
 * prompt-injection teacher used OFFLINE only to soft-label our REAL-DATA
 * train split (training/distill.py). STAGE-4 capacity upgrade: it replaces
 * the prior ~4.4M-param bert-tiny student, which three retrains (v3/v4/v5)
 * proved had a hard capacity ceiling (poem-unseen recall flat at 6.67%).
 * bert-medium uses the SAME BERT-uncased WordPiece vocab + token_type_ids
 * 3-input contract as bert-tiny, so the pure-TS tokenizer below is
 * UNCHANGED. We do NOT redistribute teacher weights — only the distilled
 * student ships, as an INT8-quantized ONNX (larger than bert-tiny's;
 * opt-in + excluded from the npm tarball). It is PROBABILISTIC,
 * paraphrase-evadable (better than L5a on the semantic slice, not an
 * oracle), advisory only, and the existing honesty fusion in src/index.ts
 * guarantees it never clears a structural block and never yields `.safe`.
 *
 * INFERENCE NETWORK: NEVER. `onnxruntime-node` is loaded by a DYNAMIC import
 * inside a try/catch. If it (or the model artifact) is absent we throw a
 * typed `L5bUnavailableError`. The cascade lets that propagate so the
 * EXISTING classifier-error path in inspectAsync turns it into an `info`
 * risk — degraded, never false-safe.
 *
 * Tokenizer: a minimal pure-TS WordPiece (BERT uncased basic-tokenize +
 * greedy longest-match) loading vocab.txt from the artifact. We deliberately
 * AVOID @xenova/transformers: it is a multi-MB peer that would re-introduce
 * the heavy-dep problem L5b is engineered to keep optional. A faithful
 * ~120-line WordPiece is the lighter, auditable path and is sufficient for
 * the short (max_len 128) inputs this stage sees.
 */
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** Thrown when onnxruntime-node or the model artifact is unavailable. */
export class L5bUnavailableError extends Error {
  constructor(message: string, public cause?: unknown) {
    super(message);
    this.name = "L5bUnavailableError";
  }
}

interface Contract {
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

/** Default in-repo artifact dir (staged v2). See training/DISTRIBUTION.md. */
function defaultModelDir(): string {
  const here = fileURLToPath(new URL(".", import.meta.url));
  // dist/l5/ -> ../../models/l5b  (and src/l5/ in dev/test)
  for (const rel of ["../../models/l5b", "../../../models/l5b"]) {
    const p = join(here, rel);
    if (existsSync(join(p, "l5b.json"))) return p;
  }
  return join(here, "../../models/l5b");
}

// ---- pure-TS BERT WordPiece tokenizer (uncased) ---------------------------

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
// CJK ranges — BERT splits these into single chars.
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

/** BERT BasicTokenizer (lowercase + accent strip + punct/CJK split). */
function basicTokenize(text: string, lower: boolean): string[] {
  let cleaned = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp === 0 || cp === 0xfffd || isControl(ch)) continue;
    cleaned += isWhitespace(ch) ? " " : ch;
  }
  // pad CJK chars so they become standalone tokens
  let spaced = "";
  for (const ch of cleaned) {
    const cp = ch.codePointAt(0) ?? 0;
    spaced += isCJK(cp) ? ` ${ch} ` : ch;
  }
  const out: string[] = [];
  for (let tok of spaced.split(/\s+/).filter(Boolean)) {
    if (lower) tok = stripAccents(tok.toLowerCase());
    // split off punctuation
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

function buildTokenizer(vocabPath: string, c: Contract): Tokenizer {
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
      if (cur === -1) return [c.unk_id]; // unknown -> whole word UNK
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

// ---- ONNX session (lazy, dynamic, offline) --------------------------------

export interface L5bOptions {
  /** Override the model artifact dir (companion-package path in prod). */
  modelDir?: string;
}

export interface L5bRunner {
  /** P(injection) in [0,1] for already-sanitized text. */
  score(text: string): Promise<number>;
  version: string;
}

let _ortModPromise: Promise<unknown> | null = null;

/**
 * Build an L5b runner. Resolves the artifact + dynamically loads
 * onnxruntime-node. Throws `L5bUnavailableError` if either is missing — the
 * cascade lets that flow into the existing classifier-error info-risk path.
 */
export async function createL5bRunner(
  opts: L5bOptions = {},
): Promise<L5bRunner> {
  const dir = opts.modelDir ?? defaultModelDir();
  const contractPath = join(dir, "l5b.json");
  if (!existsSync(contractPath))
    throw new L5bUnavailableError(
      `L5b model artifact not found at ${dir} (see training/DISTRIBUTION.md).`,
    );
  const contract: Contract = JSON.parse(readFileSync(contractPath, "utf8"));
  const modelPath = join(dir, contract.model_file);
  const vocabPath = join(dir, "vocab.txt");
  if (!existsSync(modelPath) || !existsSync(vocabPath))
    throw new L5bUnavailableError(`L5b artifact incomplete in ${dir}.`);

  let ort: any;
  try {
    // DYNAMIC import — optional peer. Never bundled, never in browser.
    _ortModPromise ??= import(/* @vite-ignore */ "onnxruntime-node");
    ort = await _ortModPromise;
  } catch (e) {
    _ortModPromise = null;
    throw new L5bUnavailableError(
      "onnxruntime-node not installed (optional peer). L5b disabled.",
      e,
    );
  }

  let session: any;
  try {
    session = await ort.InferenceSession.create(modelPath);
  } catch (e) {
    throw new L5bUnavailableError("Failed to load L5b ONNX session.", e);
  }

  const tok = buildTokenizer(vocabPath, contract);

  return {
    version: contract.version,
    async score(text: string): Promise<number> {
      const { ids, mask } = tok.encode(text);
      const n = ids.length;
      const big = (a: number[]) =>
        new ort.Tensor("int64", BigInt64Array.from(a.map(BigInt)), [1, n]);
      const feeds: Record<string, unknown> = {
        input_ids: big(ids),
        attention_mask: big(mask),
        token_type_ids: big(new Array(n).fill(0)),
      };
      const out = await session.run(feeds);
      const logits = out[contract.output].data as Float32Array | number[];
      const a = Number(logits[0]);
      const b = Number(logits[1]);
      // softmax over the 2 logits -> P(injection)
      const m = Math.max(a, b);
      const ea = Math.exp(a - m);
      const eb = Math.exp(b - m);
      const probs = [ea / (ea + eb), eb / (ea + eb)];
      return probs[contract.injection_logit_index] ?? 0;
    },
  };
}
