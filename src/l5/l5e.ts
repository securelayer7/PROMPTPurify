/**
 * L5e — the STAGE-9 "100% OURS" classifier: OUR OWN compact encoder,
 * self-pretrained from RANDOM init (no teacher, no downloaded weights) via
 * ELECTRA replaced-token-detection on permissively-licensed open corpora
 * WE chose, with OUR OWN 32k WordPiece fit on that pretrain corpus, then
 * fine-tuned on our seeded leakage-free injection corpus. Run OFFLINE
 * in-process. OPT-IN ONLY.
 *
 * WHY THIS EXISTS (honest): from-scratch L5c could not generalize
 * (POEM-UNSEEN/UNSEEN-SOURCE weak from ~12k rows); the Stage-7 l5d proved
 * a *pretrained* prior fixes that but used a third-party backbone
 * (distil-mBERT) AND over-fired on OOD-benign (9.45% FP). L5e is the
 * "build our own prior" answer: a ~15-16M-param ELECTRA-small (ALiBi,
 * bias-free) pretrained on a deliberately >=40%-benign-breadth open
 * corpus (the literature-correct V9 FP fix), so the prior treats
 * instruction/chat/email/code/multilingual registers as ordinary.
 * Pretrain plan + corpus licenses: training/PRETRAIN_PLAN.md,
 * training/PRETRAIN_RESEARCH.md, models/l5e/CORPUS_LICENSES.json. Fine-tune
 * recipe: training/train_intelligent.py (L5D_BACKBONE -> our pretrain dir).
 *
 * Contract: 2-input ONNX (input_ids, attention_mask) — ELECTRA has NO
 * token_type_ids needed here. Tokenizer = OUR WordPiece vocab, consumed by
 * the SAME faithful pure-TS BERT-WordPiece used by L5b/L5d
 * (src/l5/transformer.ts), copied here verbatim so L5b/L5d shipped paths
 * are UNTOUCHED and there is zero train/serve skew. Our vocab is cased ⇒
 * the contract sets do_lower_case=false.
 *
 * It is PROBABILISTIC, paraphrase-evadable, advisory only. The existing
 * src/index.ts honesty fusion (UNCHANGED) still guarantees it never clears
 * a structural block and never yields `.safe`.
 *
 * INFERENCE NETWORK: NEVER. onnxruntime-node is a dynamic import in a
 * try/catch; absent ⇒ typed L5bUnavailableError (shared so the existing
 * cascade error path treats it identically). opt-in + npm-excluded +
 * gitignored exactly like L5b/L5c/L5d.
 */
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { L5bUnavailableError } from "./transformer.js";

interface L5eContract {
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
  /**
   * V13 trust-frame marker token IDs (e.g., [UNTRUSTED]). Prepended after
   * [CLS] so training and inference see the same `[CLS] marker body [SEP]`
   * layout. Empty/absent on pre-V13 contracts — runtime falls back to
   * `[CLS] body [SEP]`.
   */
  prefix_token_ids?: number[];
}

function defaultModelDir(): string {
  const here = fileURLToPath(new URL(".", import.meta.url));
  for (const rel of ["../../models/l5e", "../../../models/l5e"]) {
    const p = join(here, rel);
    if (existsSync(join(p, "l5e.json"))) return p;
  }
  return join(here, "../../models/l5e");
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

function buildTokenizer(vocabPath: string, c: L5eContract): Tokenizer {
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

  const prefix = Array.isArray(c.prefix_token_ids) ? c.prefix_token_ids : [];
  return {
    encode(text: string) {
      const max = c.max_len;
      const reserved = 2 + prefix.length; // [CLS] + prefix + [SEP]
      const body: number[] = [];
      for (const w of basicTokenize(text, c.do_lower_case)) {
        for (const id of wordpiece(w)) body.push(id);
        if (body.length >= max - reserved) break;
      }
      const trimmed = body.slice(0, max - reserved);
      const ids = [c.cls_id, ...prefix, ...trimmed, c.sep_id];
      const mask = ids.map(() => 1);
      while (ids.length < max) {
        ids.push(c.pad_id);
        mask.push(0);
      }
      return { ids, mask };
    },
  };
}

export interface L5eOptions {
  /** Override the model artifact dir. */
  modelDir?: string;
}

export interface L5eRunner {
  /** P(injection) in [0,1] for already-sanitized text. */
  score(text: string): Promise<number>;
  version: string;
}

let _ortModPromise: Promise<unknown> | null = null;

/**
 * Build an L5e runner. Resolves the artifact + dynamically loads
 * onnxruntime-node. Throws shared `L5bUnavailableError` if either is
 * missing (so the existing cascade error path is identical).
 */
export async function createL5eRunner(
  opts: L5eOptions = {},
): Promise<L5eRunner> {
  const dir = opts.modelDir ?? defaultModelDir();
  const contractPath = join(dir, "l5e.json");
  if (!existsSync(contractPath))
    throw new L5bUnavailableError(
      `L5e model artifact not found at ${dir} ` +
        `(run training/train_intelligent.py + export_intelligent.py).`,
    );
  const contract: L5eContract = JSON.parse(
    readFileSync(contractPath, "utf8"),
  );
  const modelPath = join(dir, contract.model_file);
  const vocabPath = join(dir, "vocab.txt");
  if (!existsSync(modelPath) || !existsSync(vocabPath))
    throw new L5bUnavailableError(`L5e artifact incomplete in ${dir}.`);

  let ort: any;
  try {
    _ortModPromise ??= import(/* @vite-ignore */ "onnxruntime-node");
    ort = await _ortModPromise;
  } catch (e) {
    _ortModPromise = null;
    throw new L5bUnavailableError(
      "onnxruntime-node not installed (optional peer). L5e disabled.",
      e,
    );
  }

  let session: any;
  try {
    session = await ort.InferenceSession.create(modelPath);
  } catch (e) {
    throw new L5bUnavailableError("Failed to load L5e ONNX session.", e);
  }

  const tok = buildTokenizer(vocabPath, contract);

  // ~3.5 chars per WordPiece token; max_len=128 → roughly 450 chars per window.
  // Sliding 500ch / 250 stride gives full coverage of long prompts — closes
  // the gap on buried-tail injection attacks where the leak-ask is between
  // fixed head/mid/tail anchors.
  const WINDOW_CHARS = 500;
  const STRIDE_CHARS = 250;

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
      if (text.length <= WINDOW_CHARS) return scoreWindow(text);

      // Sliding window across the full text. Buried-tail attacks place the
      // leak-ask between wiki padding head and wiki padding tail — fixed
      // head/mid/tail anchors miss anywhere else. 500ch windows with 250
      // stride give 50% overlap and full coverage: a 4000-char prompt →
      // ~15 windows (~75ms total on int8 ELECTRA-small).
      const windows: string[] = [];
      for (let s = 0; s + WINDOW_CHARS <= text.length; s += STRIDE_CHARS) {
        windows.push(text.slice(s, s + WINDOW_CHARS));
      }
      const lastWindow = windows[windows.length - 1];
      if (windows.length === 0 || (lastWindow && lastWindow.length !== WINDOW_CHARS)) {
        windows.push(text.slice(-WINDOW_CHARS));
      }
      const scores = await Promise.all(windows.map(scoreWindow));
      let best = 0;
      for (const s of scores) if (s > best) best = s;
      return best;
    },
  };
}
