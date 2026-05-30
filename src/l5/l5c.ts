/**
 * L5c — OUR STRICTLY-FROM-SCRATCH classifier (Stage-5), run OFFLINE
 * in-process. OPT-IN ONLY.
 *
 * WHAT THIS IS (honest): a small Transformer encoder with a RANDOM-INIT
 * embedding table, trained ONLY on our seeded leakage-free corpus — NO
 * pretrained weights of any kind (no BERT/DeBERTa/RoBERTa backbone, NO
 * teacher / distillation, NO pretrained embedder). The tokenizer is a
 * byte-level BPE we FIT ON OUR TRAIN SPLIT ONLY (not "pretrained weights":
 * it is a deterministic merge table, re-implemented faithfully below with
 * zero deps). Maximally "ours".
 *
 * Contract: identical 2-input ONNX feed names as a normal encoder
 * (input_ids, attention_mask) — but NO token_type_ids (this is not a BERT
 * graph). It is PROBABILISTIC, paraphrase-evadable, advisory only; the
 * existing src/index.ts honesty fusion (UNCHANGED) still guarantees it
 * never clears a structural block and never yields `.safe`.
 *
 * INFERENCE NETWORK: NEVER. onnxruntime-node is a dynamic import in a
 * try/catch; absent ⇒ typed L5bUnavailableError, surfaced as an info risk
 * by the existing cascade/inspectAsync path. opt-in + npm-excluded +
 * gitignored exactly like L5b.
 */
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { L5bUnavailableError } from "./transformer.js";

const PAD = 0;
const UNK = 1;
const CLS = 2;

interface L5cContract {
  version: string;
  max_len: number;
  vocab_size: number;
  pad_id: number;
  unk_id: number;
  cls_id: number;
  model_file: string;
  tokenizer_file: string;
  inputs: string[];
  output: string;
  injection_logit_index: number;
}

interface TokBlob {
  tok2id: Record<string, number>;
  merges: [string, string][];
  vocab_size: number;
}

function defaultModelDir(): string {
  const here = fileURLToPath(new URL(".", import.meta.url));
  for (const rel of ["../../models/l5c", "../../../models/l5c"]) {
    const p = join(here, rel);
    if (existsSync(join(p, "l5c.json"))) return p;
  }
  return join(here, "../../models/l5c");
}

/**
 * Faithful pure-TS port of training/train_scratch.py `BPETokenizer`.
 * A symbol is the comma-joined string of its byte ints (the exact key
 * scheme the Python writes). Encoding: split on whitespace runs (keeping
 * the separators, like Python's re.split(r"(\s+)")), UTF-8 encode each
 * chunk to bytes, then greedily apply the lowest-rank merge until none
 * applies — byte-for-byte identical to the trainer so there is zero
 * train/serve skew.
 */
function buildTokenizer(blob: TokBlob) {
  const tok2id = new Map<string, number>();
  for (const [k, v] of Object.entries(blob.tok2id)) tok2id.set(k, v);
  const mergeRank = new Map<string, number>();
  blob.merges.forEach(([a, b], rank) => {
    mergeRank.set(a + "|" + b, rank);
  });

  const enc = new TextEncoder();

  function encodeChunk(bytes: number[]): number[] {
    // each symbol is a string "b" / "b1,b2,..." matching Python tuples
    let sym: string[] = bytes.map((b) => String(b));
    while (sym.length > 1) {
      let best = -1;
      let bi = -1;
      for (let i = 0; i < sym.length - 1; i++) {
        const r = mergeRank.get(sym[i] + "|" + sym[i + 1]);
        if (r !== undefined && (best === -1 || r < best)) {
          best = r;
          bi = i;
        }
      }
      if (bi === -1) break;
      const merged = sym[bi] + "," + sym[bi + 1];
      sym = sym.slice(0, bi).concat([merged], sym.slice(bi + 2));
    }
    return sym.map((s) => tok2id.get(s) ?? UNK);
  }

  return {
    encode(text: string, maxLen: number): { ids: number[]; mask: number[] } {
      const ids: number[] = [CLS];
      // Python: re.split(r"(\s+)", text) keeps the whitespace runs as
      // their own chunks. Mirror exactly.
      const parts = text.split(/(\s+)/);
      for (const chunk of parts) {
        if (!chunk) continue;
        const bs = Array.from(enc.encode(chunk));
        for (const id of encodeChunk(bs)) ids.push(id);
        if (ids.length >= maxLen) break;
      }
      const trimmed = ids.slice(0, maxLen);
      const mask = trimmed.map(() => 1);
      while (trimmed.length < maxLen) {
        trimmed.push(PAD);
        mask.push(0);
      }
      return { ids: trimmed, mask };
    },
  };
}

export interface L5cOptions {
  /** Override the model artifact dir. */
  modelDir?: string;
}

export interface L5cRunner {
  /** P(injection) in [0,1] for already-sanitized text. */
  score(text: string): Promise<number>;
  version: string;
}

let _ortModPromise: Promise<unknown> | null = null;

/**
 * Build an L5c runner. Resolves the artifact + dynamically loads
 * onnxruntime-node. Throws `L5bUnavailableError` (shared typed error so the
 * existing cascade error path treats it identically) if either is missing.
 */
export async function createL5cRunner(
  opts: L5cOptions = {},
): Promise<L5cRunner> {
  const dir = opts.modelDir ?? defaultModelDir();
  const contractPath = join(dir, "l5c.json");
  if (!existsSync(contractPath))
    throw new L5bUnavailableError(
      `L5c model artifact not found at ${dir} ` +
        `(run training/train_scratch.py + training/export_scratch.py).`,
    );
  const contract: L5cContract = JSON.parse(
    readFileSync(contractPath, "utf8"),
  );
  const modelPath = join(dir, contract.model_file);
  const tokPath = join(dir, contract.tokenizer_file);
  if (!existsSync(modelPath) || !existsSync(tokPath))
    throw new L5bUnavailableError(`L5c artifact incomplete in ${dir}.`);

  let ort: any;
  try {
    _ortModPromise ??= import(/* @vite-ignore */ "onnxruntime-node");
    ort = await _ortModPromise;
  } catch (e) {
    _ortModPromise = null;
    throw new L5bUnavailableError(
      "onnxruntime-node not installed (optional peer). L5c disabled.",
      e,
    );
  }

  let session: any;
  try {
    session = await ort.InferenceSession.create(modelPath);
  } catch (e) {
    throw new L5bUnavailableError("Failed to load L5c ONNX session.", e);
  }

  const blob: TokBlob = JSON.parse(readFileSync(tokPath, "utf8"));
  const tok = buildTokenizer(blob);

  return {
    version: contract.version,
    async score(text: string): Promise<number> {
      const { ids, mask } = tok.encode(text, contract.max_len);
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
    },
  };
}
