/**
 * promptpurify — type surface.
 *
 * Design honesty: deterministic code cannot decide whether a sentence is a
 * jailbreak. It CAN neutralize the mechanical attack surface (encoding, hidden
 * chars, template-token forgery) and structurally deny untrusted text any
 * instruction authority. Everything semantic is *flagged*, never *cleared*.
 */

/**
 * Where the text is going. Determines how aggressively it is treated and
 * whether it is even allowed to carry instructions. The single most important
 * defense lever (the DOMPurify "context" analog: HTML body vs attr vs URL).
 */
export type Sink =
  /** Author-controlled. Allowed to instruct the model. Lightly normalized. */
  | "trusted_instruction"
  /** End-user free text. Never granted instruction authority. */
  | "untrusted_data"
  /** Output of a tool/function call fed back to the model. */
  | "tool_output"
  /** Retrieved document / web / DB chunk (indirect-injection vector). */
  | "rag_chunk";

/** Built-in strictness profiles. */
export type Profile = "strict" | "balanced" | "off";

export interface PurifyConfig {
  profile?: Profile;
  /** Override per call. */
  sink?: Sink;
  /**
   * Strip (true) vs escape (false) known chat-template tokens such as
   * ChatML / Llama `[INST]` / special role markers. Default: strip.
   */
  stripTemplateTokens?: boolean;
  /** Max input length before truncation (context-flood mitigation). 0 = off. */
  maxLength?: number;
  /** Extra tripwire patterns merged with built-ins. */
  extraRules?: TripwireRule[];
  /**
   * L5 — optional probabilistic classifier for the semantic gap (persona /
   * fiction / paraphrase jailbreaks deterministic code cannot catch).
   * Advisory only: it ADDS a risk, it never produces a `.safe` verdict.
   * Used by `inspectAsync()`. Plug Transformers.js, an API, or a stub.
   */
  classifier?: Classifier;
  /** Score >= this adds a "high" semantic risk. Default 0.8. */
  classifierThreshold?: number;
}

export interface ClassifierResult {
  /** Injection/jailbreak likelihood, 0..1. */
  score: number;
  /** Optional model label, e.g. "INJECTION" | "SAFE". */
  label?: string;
}

export type Classifier = (
  text: string,
  ctx: { sink: Sink },
) => Promise<ClassifierResult> | ClassifierResult;

/** A flagged span — annotation only. Presence != block; absence != safe. */
export interface Risk {
  /** Rule id, e.g. "instruction-override", "role-spoof", "encoded-payload". */
  rule: string;
  /** Human-readable why. */
  message: string;
  /** Coarse severity. */
  severity: "info" | "warn" | "high";
  /** [start, end) char offsets into the *sanitized* text, when locatable. */
  span?: [number, number];
}

export interface TripwireRule {
  id: string;
  severity: Risk["severity"];
  pattern: RegExp;
  message: string;
}

/** What `normalize()` changed — for audit / idempotence tests. */
export interface NormalizationReport {
  unicodeNormalized: boolean;
  zeroWidthStripped: number;
  bidiStripped: number;
  tagCharsStripped: number;
  homoglyphsFolded: number;
  /** Zalgo / stacked combining marks removed. */
  combiningStripped: number;
  /** Emoji-stego variation selectors removed. */
  variationSelectorsStripped: number;
  /** Small-caps / regional-indicator / upside-down chars folded to ASCII. */
  stylesFolded: number;
  whitespaceCollapsed: boolean;
  truncated: boolean;
}

export interface InspectReport {
  /** Sanitized text (L1 applied; L2/L3 per sink). */
  text: string;
  /** Risks found. NEVER interpret empty as "safe". */
  risks: Risk[];
  /** True if normalization or structural transforms altered the input. */
  modified: boolean;
  /** What L1 did. */
  normalization: NormalizationReport;
  /**
   * Honest verdict. "blocked" only for hard structural violations
   * (untrusted text trying to occupy an instruction channel). Semantic
   * jailbreaks surface as high-severity risks, NOT as blocked.
   */
  verdict: "clean-structural" | "flagged" | "blocked";
  /** The sink this was processed for. */
  sink: Sink;
}

export type ChatRole = "system" | "user" | "tool";

export interface ChatMessage {
  role: ChatRole;
  content: string;
}

export interface MessageParts {
  /** Trusted system instructions (author-controlled). */
  system: string;
  /** Untrusted end-user text. */
  user?: string;
  /** Untrusted retrieved/tool data, each wrapped in its own nonce fence. */
  data?: { label: string; content: string; sink?: Sink }[];
}
