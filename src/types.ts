/**
 * Identifiers of the rules shipped with this package.
 */
export type BuiltinRuleId =
  | 'secrets'
  | 'sessionCookies'
  | 'paymentInfo'
  | 'govIds'
  | 'healthInfo'
  | 'phoneNumbers'
  | 'ips'
  | 'hosts'
  | 'users'
  | 'geoLocation'
  | 'paths';

/**
 * A rule identifier. Built-in identifiers are suggested by editors; any other string is accepted
 * so custom rules can use their own namespace, for example `acme:ticketId`.
 *
 * A rule identifier must be a valid ASCII identifier. Namespacing with `:` is not allowed — use
 * `_` instead.
 */
export type RuleId = BuiltinRuleId | (string & {});

/**
 * How a matched value is replaced.
 *
 * - `pseudo` replaces the value with a token carrying the rule's own prefix, for example
 *   `<IP:4f2a1c9d5b3e7a08>`. The same input always maps to the same token for a given key, so
 *   occurrences stay correlatable across a run and across files sanitized with the same key.
 * - `mask` produces the same stable token but always uses the neutral `R` prefix, so the kind of
 *   secret that was found is not disclosed by the output.
 */
export type RedactionMode = 'pseudo' | 'mask';

/**
 * How a key string is turned into bytes. Keys produced by {@link generateKey} are `hex`;
 * user-supplied passphrases are usually `utf8`.
 */
export type KeyEncoding = 'hex' | 'utf8';

/**
 * A detection rule: a set of patterns plus the policy for replacing what they match.
 *
 * Create rules with {@link defineRule} rather than as plain objects — it validates the shape and
 * fails early with an actionable message.
 */
export interface SanitizeRule {
  /**
   * Unique identifier. Must match `/^[A-Za-z_$][A-Za-z0-9_$]*$/`.
   */
  id: RuleId;
  /** Short human-readable name, suitable for a checkbox label or a report heading. */
  label: string;
  /** One sentence describing what the rule detects. */
  description: string;
  /** Replacement policy for values this rule matches. */
  mode: RedactionMode;
  /**
   * Token prefix used in `pseudo` mode, for example `IP` produces `<IP:…>`. Must match
   * `/^[A-Z][A-Z0-9]*$/`. Ignored in `mask` mode. Defaults to the uppercased identifier.
   */
  token?: string;
  /**
   * Regular expression source fragments, combined into one alternation per rule. Each fragment is
   * compiled with the `u` flag. At most one capturing group is allowed: it marks the value to
   * replace, so a consumed prefix such as `/home/(user)` is kept. Named groups are reserved.
   */
  patterns: string[];
  /**
   * Additional, deliberately broader fragments applied only when `aggressive` is enabled. They
   * belong to the same rule, so counts and tokens still use this rule's identifier.
   */
  aggressivePatterns?: string[];
  /**
   * Final decision for a candidate the patterns matched. Return `false` to leave the value
   * untouched — used to filter out well-known non-sensitive values and to apply checksums such as
   * Luhn or IBAN mod-97. Must be side-effect free and fast: it runs once per candidate match.
   */
  validate?: (match: string) => boolean;
  /**
   * JSON field names whose value is redacted by name alone, regardless of its shape, when the
   * input line is a JSON object. Matching ignores case, hyphens and underscores, so `x-api-key`,
   * `x_api_key` and `xApiKey` are the same key.
   */
  jsonKeys?: string[];
}

/**
 * Public description of a rule taking part in a run, without its patterns.
 */
export interface RuleInfo {
  id: RuleId;
  label: string;
  description: string;
  mode: RedactionMode;
}

/** Match counts per rule identifier. */
export type RuleCounts = Partial<Record<RuleId, number>>;

/**
 * A slice of a before/after preview. `changed` marks the parts a rule replaced.
 */
export interface SanitizeSegment {
  text: string;
  changed: boolean;
}

/**
 * One distinct value that was replaced, with the number of times it occurred.
 */
export interface SanitizeReplacement {
  ruleId: RuleId;
  original: string;
  replacement: string;
  count: number;
  /** Text immediately before the first occurrence. Present only when `report.contextChars > 0`. */
  contextBefore?: string;
  /** Text immediately after the first occurrence. Present only when `report.contextChars > 0`. */
  contextAfter?: string;
}

/**
 * Summary of a sanitization run.
 */
export interface SanitizeReport {
  /** Number of replacements per rule, for the whole input. */
  counts: RuleCounts;
  /** Sum of every entry in {@link SanitizeReport.counts}. */
  totalMatches: number;
  /** Number of lines processed. */
  lineCount: number;
  /**
   * Distinct replaced values for the whole input, deduplicated by rule and original value.
   * Empty when `report.replacements` is disabled.
   *
   * These entries contain the original, unredacted values. Treat the report as sensitive: it is
   * meant for local review, not for shipping alongside the sanitized output.
   */
  replacements: SanitizeReplacement[];
  /**
   * Before/after segments for the first `report.previewBytes` of output, so a UI can render a
   * diff without holding the whole input in memory. Empty when `report.previewBytes` is `0`.
   */
  preview: {
    before: SanitizeSegment[];
    after: SanitizeSegment[];
  };
}

/**
 * Values and patterns that must be redacted regardless of which rules are active.
 *
 * Entries here take priority over every rule, so a value that would otherwise be missed is still
 * replaced. Values allowlisted through {@link NeverRedactOptions} still win.
 */
export interface AlwaysRedactOptions {
  /** Exact substrings to redact. Matched literally; longer values win on overlap. */
  values?: readonly string[];
  /**
   * Patterns to redact. A string is treated as a regular expression source, not as a literal.
   * Flags on a `RegExp` are ignored; the combined pattern is always compiled with `gu`.
   */
  patterns?: readonly (string | RegExp)[];
  /**
   * Rule identifier reported for these matches.
   * @default 'custom'
   */
  ruleId?: RuleId;
  /**
   * Replacement policy for these matches.
   * @default 'pseudo'
   */
  mode?: RedactionMode;
  /**
   * Token prefix for these matches in `pseudo` mode.
   * @default 'CUSTOM'
   */
  token?: string;
}

/** A per-rule allowlist entry. */
export interface NeverRedactRuleEntry {
  ruleId: RuleId;
  values: readonly string[];
}

/**
 * Values that must never be redacted, even when a rule matches them.
 *
 * Checked against the matched value itself, not the surrounding line, and applied before any
 * replacement is built.
 */
export interface NeverRedactOptions {
  /** Exact values to keep, whichever rule matched them. */
  values?: readonly string[];
  /**
   * Patterns that keep a matched value when they match it in full. A string is treated as a
   * regular expression source. Flags are ignored; matching is always anchored and Unicode-aware.
   */
  patterns?: readonly (string | RegExp)[];
  /** Exact values to keep only for a specific rule. */
  byRule?: readonly NeverRedactRuleEntry[];
}

/**
 * Report detail level. Tightening these bounds lowers memory use on large inputs.
 */
export interface ReportOptions {
  /**
   * Size of the before/after preview window, in output characters. `0` disables the preview.
   * @default 262144
   */
  previewBytes?: number;
  /**
   * Whether to collect the list of distinct replaced values. Disable it when the report is only
   * used for counts — the list grows with the number of distinct sensitive values in the input.
   * @default true
   */
  replacements?: boolean;
  /**
   * How many characters of surrounding text to record next to each distinct replacement, to help
   * a reviewer judge a match. `0` omits {@link SanitizeReplacement.contextBefore} and
   * {@link SanitizeReplacement.contextAfter} entirely.
   * @default 0
   */
  contextChars?: number;
}

/**
 * Line splitting bounds, relevant for inputs that contain very long lines.
 */
export interface LineOptions {
  /**
   * A run of characters longer than this without a line terminator is processed in bounded
   * segments instead of being buffered whole.
   * @default 1048576
   */
  maxLineChars?: number;
  /**
   * Characters carried from one bounded segment into the next, so a value straddling the cut is
   * still matched. Must be smaller than `maxLineChars`.
   * @default 1024
   */
  overlapChars?: number;
}

/** A rule to run: either a built-in identifier or a rule object. */
export type RuleSelector = RuleId | SanitizeRule;

/**
 * Configuration for {@link createSanitizer}.
 */
export interface SanitizerOptions {
  /**
   * Rules to run, in priority order: when two rules can match at the same position, the one
   * listed first wins. Identifiers are resolved against the built-in rules. Passing a rule object
   * whose identifier is already present replaces that rule while keeping its position.
   * @default every built-in rule, in the order documented in the README
   */
  rules?: readonly RuleSelector[];
  /** Rules appended after {@link SanitizerOptions.rules}, so they run at the lowest priority. */
  extraRules?: readonly SanitizeRule[];
  /**
   * Whether to also apply each rule's broader `aggressivePatterns`. Catches more, at the cost of
   * more false positives.
   * @default false
   */
  aggressive?: boolean;
  /**
   * Key used to derive replacement tokens. Reuse it to keep tokens comparable across files or
   * runs; change it to make them uncorrelatable.
   * @default a fresh random 32-byte key from {@link generateKey}
   */
  key?: string;
  /**
   * How {@link SanitizerOptions.key} is decoded.
   * @default 'hex'
   */
  keyEncoding?: KeyEncoding;
  /** Values and patterns to redact regardless of the active rules. */
  alwaysRedact?: AlwaysRedactOptions;
  /** Values and patterns to keep even when a rule matches them. */
  neverRedact?: NeverRedactOptions;
  /**
   * How to treat lines that parse as a JSON object or array.
   *
   * - `'auto'` redacts values of fields named in a rule's `jsonKeys` and re-serializes the
   *   record, falling back to plain-text scanning when the line is not valid JSON.
   * - `false` always scans as plain text.
   * @default 'auto'
   */
  json?: 'auto' | false;
  /** Report detail level. */
  report?: ReportOptions;
  /** Line splitting bounds. */
  lines?: LineOptions;
}

/** Result of sanitizing an in-memory string. */
export interface SanitizeTextResult {
  /** The sanitized text. */
  output: string;
  /** Summary of what was replaced. */
  report: SanitizeReport;
}

/** Progress of a streaming run. */
export interface SanitizeProgress {
  /** Characters consumed from the source so far. */
  charsRead: number;
  /**
   * Snapshot of the report so far. Counts grow throughout the run; the distinct-replacement list
   * is omitted from snapshots and only present in the final report.
   */
  report: SanitizeReport;
}

/**
 * The subset of `AbortSignal` this package relies on, so passing a signal does not require DOM or
 * Node type definitions to be in scope.
 */
export interface AbortSignalLike {
  readonly aborted: boolean;
}

/** Per-run options for {@link Sanitizer.sanitizeStream}. */
export interface SanitizeStreamOptions {
  /** Called after each source chunk with a live snapshot of progress. */
  onProgress?: (progress: SanitizeProgress) => void;
  /**
   * Aborts the run between lines. The sink is not closed and a
   * {@link SanitizationAbortedError} is thrown.
   */
  signal?: AbortSignalLike;
}

/** A source of text chunks. Chunk boundaries do not need to align with line boundaries. */
export type TextSource = AsyncIterable<string> | Iterable<string>;

/** A destination for sanitized text. */
export interface TextSink {
  write(chunk: string): void | Promise<void>;
  /** Called once after the last chunk of a successful run. */
  close?(): void | Promise<void>;
}

/**
 * The minimal shape of a `Blob` or `File` this package reads, so browser and Node values are both
 * accepted without depending on DOM type definitions.
 */
export interface BlobLike {
  readonly size: number;
  slice(start?: number, end?: number): BlobLike;
  arrayBuffer(): Promise<ArrayBuffer>;
}

/**
 * The minimal shape of a `ReadableStream` this package reads.
 */
export interface ReadableStreamLike<T> {
  getReader(): {
    read(): Promise<{ done: boolean; value?: T }>;
    releaseLock(): void;
  };
}

/**
 * A configured, reusable sanitizer. Rules are compiled once when it is created, so sanitizing many
 * inputs with the same configuration does not recompile patterns.
 */
export interface Sanitizer {
  /**
   * The key in use, hex-encoded when it was generated. Persist it to keep tokens comparable in a
   * later run; treat it as a secret, since it is what makes the tokens unguessable.
   */
  readonly key: string;
  /** The rules taking part in a run, in priority order. */
  readonly rules: readonly RuleInfo[];
  /**
   * Sanitizes an in-memory string.
   *
   * Holds both the input and the output in memory. For anything large, prefer
   * {@link Sanitizer.sanitizeStream}.
   */
  sanitizeText(text: string): SanitizeTextResult;
  /**
   * Streams text from `source` through the rules and writes the result to `sink`, holding no more
   * than one chunk plus one line in memory.
   *
   * @returns The report for the whole run.
   * @throws {SanitizationAbortedError} When `options.signal` is aborted.
   */
  sanitizeStream(
    source: TextSource,
    sink: TextSink,
    options?: SanitizeStreamOptions,
  ): Promise<SanitizeReport>;
}
