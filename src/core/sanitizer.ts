import { createAlwaysRedactRule } from '../rules/alwaysRedact';
import { builtinRuleIds } from '../rules/registry';
import type {
  RuleInfo,
  Sanitizer,
  SanitizerOptions,
  SanitizeReport,
  SanitizeRule,
  SanitizeStreamOptions,
  SanitizeTextResult,
  TextSink,
  TextSource,
} from '../types';
import { createAllowList } from './allowlist';
import { createRuleContext, type RuleContext } from './compile';
import { InvalidOptionError, SanitizationAbortedError } from './errors';
import { assertKey, generateKey } from './key';
import { createLineSplitter } from './lineSplitter';
import { createPseudonymizer } from './pseudonymize';
import { looksLikeJson, redactJsonLine } from './redactJsonLine';
import { redactLine } from './redactLine';
import { createReportCollector, type ReportCollector } from './report';
import { resolveRules } from './resolveRules';

async function* toAsyncIterable(source: TextSource): AsyncIterable<string> {
  yield* source as AsyncIterable<string>;
}

function processLine(line: string, ctx: RuleContext, collector: ReportCollector): string {
  const options = {
    withSegments: collector.needsSegments(),
    withMatches: collector.needsMatches(),
  };

  const parsed = ctx.json && looksLikeJson(line) ? redactJsonLine(line, ctx, options) : null;
  const result = parsed ?? redactLine(line, ctx, options);

  collector.record(result);
  return result.output;
}

/**
 * Creates a reusable sanitizer.
 *
 * Rules are resolved, validated and compiled once, here — so sanitizing many
 * inputs with one sanitizer is much cheaper than calling the one-shot helpers repeatedly.
 *
 * @throws {UnknownRuleError} When `rules` names a rule that is not built in.
 * @throws {InvalidRuleError} When a custom rule is malformed.
 * @throws {InvalidKeyError} When `key` is malformed, or none could be generated.
 * @throws {InvalidOptionError} When an option value is out of range.
 *
 * @example
 * ```ts
 * const sanitizer = createSanitizer({
 *   rules: ['secrets', 'ips', 'users'],
 *   alwaysRedact: { values: ['acme-internal'] },
 *   neverRedact: { values: ['127.0.0.1'] },
 * });
 *
 * const { output, report } = sanitizer.sanitizeText('login from 10.0.0.7 failed');
 * ```
 */
export function createSanitizer(options: SanitizerOptions = {}): Sanitizer {
  const keyEncoding = options.keyEncoding ?? 'hex';
  const key = options.key ?? generateKey();
  assertKey(key, keyEncoding);

  const contextChars = options.report?.contextChars ?? 0;

  if (contextChars < 0) {
    throw new InvalidOptionError('report.contextChars must not be negative.');
  }

  const selected = resolveWithAlwaysRedact(options);

  const ctx = createRuleContext({
    rules: selected,
    aggressive: options.aggressive ?? false,
    pseudonymize: createPseudonymizer(key, keyEncoding),
    allow: createAllowList(options.neverRedact),
    contextChars,
    json: options.json !== false,
  });

  const collectorOptions = {
    previewBytes: options.report?.previewBytes,
    replacements: options.report?.replacements,
  };

  const rules: readonly RuleInfo[] = selected.map((rule) => ({
    id: rule.id,
    label: rule.label,
    description: rule.description,
    mode: rule.mode,
  }));

  function sanitizeText(text: string): SanitizeTextResult {
    const collector = createReportCollector(collectorOptions);
    const splitter = createLineSplitter(options.lines);
    let output = '';

    for (const line of splitter.push(text)) {
      output += processLine(line, ctx, collector);
    }

    for (const line of splitter.flush()) {
      output += processLine(line, ctx, collector);
    }

    return { output, report: collector.build() };
  }

  async function sanitizeStream(
    source: TextSource,
    sink: TextSink,
    streamOptions: SanitizeStreamOptions = {},
  ): Promise<SanitizeReport> {
    const collector = createReportCollector(collectorOptions);
    const splitter = createLineSplitter(options.lines);
    const { signal, onProgress } = streamOptions;
    let charsRead = 0;

    const writeLine = async (line: string): Promise<void> => {
      if (signal?.aborted === true) {
        throw new SanitizationAbortedError();
      }

      await sink.write(processLine(line, ctx, collector));
    };

    for await (const chunk of toAsyncIterable(source)) {
      charsRead += chunk.length;

      for (const line of splitter.push(chunk)) {
        await writeLine(line);
      }

      onProgress?.({ charsRead, report: collector.build({ includeReplacements: false }) });
    }

    for (const line of splitter.flush()) {
      await writeLine(line);
    }

    await sink.close?.();

    return collector.build();
  }

  return { key, rules, sanitizeText, sanitizeStream };
}

function resolveWithAlwaysRedact(options: SanitizerOptions): SanitizeRule[] {
  const selected = resolveRules(options.rules ?? builtinRuleIds, options.extraRules);
  const alwaysRule = createAlwaysRedactRule(options.alwaysRedact);

  if (!alwaysRule) {
    return selected;
  }

  if (selected.some((rule) => rule.id === alwaysRule.id)) {
    throw new InvalidOptionError(
      `alwaysRedact.ruleId "${alwaysRule.id}" collides with an active rule. Choose an identifier that is not in use.`,
    );
  }

  return [alwaysRule, ...selected];
}

/**
 * Sanitizes a string with a one-off configuration.
 *
 * Convenient for scripts and tests. Each call builds a new sanitizer, so unless `options.key` is
 * supplied the tokens are not comparable between calls. For repeated use, create a sanitizer with
 * {@link createSanitizer} instead.
 */
export function sanitizeText(text: string, options?: SanitizerOptions): SanitizeTextResult {
  return createSanitizer(options).sanitizeText(text);
}

/**
 * Streams text through a one-off sanitizer.
 *
 * See {@link sanitizeText} for the trade-off of creating a sanitizer per call.
 */
export function sanitizeStream(
  source: TextSource,
  sink: TextSink,
  options?: SanitizerOptions & SanitizeStreamOptions,
): Promise<SanitizeReport> {
  const { onProgress, signal, ...sanitizerOptions } = options ?? {};

  return createSanitizer(sanitizerOptions).sanitizeStream(source, sink, { onProgress, signal });
}
