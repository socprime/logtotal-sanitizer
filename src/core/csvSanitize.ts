import { buildColumnPlan, type CsvColumnPlan } from '../csv/columns';
import {
  createCsvRecordSplitter,
  detectDialect,
  parseCsvRecord,
  serializeCsvField,
  serializeCsvRecord,
  stripBom,
  type CsvDialect,
  type CsvField,
} from '../csv/parser';
import type { CsvOptions } from '../types';
import { isAllowed } from './allowlist';
import type { RuleContext } from './compile';
import { buildKeyedReplacement } from './keyedReplacement';
import { looksLikeJson, redactJsonLine } from './redactJsonLine';
import { redactLine, type RedactOptions, type RedactResult } from './redactLine';
import type { ReportCollector } from './report';
import { createValueDictionary, type ValueDictionary } from './valueDictionary';

export interface ResolvedCsvOptions {
  delimiter?: string;
  header?: readonly string[];
  hasHeader: boolean;
}

export function resolveCsvOptions(csv: boolean | CsvOptions): ResolvedCsvOptions {
  const opts = typeof csv === 'object' ? csv : {};
  const hasExplicitHeader = opts.header !== undefined;

  return {
    delimiter: opts.delimiter,
    header: opts.header,
    hasHeader: opts.hasHeader ?? (hasExplicitHeader ? false : true),
  };
}

function emptyRedactResult(output: string): RedactResult {
  return { output, counts: {}, matches: [] };
}

function appendGapSegments(
  result: RedactResult,
  text: string,
  withSegments: boolean,
): RedactResult {
  if (!withSegments || text.length === 0) {
    return result;
  }

  if (!result.segments) {
    result.segments = { before: [], after: [] };
  }

  result.segments.before.push({ text, changed: false });
  result.segments.after.push({ text, changed: false });
  return result;
}

function valueLooksLikeIp(value: string, ctx: RuleContext): boolean {
  const validate = ctx.rulesById.get('ips')?.validate;

  if (validate === undefined) {
    return false;
  }

  if (validate(value)) {
    return true;
  }

  const colon = value.lastIndexOf(':');

  if (colon > 0) {
    const host = value.slice(0, colon);
    const port = value.slice(colon + 1);

    if (/^\d+$/.test(port) && validate(host)) {
      return true;
    }
  }

  return false;
}

function redactOptions(collector: ReportCollector): RedactOptions {
  return {
    withSegments: collector.needsSegments(),
    withMatches: collector.needsMatches(),
  };
}

function cellRedactOptions(collector: ReportCollector): RedactOptions {
  return { withSegments: false, withMatches: collector.needsMatches() };
}

function scanCellValue(
  value: string,
  ctx: RuleContext,
  dictionary: ValueDictionary,
  collector: ReportCollector,
): { value: string; part: RedactResult } {
  if (value === '' || value === '-') {
    return { value, part: emptyRedactResult(value) };
  }

  const options = cellRedactOptions(collector);
  const parsed = ctx.json && looksLikeJson(value) ? redactJsonLine(value, ctx, options) : null;
  const base = parsed ?? redactLine(value, ctx, options);
  const dict = dictionary.apply(base.output, ctx.contextChars, options);

  if (dict.matches.length === 0 && Object.keys(dict.counts).length === 0) {
    return { value: base.output, part: base };
  }

  const counts = { ...base.counts };

  for (const [id, count] of Object.entries(dict.counts)) {
    counts[id] = (counts[id] ?? 0) + count;
  }

  return {
    value: dict.output,
    part: { output: dict.output, counts, matches: [...base.matches, ...dict.matches] },
  };
}

function ruleCellValue(
  field: CsvField,
  plan: CsvColumnPlan,
  ctx: RuleContext,
  dictionary: ValueDictionary,
  collector: ReportCollector,
): { value: string; part: RedactResult } {
  const value = field.value;

  if (value === '' || value === '-') {
    return { value, part: emptyRedactResult(value) };
  }

  const ruleId = plan.ruleId!;
  const options = cellRedactOptions(collector);

  if (ruleId === 'ips') {
    const result = redactLine(value, ctx, options);
    const hadIps = (result.counts.ips ?? 0) > 0;

    if (!hadIps && !valueLooksLikeIp(value, ctx)) {
      return { value, part: emptyRedactResult(value) };
    }

    return { value: result.output, part: result };
  }

  if (isAllowed(ctx.allow, ruleId, value)) {
    return { value, part: emptyRedactResult(value) };
  }

  const replacement = buildKeyedReplacement(ctx, ruleId, value);

  if (replacement === null) {
    return { value, part: emptyRedactResult(value) };
  }

  dictionary.remember(ruleId, value, replacement);

  const part: RedactResult = {
    output: replacement,
    counts: { [ruleId]: 1 },
    matches: options.withMatches
      ? [
          {
            ruleId,
            original: value,
            replacement,
            index: 0,
          },
        ]
      : [],
  };

  return { value: replacement, part };
}

function processAlignedRecord(
  parsed: ReturnType<typeof parseCsvRecord>,
  plan: readonly CsvColumnPlan[],
  dialect: CsvDialect,
  ctx: RuleContext,
  dictionary: ValueDictionary,
  collector: ReportCollector,
): { output: string; result: RedactResult } {
  const options = redactOptions(collector);
  const withSegments = options.withSegments === true;
  let rowResult = emptyRedactResult('');
  const serialized: string[] = [];
  let previous: {
    value: string;
    column: CsvColumnPlan;
    newValue: string;
    part: RedactResult;
  } | null = null;

  for (let index = 0; index < parsed.fields.length; index += 1) {
    const field = parsed.fields[index]!;
    const column = plan[index]!;
    let newValue: string;
    let part: RedactResult;

    if (
      previous !== null &&
      previous.value === field.value &&
      previous.column.action === column.action &&
      previous.column.ruleId === column.ruleId
    ) {
      ({ newValue, part } = previous);
    } else if (column.action === 'rule') {
      ({ value: newValue, part } = ruleCellValue(field, column, ctx, dictionary, collector));
    } else {
      ({ value: newValue, part } = scanCellValue(field.value, ctx, dictionary, collector));
    }

    previous = { value: field.value, column, newValue, part };

    const cellOut = serializeCsvField(field, newValue, dialect);
    serialized.push(cellOut);

    if (withSegments) {
      if (index > 0) {
        rowResult = appendGapSegments(rowResult, dialect.delimiter, true);
      }

      if (!rowResult.segments) {
        rowResult.segments = { before: [], after: [] };
      }

      rowResult.segments.before.push({ text: field.raw, changed: field.value !== newValue });
      rowResult.segments.after.push({ text: cellOut, changed: field.value !== newValue });

      for (const [id, count] of Object.entries(part.counts)) {
        rowResult.counts[id] = (rowResult.counts[id] ?? 0) + count;
      }

      rowResult.matches.push(...part.matches);
    } else {
      for (const [id, count] of Object.entries(part.counts)) {
        rowResult.counts[id] = (rowResult.counts[id] ?? 0) + count;
      }

      rowResult.matches.push(...part.matches);
    }
  }

  const output = serializeCsvRecord(serialized, parsed.terminator, dialect);
  rowResult.output = output;

  if (withSegments && parsed.terminator.length > 0) {
    rowResult = appendGapSegments(rowResult, parsed.terminator, true);
  }

  return { output, result: rowResult };
}

function processMisalignedRecord(
  parsed: ReturnType<typeof parseCsvRecord>,
  dialect: CsvDialect,
  ctx: RuleContext,
  dictionary: ValueDictionary,
  collector: ReportCollector,
): { output: string; result: RedactResult } {
  const options = redactOptions(collector);
  const withSegments = options.withSegments === true;
  let rowResult = emptyRedactResult('');
  const serialized: string[] = [];

  for (let index = 0; index < parsed.fields.length; index += 1) {
    const field = parsed.fields[index]!;
    const { value: newValue, part } = scanCellValue(field.value, ctx, dictionary, collector);
    const cellOut = serializeCsvField(field, newValue, dialect);
    serialized.push(cellOut);

    if (withSegments) {
      if (index > 0) {
        rowResult = appendGapSegments(rowResult, dialect.delimiter, true);
      }

      if (!rowResult.segments) {
        rowResult.segments = { before: [], after: [] };
      }

      rowResult.segments.before.push({ text: field.raw, changed: field.value !== newValue });
      rowResult.segments.after.push({ text: cellOut, changed: field.value !== newValue });
    }

    for (const [id, count] of Object.entries(part.counts)) {
      rowResult.counts[id] = (rowResult.counts[id] ?? 0) + count;
    }

    rowResult.matches.push(...part.matches);
  }

  const output = serializeCsvRecord(serialized, parsed.terminator, dialect);
  rowResult.output = output;

  if (withSegments && parsed.terminator.length > 0) {
    rowResult = appendGapSegments(rowResult, parsed.terminator, true);
  }

  return { output, result: rowResult };
}

export interface CsvProcessor {
  pushBom(bom: string): void;
  ensureDialect(sample: string): void;
  processRecord(raw: string): string;
}

export function createCsvProcessor(
  ctx: RuleContext,
  csvOptions: ResolvedCsvOptions,
  collector: ReportCollector,
): CsvProcessor {
  const dictionary = createValueDictionary();
  let dialect: CsvDialect = { delimiter: csvOptions.delimiter ?? ',', quote: '"' };
  let delimiterFixed = csvOptions.delimiter !== undefined;
  let columnPlan: CsvColumnPlan[] | null = null;
  let headerLength = 0;
  let awaitingHeader = csvOptions.hasHeader && csvOptions.header === undefined;
  let bomPrefix = '';

  if (csvOptions.header !== undefined) {
    columnPlan = buildColumnPlan(ctx, csvOptions.header);
    headerLength = csvOptions.header.length;
    collector.setCsvColumns(columnPlan);
  }

  function ensureDialect(sample: string): void {
    if (delimiterFixed) {
      return;
    }

    dialect = detectDialect(sample);
    delimiterFixed = true;
  }

  function pushBom(bom: string): void {
    if (bom.length > 0 && bomPrefix.length === 0) {
      bomPrefix = bom;
    }
  }

  function processHeaderRecord(raw: string): string {
    const { bom, text } = stripBom(raw);
    pushBom(bom);
    ensureDialect(text);

    const parsed = parseCsvRecord(text, dialect);
    const headers = parsed.fields.map((field) => field.value);
    columnPlan = buildColumnPlan(ctx, headers);
    headerLength = headers.length;
    awaitingHeader = false;
    collector.setCsvColumns(columnPlan);

    if (collector.needsSegments()) {
      collector.record({
        output: raw,
        counts: {},
        matches: [],
        segments: {
          before: [{ text: raw, changed: false }],
          after: [{ text: raw, changed: false }],
        },
      });
    } else {
      collector.record(emptyRedactResult(raw));
    }

    return raw;
  }

  function processRecord(raw: string): string {
    if (awaitingHeader) {
      return processHeaderRecord(raw);
    }

    if (!delimiterFixed) {
      ensureDialect(raw);
    }

    const parsed = parseCsvRecord(raw, dialect);
    const aligned = columnPlan !== null && parsed.fields.length === headerLength;

    if (!aligned) {
      if (columnPlan !== null) {
        collector.noteMisalignedRow();
      }

      const { output, result } = processMisalignedRecord(
        parsed,
        dialect,
        ctx,
        dictionary,
        collector,
      );
      collector.record(result);
      return output;
    }

    const { output, result } = processAlignedRecord(
      parsed,
      columnPlan!,
      dialect,
      ctx,
      dictionary,
      collector,
    );
    collector.record(result);
    return output;
  }

  return { pushBom, ensureDialect, processRecord };
}

export function sanitizeCsvText(
  text: string,
  ctx: RuleContext,
  csvOptions: ResolvedCsvOptions,
  collector: ReportCollector,
): string {
  const { bom, text: body } = stripBom(text);
  const processor = createCsvProcessor(ctx, csvOptions, collector);
  processor.pushBom(bom);
  processor.ensureDialect(body);

  const splitter = createCsvRecordSplitter();
  let output = bom;

  for (const record of splitter.push(body)) {
    output += processor.processRecord(record);
  }

  for (const record of splitter.flush()) {
    output += processor.processRecord(record);
  }

  return output;
}

export function createCsvStreamRunner(
  ctx: RuleContext,
  csvOptions: ResolvedCsvOptions,
  collector: ReportCollector,
): { processor: CsvProcessor; splitter: ReturnType<typeof createCsvRecordSplitter> } {
  return {
    processor: createCsvProcessor(ctx, csvOptions, collector),
    splitter: createCsvRecordSplitter(),
  };
}
