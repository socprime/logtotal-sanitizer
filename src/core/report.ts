import type { RuleCounts, SanitizeReplacement, SanitizeReport, SanitizeSegment } from '../types';
import { DEFAULT_PREVIEW_BYTES } from './constants';
import { InvalidOptionError } from './errors';
import type { RedactResult } from './redactLine';

export interface ReportCollectorOptions {
  previewBytes?: number;
  replacements?: boolean;
  maxReplacementsPerRule?: number;
}

export interface ReportSnapshotOptions {
  includeReplacements?: boolean;
}

export interface ReportCollector {
  needsSegments(): boolean;
  needsMatches(): boolean;
  record(result: RedactResult): void;
  build(options?: ReportSnapshotOptions): SanitizeReport;
}

export function createReportCollector(options: ReportCollectorOptions = {}): ReportCollector {
  const previewBytes = options.previewBytes ?? DEFAULT_PREVIEW_BYTES;
  const collectReplacements = options.replacements ?? true;
  const maxPerRule = options.maxReplacementsPerRule;
  const limited = maxPerRule !== undefined;

  if (previewBytes < 0) {
    throw new InvalidOptionError('report.previewBytes must not be negative.');
  }

  if (limited && (maxPerRule < 0 || !Number.isInteger(maxPerRule))) {
    throw new InvalidOptionError('report.maxReplacementsPerRule must be a non-negative integer.');
  }

  const counts: Record<string, number> = {};
  const replacements = new Map<string, SanitizeReplacement>();
  const perRuleDistinct = limited ? new Map<string, number>() : null;
  const before: SanitizeSegment[] = [];
  const after: SanitizeSegment[] = [];
  let lineCount = 0;
  let previewBytesUsed = 0;
  let previewClosed = previewBytes === 0;
  let truncated = false;

  function needsSegments(): boolean {
    return !previewClosed;
  }

  function needsMatches(): boolean {
    return collectReplacements;
  }

  function record(result: RedactResult): void {
    lineCount += 1;

    for (const [id, count] of Object.entries(result.counts)) {
      counts[id] = (counts[id] ?? 0) + count;
    }

    if (collectReplacements) {
      for (const match of result.matches) {
        const key = `${match.ruleId}\u0000${match.original}`;
        const existing = replacements.get(key);

        if (existing) {
          existing.count += 1;
          continue;
        }

        if (perRuleDistinct) {
          const n = perRuleDistinct.get(match.ruleId) ?? 0;

          if (n >= maxPerRule!) {
            truncated = true;
            continue;
          }

          perRuleDistinct.set(match.ruleId, n + 1);
        }

        replacements.set(key, {
          ruleId: match.ruleId,
          original: match.original,
          replacement: match.replacement,
          count: 1,
          ...(match.contextBefore !== undefined
            ? { contextBefore: match.contextBefore, contextAfter: match.contextAfter }
            : {}),
        });
      }
    }

    if (previewClosed) {
      return;
    }

    if (result.segments) {
      before.push(...result.segments.before);
      after.push(...result.segments.after);
    }

    previewBytesUsed += result.output.length;

    if (previewBytesUsed >= previewBytes) {
      previewClosed = true;
    }
  }

  function build(snapshot?: ReportSnapshotOptions): SanitizeReport {
    const includeReplacements = snapshot?.includeReplacements ?? true;
    let totalMatches = 0;

    for (const count of Object.values(counts)) {
      totalMatches += count;
    }

    return {
      counts: { ...counts } as RuleCounts,
      totalMatches,
      lineCount,
      replacements: includeReplacements ? [...replacements.values()] : [],
      preview: { before: [...before], after: [...after] },
      ...(truncated && includeReplacements ? { replacementsTruncated: true } : {}),
    };
  }

  return { needsSegments, needsMatches, record, build };
}
