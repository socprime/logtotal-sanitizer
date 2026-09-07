import type { RuleCounts, SanitizeReplacement, SanitizeReport, SanitizeSegment } from '../types';
import { DEFAULT_PREVIEW_BYTES } from './constants';

export interface MergeReportsOptions {
  previewBytes?: number;
  maxReplacementsPerRule?: number;
}

function emptyReport(): SanitizeReport {
  return {
    counts: {},
    totalMatches: 0,
    lineCount: 0,
    replacements: [],
    preview: { before: [], after: [] },
  };
}

function cloneReplacement(row: SanitizeReplacement): SanitizeReplacement {
  return {
    ruleId: row.ruleId,
    original: row.original,
    replacement: row.replacement,
    count: row.count,
    ...(row.contextBefore !== undefined
      ? { contextBefore: row.contextBefore, contextAfter: row.contextAfter }
      : {}),
  };
}

function mergePreview(
  reports: readonly SanitizeReport[],
  previewBytes: number,
): { before: SanitizeSegment[]; after: SanitizeSegment[] } {
  if (previewBytes === 0) {
    return { before: [], after: [] };
  }

  const before: SanitizeSegment[] = [];
  const after: SanitizeSegment[] = [];
  let used = 0;

  for (const report of reports) {
    const afterSegs = report.preview.after;
    const beforeSegs = report.preview.before;

    for (let i = 0; i < afterSegs.length; i += 1) {
      if (used >= previewBytes) {
        return { before, after };
      }

      after.push(afterSegs[i]!);
      before.push(beforeSegs[i] ?? { text: '', changed: false });
      used += afterSegs[i]!.text.length;
    }
  }

  return { before, after };
}

export function mergeReports(
  reports: readonly SanitizeReport[],
  options: MergeReportsOptions = {},
): SanitizeReport {
  if (reports.length === 0) {
    return emptyReport();
  }

  const previewBytes = options.previewBytes ?? DEFAULT_PREVIEW_BYTES;
  const maxPerRule = options.maxReplacementsPerRule;
  const limited = maxPerRule !== undefined;
  const counts: Record<string, number> = {};
  const replacements = new Map<string, SanitizeReplacement>();
  const perRuleDistinct = limited ? new Map<string, number>() : null;
  let lineCount = 0;
  let truncated = false;

  for (const report of reports) {
    lineCount += report.lineCount;

    if (report.replacementsTruncated === true) {
      truncated = true;
    }

    for (const [id, count] of Object.entries(report.counts)) {
      counts[id] = (counts[id] ?? 0) + (count ?? 0);
    }

    for (const row of report.replacements) {
      const key = `${row.ruleId}\u0000${row.original}`;
      const existing = replacements.get(key);

      if (existing) {
        existing.count += row.count;
        continue;
      }

      if (maxPerRule !== undefined && perRuleDistinct) {
        const n = perRuleDistinct.get(row.ruleId) ?? 0;

        if (n >= maxPerRule) {
          truncated = true;
          continue;
        }

        perRuleDistinct.set(row.ruleId, n + 1);
      }

      replacements.set(key, cloneReplacement(row));
    }
  }

  let totalMatches = 0;

  for (const count of Object.values(counts)) {
    totalMatches += count;
  }

  return {
    counts: counts as RuleCounts,
    totalMatches,
    lineCount,
    replacements: [...replacements.values()],
    preview: mergePreview(reports, previewBytes),
    ...(truncated ? { replacementsTruncated: true } : {}),
  };
}
