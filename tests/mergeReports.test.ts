import { describe, expect, it } from 'vitest';

import { DEFAULT_PREVIEW_BYTES } from '../src/core/constants.js';
import { mergeReports } from '../src/index.js';
import type { SanitizeReport, SanitizeReplacement } from '../src/types.js';

function replacement(
  original: string,
  count: number,
  extras: Partial<SanitizeReplacement> = {},
): SanitizeReplacement {
  return {
    ruleId: 'ips',
    original,
    replacement: `<IP:${original}>`,
    count,
    ...extras,
  };
}

function report(partial: Partial<SanitizeReport>): SanitizeReport {
  return {
    counts: {},
    totalMatches: 0,
    lineCount: 0,
    replacements: [],
    preview: { before: [], after: [] },
    ...partial,
  };
}

describe('mergeReports', () => {
  it('sums counts, totals and lineCount', () => {
    const merged = mergeReports([
      report({ counts: { ips: 2, users: 1 }, totalMatches: 3, lineCount: 4 }),
      report({ counts: { ips: 5 }, totalMatches: 5, lineCount: 6 }),
    ]);

    expect(merged.counts).toEqual({ ips: 7, users: 1 });
    expect(merged.totalMatches).toBe(8);
    expect(merged.lineCount).toBe(10);
  });

  it('merges replacements by ruleId and original, keeping context from the earlier report', () => {
    const merged = mergeReports([
      report({
        replacements: [
          replacement('10.0.0.1', 2, { contextBefore: 'from ', contextAfter: ' ok' }),
        ],
      }),
      report({
        replacements: [
          replacement('10.0.0.1', 3, { contextBefore: 'later ', contextAfter: ' no' }),
          replacement('10.0.0.2', 1, { contextBefore: 'and ', contextAfter: '' }),
        ],
      }),
    ]);

    expect(merged.replacements).toEqual([
      replacement('10.0.0.1', 5, { contextBefore: 'from ', contextAfter: ' ok' }),
      replacement('10.0.0.2', 1, { contextBefore: 'and ', contextAfter: '' }),
    ]);
  });

  it('is associative for counts and replacement context', () => {
    const a = report({
      counts: { ips: 1 },
      totalMatches: 1,
      lineCount: 1,
      replacements: [replacement('10.0.0.1', 1, { contextBefore: 'a' })],
    });
    const b = report({
      counts: { ips: 1 },
      totalMatches: 1,
      lineCount: 1,
      replacements: [replacement('10.0.0.1', 1, { contextBefore: 'b' })],
    });
    const c = report({
      counts: { ips: 2 },
      totalMatches: 2,
      lineCount: 2,
      replacements: [replacement('10.0.0.2', 2, { contextBefore: 'c' })],
    });

    const left = mergeReports([mergeReports([a, b]), c]);
    const right = mergeReports([a, mergeReports([b, c])]);
    const flat = mergeReports([a, b, c]);

    expect(left).toEqual(flat);
    expect(right).toEqual(flat);
    expect(flat.replacements[0]?.contextBefore).toBe('a');
  });

  it('concatenates preview segments in report order until previewBytes', () => {
    const a = report({
      preview: {
        before: [{ text: 'AAAA', changed: false }],
        after: [{ text: 'aaaa', changed: false }],
      },
    });
    const b = report({
      preview: {
        before: [{ text: 'BBBB', changed: false }],
        after: [{ text: 'bbbb', changed: false }],
      },
    });

    const merged = mergeReports([a, b], { previewBytes: 4 });
    expect(merged.preview.after.map((s) => s.text).join('')).toBe('aaaa');
    expect(merged.preview.before.map((s) => s.text).join('')).toBe('AAAA');

    const uncapped = mergeReports([a, b], { previewBytes: DEFAULT_PREVIEW_BYTES });
    expect(uncapped.preview.after.map((s) => s.text).join('')).toBe('aaaabbbb');
  });

  it('reapplies maxReplacementsPerRule after the merge', () => {
    const a = report({
      replacements: [replacement('10.0.0.1', 1), replacement('10.0.0.2', 1)],
    });
    const b = report({
      replacements: [replacement('10.0.0.3', 4)],
    });

    const merged = mergeReports([a, b], { maxReplacementsPerRule: 2 });
    expect(merged.replacements.map((row) => row.original)).toEqual(['10.0.0.1', '10.0.0.2']);
    expect(merged.replacementsTruncated).toBe(true);
  });

  it('propagates replacementsTruncated from an input even when the merge itself does not cap', () => {
    const merged = mergeReports([
      report({ replacementsTruncated: true, replacements: [replacement('10.0.0.1', 1)] }),
      report({ replacements: [replacement('10.0.0.2', 1)] }),
    ]);

    expect(merged.replacements).toHaveLength(2);
    expect(merged.replacementsTruncated).toBe(true);
  });

  it('returns an empty report for no inputs', () => {
    expect(mergeReports([])).toEqual({
      counts: {},
      totalMatches: 0,
      lineCount: 0,
      replacements: [],
      preview: { before: [], after: [] },
    });
  });
});
