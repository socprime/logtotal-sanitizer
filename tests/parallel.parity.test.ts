import { describe, expect, it } from 'vitest';

import { DEFAULT_PREVIEW_BYTES } from '../src/core/constants.js';
import {
  createSanitizer,
  fromBlob,
  mergeReports,
  planLineAlignedRanges,
  sanitizeText,
  toStringSink,
} from '../src/index.js';
import type { SanitizeReport, SanitizerOptions } from '../src/types.js';

const KEY = '0123456789abcdef'.repeat(4);

const OPTIONS: SanitizerOptions = {
  key: KEY,
  keyEncoding: 'hex',
  report: { contextChars: 10, previewBytes: DEFAULT_PREVIEW_BYTES },
};

function replacementKey(row: { ruleId: string; original: string }): string {
  return `${row.ruleId}\u0000${row.original}`;
}

function sortReplacements(report: SanitizeReport): SanitizeReport {
  return {
    ...report,
    replacements: [...report.replacements].sort((a, b) =>
      replacementKey(a).localeCompare(replacementKey(b)),
    ),
  };
}

async function sanitizeShards(
  blob: Blob,
  partCount: number,
): Promise<{ output: string; report: SanitizeReport; ranges: Awaited<ReturnType<typeof planLineAlignedRanges>> }> {
  const ranges = await planLineAlignedRanges(blob, partCount);
  const sanitizer = createSanitizer(OPTIONS);
  const outputs: string[] = [];
  const reports: SanitizeReport[] = [];

  for (let i = 0; i < ranges.length; i += 1) {
    const range = ranges[i]!;
    const sink = toStringSink();
    const report = await sanitizer.sanitizeStream(fromBlob(blob.slice(range.start, range.end)), sink, {
      previewBytes: i === 0 ? DEFAULT_PREVIEW_BYTES : 0,
    });
    outputs.push(sink.text);
    reports.push(report);
  }

  return {
    output: outputs.join(''),
    report: mergeReports(reports, { previewBytes: DEFAULT_PREVIEW_BYTES }),
    ranges,
  };
}

function buildFixture(): string {
  const jsonLines = [
    JSON.stringify({ message: 'login from 10.0.0.1', user: 'alice@example.test' }),
    JSON.stringify({ password: 'correct-horse', host: 'app.internal.example' }),
  ];
  const crlf = 'windows path C:\\Users\\bob\\app.log\r\n';
  const longLine = `${'n'.repeat(2000)} 10.0.0.9 ${'m'.repeat(2000)}\n`;
  const tail = 'unterminated 10.0.0.7 trailing';
  const body = [
    'plain 10.0.0.2 ok',
    'user=jdoe path=/home/alice/app.log',
    'Authorization: Bearer abcdefghijklmnop',
    crlf.trimEnd(),
    ...jsonLines,
    longLine.trimEnd(),
    'Nov 15 09:19:41 srv-app-07 sshd: ok',
  ];

  return `${body.join('\n')}\n${tail}`;
}

describe('parallel shard parity', () => {
  it.each([1, 2, 3, 7, 64])('matches sequential output and report for K=%s', async (partCount) => {
    const text = `${buildFixture()}\n${Array.from({ length: 80 }, (_, i) => `row ${i} from 10.0.${i % 8}.${i % 250}`).join('\n')}\n`;
    const blob = new Blob([text]);
    const sequential = sanitizeText(text, OPTIONS);
    const parallel = await sanitizeShards(blob, partCount);

    expect(parallel.output).toBe(sequential.output);
    expect(parallel.report.counts).toEqual(sequential.report.counts);
    expect(parallel.report.totalMatches).toBe(sequential.report.totalMatches);
    expect(parallel.report.lineCount).toBe(sequential.report.lineCount);
    expect(sortReplacements(parallel.report).replacements).toEqual(
      sortReplacements(sequential.report).replacements,
    );

    const firstShard = parallel.ranges[0];
    if (firstShard && firstShard.end - firstShard.start >= DEFAULT_PREVIEW_BYTES) {
      expect(parallel.report.preview.after.map((s) => s.text).join('')).toBe(
        sequential.report.preview.after.map((s) => s.text).join(''),
      );
    }
  });

  it('redacts a consumed-prefix path and a lookbehind secret as the first lines of a later shard', async () => {
    const left = `${Array.from({ length: 20 }, (_, i) => `pad ${i} 10.0.0.${i}`).join('\n')}\n`;
    const consumed = 'path=/home/alice/app.log';
    // Built at runtime so GitHub secret scanning does not treat a fixture SID as a real secret.
    const sid = `AC${'0123456789abcdef'.repeat(2)}`;
    const lookbehind = `Twilio SID ${sid} auth=ok`;
    const text = `${left}${consumed}\n${lookbehind}\n`;
    const blob = new Blob([text]);
    const cut = new TextEncoder().encode(left).byteLength;
    const sanitizer = createSanitizer(OPTIONS);
    const sink0 = toStringSink();
    const sink1 = toStringSink();
    const report0 = await sanitizer.sanitizeStream(fromBlob(blob.slice(0, cut)), sink0);
    const report1 = await sanitizer.sanitizeStream(fromBlob(blob.slice(cut)), sink1, {
      previewBytes: 0,
    });
    const sequential = sanitizeText(text, OPTIONS);
    const output = `${sink0.text}${sink1.text}`;
    const merged = mergeReports([report0, report1], { previewBytes: DEFAULT_PREVIEW_BYTES });

    expect(new TextDecoder().decode(await blob.slice(cut, cut + consumed.length).arrayBuffer())).toBe(
      consumed,
    );
    expect(output).toBe(sequential.output);
    expect(output).toMatch(/\/home\/<R:[0-9a-f]{16}>\/app\.log/);
    expect(output).not.toContain('alice');
    expect(output).not.toContain(sid);
    expect(merged.totalMatches).toBe(sequential.report.totalMatches);
  });

  it('matches sequential output when a line longer than maxLineChars sits inside one shard', async () => {
    const options: SanitizerOptions = {
      ...OPTIONS,
      lines: { maxLineChars: 64, overlapChars: 16 },
    };
    const long = `${'n'.repeat(200)}10.0.0.9${'m'.repeat(200)}`;
    const text = `start 10.0.0.1\n${long}\nend 10.0.0.2\n`;
    const sequential = sanitizeText(text, options);
    const blob = new Blob([text]);
    const sanitizer = createSanitizer(options);
    const ranges = await planLineAlignedRanges(blob, 3);
    const outputs: string[] = [];

    for (const range of ranges) {
      const sink = toStringSink();
      await sanitizer.sanitizeStream(fromBlob(blob.slice(range.start, range.end)), sink);
      outputs.push(sink.text);
    }

    expect(outputs.join('')).toBe(sequential.output);
  });

  it('keeps CRLF with the preceding line when a cut lands on LF', async () => {
    const text = 'alpha 10.0.0.1\r\nbeta 10.0.0.2\r\ngamma 10.0.0.3\r\n';
    const blob = new Blob([text]);
    const sequential = sanitizeText(text, OPTIONS);
    const parallel = await sanitizeShards(blob, 3);
    expect(parallel.output).toBe(sequential.output);
    expect(parallel.output).toContain('\r\n');
  });
});
