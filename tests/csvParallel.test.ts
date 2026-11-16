import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  createCsvRecordSplitter,
  parseCsvRecord,
  stripBom,
  type CsvDialect,
} from '../src/csv/parser.js';
import { mergeReports, planLineAlignedRanges, sanitizeText } from '../src/index.js';
import type { SanitizeReport, SanitizerOptions } from '../src/types.js';

const KEY = '0123456789abcdef'.repeat(4);
const DIALECT: CsvDialect = { delimiter: ',', quote: '"' };

/**
 * Multi-line quoted cells sit in the first data records only. `planLineAlignedRanges`
 * snaps to the next LF, which can fall inside a quoted cell, so later cuts must start
 * after those records.
 *
 * The value dictionary is forward-only and private to each run. Free-text cells and
 * misaligned rows can disagree with a single pass when a users/hosts value was learned
 * in an earlier shard. Typed columns and the header do not consult it.
 */
const FIXTURE_URL = new URL('./fixtures/ecs-export.csv', import.meta.url);

const ABSENT_WHEN_REDACTED = [
  'EXAMPLE.LAB',
  'example.lab',
  'WKS-01$',
  'wks-01',
  'dc-02',
  'alice',
  'bob',
  '10.1.2.',
  '192.168.5.',
  '203.0.113.',
] as const;

function loadFixture(): string {
  return readFileSync(FIXTURE_URL, 'utf8');
}

function splitRecords(text: string): string[] {
  const splitter = createCsvRecordSplitter();
  return [...splitter.push(text), ...splitter.flush()];
}

function fieldValues(record: string): string[] {
  const { text } = stripBom(record);
  return parseCsvRecord(text, DIALECT).fields.map((field) => field.value);
}

function baseOptions(csv: SanitizerOptions['csv']): SanitizerOptions {
  return { key: KEY, keyEncoding: 'hex', csv };
}

describe('ECS CSV fixture', () => {
  const input = loadFixture();
  const inputRecords = splitRecords(input);
  const headerNames = fieldValues(inputRecords[0]!);
  const width = headerNames.length;

  it('keeps the header, redacts identifiers, and counts three misaligned rows', () => {
    expect(inputRecords).toHaveLength(40);
    expect(inputRecords.join('')).toBe(input);
    expect(headerNames).toContain('host.name.keyword');
    expect(headerNames).toContain('user.effective.domain.keyword');
    expect(headerNames).toContain('source.ip.keyword');

    for (const record of inputRecords.slice(1, 4)) {
      expect(fieldValues(record).some((value) => value.includes('\n'))).toBe(true);
    }

    for (const record of inputRecords.slice(4)) {
      expect(fieldValues(record).some((value) => value.includes('\n'))).toBe(false);
    }

    expect(inputRecords.filter((record) => fieldValues(record).length !== width)).toHaveLength(3);

    const { output, report } = sanitizeText(input, baseOptions(true));
    const outputRecords = splitRecords(output);

    expect(outputRecords[0]).toBe(inputRecords[0]);
    expect(report.csv?.misalignedRows).toBe(3);
    expect(report.csv?.columns).toHaveLength(width);
    expect(report.csv?.columns.find((column) => column.name === 'host.name')).toEqual({
      name: 'host.name',
      action: 'rule',
      ruleId: 'hosts',
    });
    expect(report.csv?.columns.find((column) => column.name === 'message')).toEqual({
      name: 'message',
      action: 'scan',
      ruleId: null,
    });

    for (const needle of ABSENT_WHEN_REDACTED) {
      expect(output).not.toContain(needle);
    }

    const systemRow = outputRecords.find((record) => fieldValues(record)[4] === 'SYSTEM');
    expect(systemRow).toBeDefined();
    expect(output).toContain('SYSTEM');

    const kept = sanitizeText(input, { ...baseOptions(true), keepPrivateIps: true });

    expect(kept.output).toMatch(/10\.1\.2\.\d+/);
    expect(kept.output).toMatch(/192\.168\.5\.\d+/);
    expect(kept.output).not.toContain('203.0.113.');
    expect(kept.report.csv?.misalignedRows).toBe(3);
  });

  it('matches typed columns across LF-aligned shards and sums misaligned rows', async () => {
    const single = sanitizeText(input, baseOptions(true));
    const blob = new Blob([input]);
    const ranges = await planLineAlignedRanges(blob, 3);

    expect(ranges.length).toBe(3);
    expect(ranges[0]?.start).toBe(0);

    let protectedChars = 0;

    for (const record of inputRecords.slice(0, 4)) {
      protectedChars += record.length;
    }

    const protectedBytes = new TextEncoder().encode(input.slice(0, protectedChars)).byteLength;

    for (const range of ranges) {
      if (range.start > 0) {
        expect(range.start).toBeGreaterThanOrEqual(protectedBytes);
      }
    }

    const outputs: string[] = [];
    const reports: SanitizeReport[] = [];

    for (let index = 0; index < ranges.length; index += 1) {
      const range = ranges[index]!;
      const part = new TextDecoder().decode(await blob.slice(range.start, range.end).arrayBuffer());
      const result = sanitizeText(part, baseOptions(index === 0 ? true : { header: headerNames }));
      outputs.push(result.output);
      reports.push(result.report);
    }

    const merged = mergeReports(reports);
    const parallelRecords = splitRecords(outputs.join(''));
    const singleRecords = splitRecords(single.output);
    const typedIndexes = (single.report.csv?.columns ?? []).flatMap((column, index) =>
      column.action === 'rule' ? [index] : [],
    );

    expect(merged.csv?.misalignedRows).toBe(3);
    expect(merged.csv?.columns).toEqual(single.report.csv?.columns);
    expect(parallelRecords[0]).toBe(singleRecords[0]);
    expect(parallelRecords).toHaveLength(singleRecords.length);

    for (let index = 1; index < singleRecords.length; index += 1) {
      const singleFields = fieldValues(singleRecords[index]!);

      if (singleFields.length !== width) {
        continue;
      }

      const parallelFields = fieldValues(parallelRecords[index]!);
      expect(parallelFields).toHaveLength(width);

      for (const column of typedIndexes) {
        expect(parallelFields[column]).toBe(singleFields[column]);
      }
    }
  });
});
