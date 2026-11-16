import { describe, expect, it } from 'vitest';

import { createCsvRecordSplitter, parseCsvRecord } from '../src/csv/parser.js';
import {
  createSanitizer,
  fromString,
  sanitizeStream,
  sanitizeText,
  toStringSink,
} from '../src/index.js';

const KEY = '0123456789abcdef'.repeat(4);

const HEADER =
  '"@timestamp","host.name","host.name.keyword","user.name","user.effective.name","user.effective.domain","user.effective.domain.keyword","user.effective.id","source.ip","dns.question.name","event.code","host.os.name","message"';

const HEADER_NAMES = [
  '@timestamp',
  'host.name',
  'host.name.keyword',
  'user.name',
  'user.effective.name',
  'user.effective.domain',
  'user.effective.domain.keyword',
  'user.effective.id',
  'source.ip',
  'dns.question.name',
  'event.code',
  'host.os.name',
  'message',
] as const;

function dataRow(overrides: Partial<Record<(typeof HEADER_NAMES)[number], string>> = {}): string {
  const values: Record<string, string> = {
    '@timestamp': '2025-01-01T00:00:00.000Z',
    'host.name': 'wkstn-alfa',
    'host.name.keyword': 'wkstn-alfa',
    'user.name': 'WKS-0042$',
    'user.effective.name': 'jdoe',
    'user.effective.domain': 'CONTOSO.LAB',
    'user.effective.domain.keyword': 'CONTOSO.LAB',
    'user.effective.id': 'S-1-5-21-1000',
    'source.ip': '10.0.20.5',
    'dns.question.name': 'wkstn-alfa',
    'event.code': '4624',
    'host.os.name': 'Windows 11',
    message: 'Account logon: CONTOSO.LAB\\jdoe from WKS-0042$',
    ...overrides,
  };

  return HEADER_NAMES.map((name) => {
    const value = values[name] ?? '';
    return value.includes(',') || value.includes('"') || value.includes('\n')
      ? `"${value.replace(/"/g, '""')}"`
      : value;
  }).join(',');
}

function fixture(extraRows: string[] = []): string {
  return [HEADER, dataRow(), ...extraRows].join('\n');
}

const csvOptions = {
  key: KEY,
  keyEncoding: 'hex' as const,
  csv: true,
};

describe('csv sanitization', () => {
  it('keeps the header byte-identical and redacts typed ECS columns', () => {
    const input = fixture();
    const { output, report } = sanitizeText(input, csvOptions);
    const lines = output.split('\n');

    expect(lines[0]).toBe(HEADER);

    const cells = lines[1]!.split(',');
    expect(cells[1]).toMatch(/^<HOST:[0-9a-f]{16}>$/);
    expect(cells[2]).toBe(cells[1]);
    expect(cells[3]).toMatch(/^<USER:[0-9a-f]{16}>\$$/);
    expect(cells[5]).toMatch(/^<HOST:[0-9a-f]{16}>$/);
    expect(cells[6]).toBe(cells[5]);
    expect(cells[4]).toMatch(/^<USER:[0-9a-f]{16}>$/);
    expect(cells[10]).toBe('4624');
    expect(cells[11]).toBe('Windows 11');
    expect(report.counts.users).toBeGreaterThan(0);
    expect(report.counts.hosts).toBeGreaterThan(0);
    expect(report.counts.ips).toBe(1);
  });

  it('leaves SYSTEM and dash placeholders unchanged', () => {
    const input = fixture([
      dataRow({ 'user.name': 'SYSTEM', 'user.effective.domain': '-', 'source.ip': '8.8.8.8' }),
    ]);
    const { output } = sanitizeText(input, csvOptions);
    const row = output.split('\n')[2]!;
    const cells = row.split(',');

    expect(cells[3]).toBe('SYSTEM');
    expect(cells[5]).toBe('-');
    expect(cells[8]).toMatch(/^<IP:[0-9a-f]{16}>$/);
  });

  it('applies the value dictionary inside message cells', () => {
    const { output } = sanitizeText(fixture(), csvOptions);
    const message = output.split('\n')[1]!.split(',').at(-1);

    expect(message).toMatch(/<HOST:[0-9a-f]{16}>\\<USER:[0-9a-f]{16}>/);
    expect(message).toMatch(/<USER:[0-9a-f]{16}>\$$/);
    expect(message).not.toContain('CONTOSO.LAB');
    expect(message).not.toContain('WKS-0042$');
  });

  it('respects keepPrivateIps for private source.ip values', () => {
    const base = fixture();
    const withPrivate = sanitizeText(base, { ...csvOptions, keepPrivateIps: true });
    const without = sanitizeText(base, csvOptions);

    expect(withPrivate.output).toContain('10.0.20.5');
    expect(without.output.split('\n')[1]).toMatch(/<IP:[0-9a-f]{16}>/);
  });

  it('round-trips quoted cells with comma, quotes and newline', () => {
    const tricky = 'alpha,"beta, ""gamma""",delta\nomega';
    const input = fixture([dataRow({ message: tricky })]);
    const { output } = sanitizeText(input, csvOptions);
    const splitter = createCsvRecordSplitter();
    const records = [...splitter.push(output), ...splitter.flush()];
    const parsed = parseCsvRecord(records[2]!, { delimiter: ',', quote: '"' });
    const messageField = parsed.fields.at(-1)!;

    expect(messageField.quoted).toBe(true);
    expect(messageField.value).toContain('beta, ""gamma""');
    expect(messageField.value).toContain('delta');
    expect(messageField.value).toContain('omega');
  });

  it('counts misaligned rows and regex-scans every cell', () => {
    const misaligned = `${dataRow()},extra,fields`;
    const input = fixture([misaligned]);
    const { output, report } = sanitizeText(input, csvOptions);

    expect(report.csv?.misalignedRows).toBe(1);
    expect(output).toContain('<HOST:');
    expect(output).toContain('<USER:');
  });

  it('classifies data-only shards with csv.header', () => {
    const shard = dataRow();
    const withHeader = sanitizeText(fixture(), csvOptions);
    const shardOnly = sanitizeText(`${shard}\n`, {
      ...csvOptions,
      csv: { header: [...HEADER_NAMES] },
    });

    expect(shardOnly.output.trim()).toBe(withHeader.output.split('\n')[1]);
  });

  it('matches sanitizeText when sanitizeStream uses tiny chunks', async () => {
    const input = fixture();
    const textResult = sanitizeText(input, csvOptions);
    const sink = toStringSink();
    const sanitizer = createSanitizer(csvOptions);

    await sanitizer.sanitizeStream(fromString(input, 3), sink);

    expect(sink.text).toBe(textResult.output);
  });

  it('auto-detects semicolon delimiters', () => {
    const semiHeader = HEADER.replace(/,/g, ';');
    const semiRow = dataRow().replace(/,/g, ';');
    const input = `${semiHeader}\n${semiRow}\n`;
    const { output } = sanitizeText(input, csvOptions);
    const cells = output.split('\n')[1]!.split(';');

    expect(cells[3]).toMatch(/^<USER:[0-9a-f]{16}>\$$/);
  });

  it('exposes csv column plans in the report', () => {
    const { report } = sanitizeText(fixture(), csvOptions);

    expect(report.csv?.columns.length).toBe(HEADER_NAMES.length);
    expect(report.csv?.columns.find((col) => col.name === 'host.name')).toEqual({
      name: 'host.name',
      action: 'rule',
      ruleId: 'hosts',
    });
    expect(report.csv?.columns.find((col) => col.name === 'message')).toEqual({
      name: 'message',
      action: 'scan',
      ruleId: null,
    });
  });

  it('preserves UTF-8 BOM in output', () => {
    const { output } = sanitizeText(`\uFEFF${fixture()}`, csvOptions);

    expect(output.startsWith('\uFEFF')).toBe(true);
    expect(output.slice(1).split('\n')[0]).toBe(HEADER);
  });

  it('does not change line-mode behavior when csv is disabled', () => {
    const line = 'login from 8.8.8.8';
    const plain = sanitizeText(line, { key: KEY, keyEncoding: 'hex', rules: ['ips'] });
    const withFalse = sanitizeText(line, {
      key: KEY,
      keyEncoding: 'hex',
      rules: ['ips'],
      csv: false,
    });

    expect(withFalse).toEqual(plain);
  });

  it('supports sanitizeStream with csv enabled', async () => {
    const sink = toStringSink();
    const report = await sanitizeStream(fromString(fixture()), sink, csvOptions);

    expect(sink.text.split('\n')[0]).toBe(HEADER);
    expect(report.csv?.columns.length).toBe(HEADER_NAMES.length);
  });
});
