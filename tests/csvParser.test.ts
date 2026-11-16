import { describe, expect, it } from 'vitest';

import {
  createCsvRecordSplitter,
  detectDialect,
  parseCsvRecord,
  serializeCsvField,
  serializeCsvRecord,
  stripBom,
  type CsvDialect,
} from '../src/csv/parser.js';

const COMMA: CsvDialect = { delimiter: ',', quote: '"' };

function collectRecords(
  input: string,
  chunkSize?: number,
  options?: { maxRecordChars?: number },
): string[] {
  const splitter = createCsvRecordSplitter(options);
  const records: string[] = [];

  if (chunkSize === undefined) {
    records.push(...splitter.push(input));
  } else {
    for (let offset = 0; offset < input.length; offset += chunkSize) {
      records.push(...splitter.push(input.slice(offset, offset + chunkSize)));
    }
  }

  records.push(...splitter.flush());
  return records;
}

function reassemble(records: string[]): string {
  return records.join('');
}

function roundTripInput(input: string, dialect: CsvDialect = COMMA): string {
  const records = collectRecords(input);
  return records
    .map((record) => {
      const parsed = parseCsvRecord(record, dialect);
      return serializeCsvRecord(
        parsed.fields.map((field) => field.raw),
        parsed.terminator,
        dialect,
      );
    })
    .join('');
}

describe('detectDialect', () => {
  it.each([
    ['comma', 'name,age,city\nAlice,30,NYC\nBob,25,LA\n', ','],
    ['semicolon', 'name;age;city\nAlice;30;NYC\nBob;25;LA\n', ';'],
    ['tab', 'name\tage\tcity\nAlice\t30\tNYC\nBob\t25\tLA\n', '\t'],
    ['pipe', 'name|age|city\nAlice|30|NYC\nBob|25|LA\n', '|'],
  ])('detects %s delimiter', (_label, sample, delimiter) => {
    expect(detectDialect(sample).delimiter).toBe(delimiter);
  });

  it('ignores delimiters inside quoted fields', () => {
    const sample = 'a,"b,c",d\n1,"2;3",4\n';
    expect(detectDialect(sample).delimiter).toBe(',');
  });
});

describe('createCsvRecordSplitter', () => {
  it('splits embedded newlines inside quoted fields', () => {
    const input = 'header\n"line1\nline2",value\n';
    const records = collectRecords(input);

    expect(records).toEqual(['header\n', '"line1\nline2",value\n']);
  });

  it('preserves CRLF terminators', () => {
    const input = 'a,b\r\nc,d\r\n';
    expect(collectRecords(input)).toEqual(['a,b\r\n', 'c,d\r\n']);
  });

  it('splits CRLF across chunk boundaries', () => {
    const input = 'a,b\r\nc,d\r\n';
    const records = collectRecords(input, 3);

    expect(reassemble(records)).toBe(input);
    expect(records).toEqual(['a,b\r\n', 'c,d\r\n']);
  });

  it('splits doubled quotes across chunk boundaries', () => {
    const input = '"a""b",next\n';
    const records = collectRecords(input, 2);

    expect(records).toEqual([input]);
  });

  it('returns the last record without a newline on flush', () => {
    const records = collectRecords('only,one');

    expect(records).toEqual(['only,one']);
  });
});

describe('stripBom', () => {
  it('strips a UTF-8 BOM prefix', () => {
    expect(stripBom('\uFEFFname,age\n')).toEqual({
      bom: '\uFEFF',
      text: 'name,age\n',
    });
  });
});

describe('parseCsvRecord', () => {
  it('parses empty and unquoted fields', () => {
    const parsed = parseCsvRecord('a,,c\n', COMMA);

    expect(parsed.terminator).toBe('\n');
    expect(parsed.fields.map((field) => field.value)).toEqual(['a', '', 'c']);
    expect(parsed.fields.map((field) => field.raw)).toEqual(['a', '', 'c']);
    expect(parsed.fields.map((field) => field.quoted)).toEqual([false, false, false]);
  });

  it('unescapes quoted fields and keeps raw slices', () => {
    const parsed = parseCsvRecord('"a""b",c\r\n', COMMA);

    expect(parsed.terminator).toBe('\r\n');
    expect(parsed.fields[0]).toEqual({ value: 'a"b', raw: '"a""b"', quoted: true });
    expect(parsed.fields[1]).toEqual({ value: 'c', raw: 'c', quoted: false });
  });
});

describe('round-trip identity', () => {
  const fixtures = [
    'a,b,c\n',
    'a,"b,c",d\r\n',
    '"x""y",z\n',
    'unquoted,with"stray"quote\n',
    'empty,,trailing,\n',
    '\uFEFFh1,h2\n',
    'single',
    '"multi\nline",ok\n',
  ];

  it.each(fixtures)('preserves bytes for %#', (fixture) => {
    const dialect = detectDialect(fixture);
    expect(roundTripInput(fixture, dialect)).toBe(fixture);
  });
});

describe('serializeCsvField', () => {
  it('returns raw when the value is unchanged', () => {
    const field = { value: 'plain', raw: 'plain', quoted: false };

    expect(serializeCsvField(field, 'plain', COMMA)).toBe('plain');
  });

  it('quotes values containing special characters', () => {
    expect(serializeCsvField({ value: 'a', raw: 'a', quoted: false }, 'a,b', COMMA)).toBe('"a,b"');
    expect(serializeCsvField({ value: 'a', raw: 'a', quoted: false }, 'a"b', COMMA)).toBe('"a""b"');
    expect(serializeCsvField({ value: 'a', raw: 'a', quoted: false }, 'a\nb', COMMA)).toBe(
      '"a\nb"',
    );
  });

  it('keeps originally quoted fields quoted when modified', () => {
    const field = { value: 'x', raw: '"x"', quoted: true };

    expect(serializeCsvField(field, 'y', COMMA)).toBe('"y"');
  });
});

describe('chunking invariants', () => {
  const fixture =
    'header,id,text\n' +
    '1,"embedded\nnewline","quote""inside"\n' +
    '2,plain,"a,b"\r\n' +
    '3,last-no-newline';

  it('yields identical records for every split index', () => {
    const baseline = collectRecords(fixture);

    for (let splitAt = 1; splitAt < fixture.length; splitAt += 1) {
      const records = collectRecords(fixture, splitAt);
      expect(records).toEqual(baseline);
      expect(reassemble(records)).toBe(fixture);
    }
  });

  it('yields identical records across random chunk sizes', () => {
    const baseline = collectRecords(fixture);
    const chunkSizes = [1, 2, 3, 5, 7, 13, 27, 64, 97, 256, 1024];

    for (const chunkSize of chunkSizes) {
      const records = collectRecords(fixture, chunkSize);
      expect(records).toEqual(baseline);
    }
  });
});

describe('maxRecordChars fallback', () => {
  it('stops quoting and emits at the next newline for an unclosed quote', () => {
    const prefix = '"';
    const payload = 'x'.repeat(32);
    const input = `${prefix}${payload}\nsecond\n`;
    const records = collectRecords(input, undefined, { maxRecordChars: 16 });

    expect(records.length).toBeGreaterThanOrEqual(2);
    expect(records[0]).toContain('\n');
    expect(reassemble(records)).toBe(input);
  });
});
