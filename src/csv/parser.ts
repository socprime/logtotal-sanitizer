const DELIMITER_CANDIDATES = [',', ';', '\t', '|'] as const;

const DEFAULT_MAX_RECORD_CHARS = 4 * 1024 * 1024;

const UTF8_BOM = '\uFEFF';

export interface CsvDialect {
  delimiter: string;
  quote: '"';
}

export interface CsvRecordSplitter {
  push(chunk: string): string[];
  flush(): string[];
}

export interface CsvField {
  value: string;
  raw: string;
  quoted: boolean;
}

export interface ParsedCsvRecord {
  fields: CsvField[];
  terminator: string;
}

export function createCsvRecordSplitter(
  options: { quote?: string; maxRecordChars?: number } = {},
): CsvRecordSplitter {
  const quote = options.quote ?? '"';
  const maxRecordChars = options.maxRecordChars ?? DEFAULT_MAX_RECORD_CHARS;
  const special = new RegExp(`[${quote.replace(/[\\\]^-]/g, '\\$&')}\\r\\n]`, 'g');

  let carry = '';
  let scanPos = 0;
  let recordStart = 0;
  let inQuotes = false;

  function emit(records: string[], end: number): void {
    records.push(carry.slice(recordStart, end));
    recordStart = end;
    scanPos = end;
  }

  function push(chunk: string): string[] {
    carry += chunk;
    const records: string[] = [];

    while (scanPos < carry.length) {
      if (inQuotes) {
        if (scanPos - recordStart > maxRecordChars) {
          inQuotes = false;
          continue;
        }

        const q = carry.indexOf(quote, scanPos);
        if (q === -1) {
          if (carry.length - recordStart > maxRecordChars) {
            inQuotes = false;
            continue;
          }
          break;
        }

        if (q + 1 < carry.length && carry[q + 1] === quote) {
          scanPos = q + 2;
          continue;
        }

        if (q + 1 >= carry.length) {
          break;
        }

        inQuotes = false;
        scanPos = q + 1;
        continue;
      }

      special.lastIndex = scanPos;
      const found = special.exec(carry);

      if (found === null) {
        scanPos = carry.length;
        break;
      }

      const next = found.index;
      const char = found[0];

      if (char === quote) {
        inQuotes = true;
        scanPos = next + 1;
        continue;
      }

      if (char === '\r') {
        if (next + 1 >= carry.length) {
          scanPos = next;
          break;
        }

        emit(records, carry[next + 1] === '\n' ? next + 2 : next + 1);
        continue;
      }

      emit(records, next + 1);
    }

    if (recordStart > 0) {
      carry = carry.slice(recordStart);
      scanPos -= recordStart;
      recordStart = 0;
    }

    return records;
  }

  function flush(): string[] {
    if (carry.length === 0) {
      return [];
    }

    const rest = carry;
    carry = '';
    scanPos = 0;
    recordStart = 0;
    inQuotes = false;
    return [rest];
  }

  return { push, flush };
}

function splitTerminator(raw: string): { body: string; terminator: string } {
  if (raw.endsWith('\r\n')) {
    return { body: raw.slice(0, -2), terminator: '\r\n' };
  }

  if (raw.endsWith('\n')) {
    return { body: raw.slice(0, -1), terminator: '\n' };
  }

  return { body: raw, terminator: '' };
}

function parseFields(body: string, dialect: CsvDialect): CsvField[] {
  if (body.length === 0) {
    return [{ value: '', raw: '', quoted: false }];
  }

  const fields: CsvField[] = [];
  const { delimiter, quote } = dialect;
  let pos = 0;

  while (pos < body.length) {
    const fieldStart = pos;

    if (body[pos] === quote) {
      let index = pos + 1;
      let value = '';

      while (index < body.length) {
        if (body[index] === quote) {
          if (body[index + 1] === quote) {
            value += quote;
            index += 2;
            continue;
          }

          fields.push({
            value,
            raw: body.slice(fieldStart, index + 1),
            quoted: true,
          });
          pos = index + 1;
          if (pos < body.length && body[pos] === delimiter) {
            pos += 1;
          }
          break;
        }

        value += body[index];
        index += 1;
      }

      if (index >= body.length) {
        fields.push({
          value,
          raw: body.slice(fieldStart),
          quoted: true,
        });
        break;
      }

      continue;
    }

    const delimiterAt = body.indexOf(delimiter, pos);
    const end = delimiterAt === -1 ? body.length : delimiterAt;
    const raw = body.slice(pos, end);
    fields.push({ value: raw, raw, quoted: false });
    pos = end + 1;
    if (delimiterAt === -1) {
      break;
    }
  }

  if (body.endsWith(delimiter)) {
    fields.push({ value: '', raw: '', quoted: false });
  }

  return fields;
}

export function parseCsvRecord(raw: string, dialect: CsvDialect): ParsedCsvRecord {
  const { body, terminator } = splitTerminator(raw);
  const fields = parseFields(body, dialect);
  return { fields, terminator };
}

function collectRecordsFromSample(sample: string): string[] {
  const splitter = createCsvRecordSplitter();
  const records: string[] = [];
  const step = 4096;

  for (let offset = 0; offset < sample.length; offset += step) {
    records.push(...splitter.push(sample.slice(offset, offset + step)));
    if (records.length >= 5) {
      return records.slice(0, 5);
    }
  }

  records.push(...splitter.flush());
  return records.slice(0, 5);
}

export function detectDialect(sample: string): CsvDialect {
  const { text } = stripBom(sample);
  const records = collectRecordsFromSample(text);

  if (records.length === 0) {
    return { delimiter: ',', quote: '"' };
  }

  let bestDelimiter: string = ',';
  let bestScore = -1;

  for (const delimiter of DELIMITER_CANDIDATES) {
    const dialect: CsvDialect = { delimiter, quote: '"' };
    const counts = records.map((record) => parseCsvRecord(record, dialect).fields.length);

    if (counts.every((count) => count <= 1)) {
      continue;
    }

    const reference = counts[0];
    const consistent = counts.filter((count) => count === reference).length;
    const score = consistent * 10_000 + reference;

    if (score > bestScore) {
      bestScore = score;
      bestDelimiter = delimiter;
    }
  }

  return { delimiter: bestDelimiter, quote: '"' };
}

function mustQuoteValue(value: string, dialect: CsvDialect): boolean {
  return (
    value.includes(dialect.delimiter) ||
    value.includes(dialect.quote) ||
    value.includes('\r') ||
    value.includes('\n')
  );
}

export function serializeCsvField(field: CsvField, newValue: string, dialect: CsvDialect): string {
  if (newValue === field.value) {
    return field.raw;
  }

  const quote = field.quoted || mustQuoteValue(newValue, dialect);
  if (!quote) {
    return newValue;
  }

  const escaped = newValue.split(dialect.quote).join(dialect.quote + dialect.quote);
  return dialect.quote + escaped + dialect.quote;
}

export function serializeCsvRecord(
  fields: string[],
  terminator: string,
  dialect: CsvDialect,
): string {
  return fields.join(dialect.delimiter) + terminator;
}

export function stripBom(text: string): { bom: string; text: string } {
  if (text.startsWith(UTF8_BOM)) {
    return { bom: UTF8_BOM, text: text.slice(UTF8_BOM.length) };
  }

  return { bom: '', text };
}
