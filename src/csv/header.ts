import { InvalidOptionError } from '../core/errors';
import {
  createCsvRecordSplitter,
  detectDialect,
  parseCsvRecord,
  stripBom,
  type CsvDialect,
} from './parser';

const HEADER_STEP_BYTES = 64 * 1024;
const DEFAULT_MAX_HEADER_BYTES = 4 * 1024 * 1024;

/**
 * CSV options implied by a path and format when the caller did not pass `csv`.
 *
 * `.tsv` selects a tab delimiter. Any other CSV input leaves the delimiter to detection.
 */
export function csvOptionsForFormat(
  format: string,
  inputPath?: string,
): true | { delimiter: '\t' } | undefined {
  if (format !== 'auto' && format !== 'lines' && format !== 'csv') {
    throw new InvalidOptionError('format must be "auto", "lines", or "csv".');
  }

  if (format === 'lines') {
    return undefined;
  }

  const lower = inputPath?.toLowerCase();
  const tsv = lower?.endsWith('.tsv') === true;

  if (format === 'csv') {
    return tsv ? { delimiter: '\t' } : true;
  }

  if (tsv) {
    return { delimiter: '\t' };
  }

  if (lower?.endsWith('.csv') === true) {
    return true;
  }

  return undefined;
}

/**
 * Reads the first CSV record and returns its field values.
 *
 * The blob is decoded in 64 KiB steps until one complete record is available. Quoted newlines
 * stay inside that record. A leading UTF-8 BOM is removed. The delimiter is detected when
 * `options.delimiter` is omitted.
 *
 * Parallel workers use this so shard 0 can run with `csv: true` and later shards with
 * `csv: { header }`.
 *
 * @throws {InvalidOptionError} When no complete record occurs within `maxBytes` (default 4 MiB).
 */
export async function readCsvHeader(
  blob: Blob,
  options?: { delimiter?: string; maxBytes?: number },
): Promise<string[]> {
  const maxBytes = options?.maxBytes ?? DEFAULT_MAX_HEADER_BYTES;

  if (!Number.isInteger(maxBytes) || maxBytes < 1) {
    throw new InvalidOptionError('maxBytes must be an integer >= 1.');
  }

  const splitter = createCsvRecordSplitter({ maxRecordChars: maxBytes });
  const decoder = new TextDecoder('utf-8');
  const limit = Math.min(blob.size, maxBytes);
  let offset = 0;
  let record: string | undefined;

  while (offset < limit) {
    const end = Math.min(offset + HEADER_STEP_BYTES, limit);
    const bytes = new Uint8Array(await blob.slice(offset, end).arrayBuffer());
    offset = end;
    const chunk = decoder.decode(bytes, { stream: offset < blob.size });
    const records = splitter.push(chunk);

    if (records.length > 0) {
      record = records[0];
      break;
    }
  }

  if (record === undefined && offset >= blob.size) {
    record = splitter.flush()[0];
  }

  if (record === undefined) {
    throw new InvalidOptionError(`No complete CSV record within ${maxBytes} bytes.`);
  }

  const { text } = stripBom(record);
  const dialect: CsvDialect =
    options?.delimiter === undefined
      ? detectDialect(text)
      : { delimiter: options.delimiter, quote: '"' };

  return parseCsvRecord(text, dialect).fields.map((field) => field.value);
}
