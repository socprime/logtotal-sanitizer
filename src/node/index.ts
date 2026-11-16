import { createReadStream, createWriteStream } from 'node:fs';
import { once } from 'node:events';
import type { Readable, Writable } from 'node:stream';
import { finished } from 'node:stream/promises';

import { createSanitizer } from '../core/sanitizer';
import { csvOptionsForFormat } from '../csv/header';
import { toNullSink } from '../io/sinks';
import type {
  AbortSignalLike,
  SanitizeProgress,
  SanitizeReport,
  SanitizerOptions,
  TextSink,
  TextSource,
} from '../types';

const DEFAULT_CHUNK_BYTES = 4 * 1024 * 1024;

/**
 * Reads a Node readable stream as UTF-8 text.
 *
 * Byte chunks are decoded across chunk boundaries, so multi-byte characters are never split.
 */
export function fromNodeStream(stream: Readable | AsyncIterable<string | Uint8Array>): TextSource {
  return {
    async *[Symbol.asyncIterator](): AsyncIterator<string> {
      const decoder = new TextDecoder('utf-8');

      for await (const chunk of stream as AsyncIterable<string | Uint8Array>) {
        const text = typeof chunk === 'string' ? chunk : decoder.decode(chunk, { stream: true });

        if (text.length > 0) {
          yield text;
        }
      }

      const tail = decoder.decode();

      if (tail.length > 0) {
        yield tail;
      }
    },
  };
}

/**
 * Reads a file as UTF-8 text.
 *
 * @param path Path to the file to read.
 * @param chunkBytes Read buffer size.
 */
export function fromFile(path: string, chunkBytes = DEFAULT_CHUNK_BYTES): TextSource {
  return fromNodeStream(createReadStream(path, { highWaterMark: chunkBytes }));
}

/**
 * Writes sanitized text to a Node writable stream, respecting backpressure.
 *
 * The stream is not ended when the run finishes, so it is safe to pass `process.stdout`.
 */
export function toNodeStream(stream: Writable): TextSink {
  return {
    async write(chunk: string): Promise<void> {
      if (!stream.write(chunk)) {
        await once(stream, 'drain');
      }
    },
  };
}

/**
 * Writes sanitized text to a file, creating or truncating it.
 *
 * The file is closed and flushed when the run finishes.
 */
export function toFile(path: string): TextSink {
  const stream = createWriteStream(path, { encoding: 'utf-8' });
  const target = toNodeStream(stream);

  return {
    write: target.write.bind(target),
    async close(): Promise<void> {
      stream.end();
      await finished(stream);
    },
  };
}

/** Options for {@link sanitizeFile}. */
export interface SanitizeFileOptions extends SanitizerOptions {
  /** Path of the file to read. */
  input: string;
  /**
   * Input mode used when `csv` is omitted. `auto` reads paths ending in `.csv` or `.tsv` as CSV
   * (a tab delimiter for `.tsv`) and every other path as lines. `lines` forces line mode. `csv`
   * forces CSV mode, with a tab delimiter for `.tsv` paths.
   * @default 'auto'
   */
  format?: 'auto' | 'lines' | 'csv';
  /** Path to write the sanitized result to. Omit for a report-only run. */
  output?: string;
  /** Read buffer size, in bytes. */
  chunkBytes?: number;
  /** Called after each chunk with a live snapshot of progress. */
  onProgress?: (progress: SanitizeProgress) => void;
  /** Aborts the run between lines. A partially written output file is left in place. */
  signal?: AbortSignalLike;
}

/**
 * Sanitizes a file on disk, streaming it so memory use stays flat regardless of file size.
 *
 * @returns The report for the whole file.
 * @throws {SanitizationAbortedError} When `options.signal` is aborted.
 *
 * @example
 * ```ts
 * const report = await sanitizeFile({
 *   input: 'app.log',
 *   output: 'app.sanitized.log',
 *   rules: ['secrets', 'ips'],
 * });
 *
 * console.log(`${report.totalMatches} values redacted`);
 * ```
 */
export async function sanitizeFile(options: SanitizeFileOptions): Promise<SanitizeReport> {
  const { input, output, chunkBytes, onProgress, signal, format, ...sanitizerOptions } = options;
  const csv =
    sanitizerOptions.csv !== undefined
      ? sanitizerOptions.csv
      : csvOptionsForFormat(format ?? 'auto', input);
  const sanitizer = createSanitizer({ ...sanitizerOptions, csv });
  const sink = output === undefined ? toNullSink() : toFile(output);

  return sanitizer.sanitizeStream(fromFile(input, chunkBytes), sink, { onProgress, signal });
}

export * from '../index';
