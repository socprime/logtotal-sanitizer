import type { LineOptions } from '../types';
import { DEFAULT_LINE_OVERLAP_CHARS, DEFAULT_MAX_LINE_CHARS } from './constants';
import { InvalidOptionError } from './errors';

export interface LineSplitter {
  push(chunk: string): string[];
  flush(): string[];
}

function extractLines(buffer: string): { lines: string[]; rest: string } {
  const lines: string[] = [];
  let start = 0;

  for (let end = buffer.indexOf('\n', start); end !== -1; end = buffer.indexOf('\n', end + 1)) {
    lines.push(buffer.slice(start, end + 1));
    start = end + 1;
  }

  return { lines, rest: buffer.slice(start) };
}

export function createLineSplitter(options: LineOptions = {}): LineSplitter {
  const maxLineChars = options.maxLineChars ?? DEFAULT_MAX_LINE_CHARS;
  const overlapChars = options.overlapChars ?? DEFAULT_LINE_OVERLAP_CHARS;

  if (maxLineChars < 1) {
    throw new InvalidOptionError('lines.maxLineChars must be at least 1.');
  }

  if (overlapChars < 0 || overlapChars >= maxLineChars) {
    throw new InvalidOptionError(
      `lines.overlapChars must be between 0 and lines.maxLineChars - 1 (${maxLineChars - 1}), got ${overlapChars}.`,
    );
  }

  let carry = '';

  function push(chunk: string): string[] {
    carry += chunk;

    const { lines, rest } = extractLines(carry);
    carry = rest;

    while (carry.length > maxLineChars) {
      const cut = carry.length - overlapChars;
      lines.push(carry.slice(0, cut));
      carry = carry.slice(cut);
    }

    return lines;
  }

  function flush(): string[] {
    if (carry.length === 0) {
      return [];
    }

    const rest = carry;
    carry = '';
    return [rest];
  }

  return { push, flush };
}
