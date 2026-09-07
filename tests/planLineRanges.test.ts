import { describe, expect, it } from 'vitest';

import { InvalidOptionError } from '../src/core/errors.js';
import { planLineAlignedRanges } from '../src/index.js';

function blobFrom(text: string): Blob {
  return new Blob([text]);
}

async function expectCoverage(blob: Blob, partCount: number): Promise<void> {
  const ranges = await planLineAlignedRanges(blob, partCount);

  if (blob.size === 0) {
    expect(ranges).toEqual([]);
    return;
  }

  expect(ranges.length).toBeGreaterThan(0);
  expect(ranges[0]?.start).toBe(0);
  expect(ranges.at(-1)?.end).toBe(blob.size);

  for (let i = 0; i < ranges.length; i += 1) {
    const range = ranges[i]!;
    expect(range.start).toBeLessThan(range.end);

    if (i > 0) {
      expect(range.start).toBe(ranges[i - 1]!.end);
    }

    if (range.start > 0) {
      const before = new Uint8Array(await blob.slice(range.start - 1, range.start).arrayBuffer());
      expect(before[0]).toBe(0x0a);
    }
  }
}

describe('planLineAlignedRanges', () => {
  it('covers the blob without gaps, overlaps or empty ranges', async () => {
    const samples = [
      'a\nb\nc\nd\ne\n',
      'one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\n',
      `${'x'.repeat(100)}\n${'y'.repeat(100)}\n${'z'.repeat(100)}\n`,
      '\n\n\n\n',
      'no-newlines-at-all',
      '\n',
      'trailing-no-nl',
      `\uFEFFalpha\nbeta\ngamma\n`,
    ];

    for (const text of samples) {
      const blob = blobFrom(text);

      for (const partCount of [1, 2, 3, 7, 16, 64]) {
        await expectCoverage(blob, partCount);
      }
    }
  });

  it('returns no ranges for an empty blob', async () => {
    expect(await planLineAlignedRanges(blobFrom(''), 4)).toEqual([]);
  });

  it('returns a single range when the blob has no newlines', async () => {
    const blob = blobFrom('abcdefghij');
    expect(await planLineAlignedRanges(blob, 8)).toEqual([{ start: 0, end: blob.size }]);
  });

  it('returns a single range when partCount is 1', async () => {
    const blob = blobFrom('a\nb\nc\n');
    expect(await planLineAlignedRanges(blob, 1)).toEqual([{ start: 0, end: blob.size }]);
  });

  it('snaps cuts to the byte after the first newline', async () => {
    const blob = blobFrom('aaaa\nbbbb\ncccc\n');
    const ranges = await planLineAlignedRanges(blob, 3);
    expect(ranges.length).toBeGreaterThan(1);

    for (const range of ranges) {
      const slice = new TextDecoder().decode(await blob.slice(range.start, range.end).arrayBuffer());
      if (range.end < blob.size) {
        expect(slice.endsWith('\n')).toBe(true);
      }
    }
  });

  it('drops a cut when the probe window never finds a newline', async () => {
    const blob = blobFrom(`${'a'.repeat(50)}\n${'b'.repeat(50)}`);
    const ranges = await planLineAlignedRanges(blob, 4, { probeBytes: 4, maxProbeBytes: 8 });
    expect(ranges[0]?.start).toBe(0);
    expect(ranges.at(-1)?.end).toBe(blob.size);
    expect(ranges.every((range) => range.end > range.start)).toBe(true);
  });

  it('keeps a BOM in the first range', async () => {
    const blob = blobFrom(`\uFEFFone\ntwo\nthree\n`);
    const ranges = await planLineAlignedRanges(blob, 3);
    const first = new Uint8Array(await blob.slice(ranges[0]!.start, ranges[0]!.start + 3).arrayBuffer());
    expect([...first]).toEqual([0xef, 0xbb, 0xbf]);
  });

  it('rejects a non-positive partCount', async () => {
    await expect(planLineAlignedRanges(blobFrom('a\n'), 0)).rejects.toBeInstanceOf(InvalidOptionError);
  });
});
