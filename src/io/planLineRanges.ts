import { DEFAULT_RANGE_MAX_PROBE_BYTES, DEFAULT_RANGE_PROBE_BYTES } from '../core/constants';
import { InvalidOptionError } from '../core/errors';
import type { BlobLike } from '../types';

const LF = 0x0a;

export interface ByteRange {
  start: number;
  end: number;
}

export interface PlanLineRangesOptions {
  probeBytes?: number;
  maxProbeBytes?: number;
}

async function snapToNewline(
  blob: BlobLike,
  from: number,
  probeBytes: number,
  maxProbeBytes: number,
): Promise<number | null> {
  if (from <= 0 || from >= blob.size) {
    return null;
  }

  let scanned = 0;
  let window = probeBytes;

  while (scanned < maxProbeBytes && from + scanned < blob.size) {
    const chunkEnd = Math.min(from + Math.min(window, maxProbeBytes), blob.size);
    const buffer = await blob.slice(from + scanned, chunkEnd).arrayBuffer();
    const bytes = new Uint8Array(buffer);
    const idx = bytes.indexOf(LF);

    if (idx !== -1) {
      return from + scanned + idx + 1;
    }

    scanned = chunkEnd - from;
    window = Math.min(window * 2, maxProbeBytes);
  }

  return null;
}

export async function planLineAlignedRanges(
  blob: BlobLike,
  partCount: number,
  options: PlanLineRangesOptions = {},
): Promise<ByteRange[]> {
  if (!Number.isInteger(partCount) || partCount < 1) {
    throw new InvalidOptionError('partCount must be an integer >= 1.');
  }

  const probeBytes = options.probeBytes ?? DEFAULT_RANGE_PROBE_BYTES;
  const maxProbeBytes = options.maxProbeBytes ?? DEFAULT_RANGE_MAX_PROBE_BYTES;

  if (!Number.isInteger(probeBytes) || probeBytes < 1) {
    throw new InvalidOptionError('probeBytes must be an integer >= 1.');
  }

  if (!Number.isInteger(maxProbeBytes) || maxProbeBytes < probeBytes) {
    throw new InvalidOptionError('maxProbeBytes must be an integer >= probeBytes.');
  }

  if (blob.size <= 0) {
    return [];
  }

  if (partCount === 1) {
    return [{ start: 0, end: blob.size }];
  }

  const cuts = new Set<number>();

  for (let i = 1; i < partCount; i += 1) {
    const nominal = Math.round((blob.size * i) / partCount);
    const snapped = await snapToNewline(blob, nominal, probeBytes, maxProbeBytes);

    if (snapped !== null && snapped > 0 && snapped < blob.size) {
      cuts.add(snapped);
    }
  }

  const bounds = [0, ...[...cuts].sort((a, b) => a - b), blob.size];
  const ranges: ByteRange[] = [];

  for (let i = 0; i < bounds.length - 1; i += 1) {
    const start = bounds[i]!;
    const end = bounds[i + 1]!;

    if (end > start) {
      ranges.push({ start, end });
    }
  }

  return ranges;
}
