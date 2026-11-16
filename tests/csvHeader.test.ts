import { describe, expect, it } from 'vitest';

import { InvalidOptionError, readCsvHeader } from '../src/index.js';

const STEP_BYTES = 64 * 1024;

describe('readCsvHeader', () => {
  it('strips a BOM and keeps a quoted comma and embedded newline', async () => {
    const csv = '\uFEFF"last, first\nname",age\n1,2\n';

    await expect(readCsvHeader(new Blob([csv]))).resolves.toEqual(['last, first\nname', 'age']);
  });

  it('detects a semicolon delimiter', async () => {
    const csv = 'name;age;city\nAlice;30;NYC\n';

    await expect(readCsvHeader(new Blob([csv]))).resolves.toEqual(['name', 'age', 'city']);
  });

  it('reads a header that spans more than one 64 KiB step', async () => {
    const name = 'h'.repeat(STEP_BYTES + 32);
    const csv = `${name},next\n1,2\n`;

    await expect(readCsvHeader(new Blob([csv]))).resolves.toEqual([name, 'next']);
  });

  it('keeps a multi-byte character that straddles a 64 KiB step', async () => {
    const name = `${'h'.repeat(STEP_BYTES - 1)}ї`;
    const csv = `${name},next\n1,2\n`;

    await expect(readCsvHeader(new Blob([csv]))).resolves.toEqual([name, 'next']);
  });

  it('returns a header with no trailing newline when the blob ends', async () => {
    await expect(readCsvHeader(new Blob(['name,age']))).resolves.toEqual(['name', 'age']);
  });

  it('uses an explicit delimiter', async () => {
    const csv = 'name|age\nAlice|30\n';

    await expect(readCsvHeader(new Blob([csv]), { delimiter: '|' })).resolves.toEqual([
      'name',
      'age',
    ]);
  });

  it('throws when no complete record occurs within maxBytes', async () => {
    const blob = new Blob([`${'a'.repeat(50)}\n`]);

    await expect(readCsvHeader(blob, { maxBytes: 20 })).rejects.toBeInstanceOf(InvalidOptionError);
    await expect(readCsvHeader(new Blob([]))).rejects.toBeInstanceOf(InvalidOptionError);
  });
});
