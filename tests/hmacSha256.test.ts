import { createHash, createHmac } from 'node:crypto';

import { describe, expect, it } from 'vitest';
import { bytesToHex, createHmacSha256, hexToBytes, sha256 } from '../src/core/hmac.js';

const textEncoder = new TextEncoder();

function hmac(keyHex: string, messageHex: string): string {
  return bytesToHex(createHmacSha256(hexToBytes(keyHex))(hexToBytes(messageHex)));
}

describe('sha256', () => {
  it('matches the known digest of "abc"', () => {
    expect(bytesToHex(sha256(textEncoder.encode('abc')))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('matches the known digest of the empty string', () => {
    expect(bytesToHex(sha256(new Uint8Array(0)))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });
});

describe('createHmacSha256', () => {
  it('matches RFC 4231 test case 1', () => {
    expect(
      hmac('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', bytesToHex(textEncoder.encode('Hi There'))),
    ).toBe('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
  });

  it('matches RFC 4231 test case 2', () => {
    expect(
      hmac(
        bytesToHex(textEncoder.encode('Jefe')),
        bytesToHex(textEncoder.encode('what do ya want for nothing?')),
      ),
    ).toBe('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
  });

  it('is deterministic for the same key and message', () => {
    const key = hexToBytes('00'.repeat(32));
    const message = textEncoder.encode('same input every time');
    const sign = createHmacSha256(key);
    expect(bytesToHex(sign(message))).toBe(bytesToHex(sign(message)));
  });
});

function pseudo(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 1) {
    out[i] = (i * 31 + n * 7) % 256;
  }
  return out;
}

describe('sha256 boundaries', () => {
  it('matches Node crypto around the SHA-256 padding and block boundaries', () => {
    for (const length of [0, 1, 54, 55, 56, 63, 64, 65, 66, 119, 120, 121, 128, 129, 1000]) {
      const message = pseudo(length);
      expect(bytesToHex(sha256(message))).toBe(createHash('sha256').update(message).digest('hex'));
    }
  });
});

describe('createHmacSha256 block handling', () => {
  it('matches Node crypto across key lengths and message boundary sizes', () => {
    for (const keyLength of [0, 1, 32, 64, 65, 128]) {
      const key = pseudo(keyLength);
      const sign = createHmacSha256(key);

      for (const length of [0, 1, 54, 55, 56, 63, 64, 65, 119, 120, 121, 256, 1000]) {
        const message = pseudo(length);
        expect(bytesToHex(sign(message))).toBe(
          createHmac('sha256', key).update(message).digest('hex'),
        );
      }
    }
  });

  it('gives the same output for long and short messages in any order', () => {
    const sign = createHmacSha256(pseudo(32));
    const reused = createHmacSha256(pseudo(32));
    const fresh = createHmacSha256(pseudo(32));
    const key = pseudo(32);
    const lengths = [1000, 3, 55, 2, 120, 300, 65, 1];

    for (let round = 0; round < 3; round += 1) {
      for (const length of lengths) {
        const message = pseudo((length + round * 13) % 900);
        const expected = createHmac('sha256', key).update(message).digest('hex');
        sign(message);
        expect(bytesToHex(sign(message))).toBe(expected);
        expect(bytesToHex(reused(message))).toBe(expected);
        expect(bytesToHex(fresh(message))).toBe(expected);
      }
    }
  });

  it('clears throwaway buffers for messages larger than the retained scratch', () => {
    const key = pseudo(32);
    const sign = createHmacSha256(key);

    for (const length of [400, 1000, 65, 3, 200, 7, 999, 0, 300, 55]) {
      const message = pseudo(length);
      expect(bytesToHex(sign(message))).toBe(
        createHmac('sha256', key).update(message).digest('hex'),
      );
    }
  });
});
