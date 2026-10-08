const BLOCK_BYTES = 64;
const DIGEST_BYTES = 32;

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const INITIAL_STATE = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

function rotr(value: number, bits: number): number {
  return ((value >>> bits) | (value << (32 - bits))) >>> 0;
}

function compressBlock(state: Uint32Array, view: DataView, offset: number, w: Uint32Array): void {
  for (let i = 0; i < 16; i += 1) {
    w[i] = view.getUint32(offset + i * 4, false);
  }

  for (let i = 16; i < 64; i += 1) {
    const x = w[i - 15]!;
    const y = w[i - 2]!;
    const s0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3);
    const s1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10);
    w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) >>> 0;
  }

  let a = state[0]!;
  let b = state[1]!;
  let c = state[2]!;
  let d = state[3]!;
  let e = state[4]!;
  let f = state[5]!;
  let g = state[6]!;
  let h = state[7]!;

  for (let i = 0; i < 64; i += 1) {
    const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const ch = (e & f) ^ (~e & g);
    const temp1 = (h + s1 + ch + K[i]! + w[i]!) >>> 0;
    const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = (s0 + maj) >>> 0;

    h = g;
    g = f;
    f = e;
    e = (d + temp1) >>> 0;
    d = c;
    c = b;
    b = a;
    a = (temp1 + temp2) >>> 0;
  }

  state[0] = (state[0]! + a) >>> 0;
  state[1] = (state[1]! + b) >>> 0;
  state[2] = (state[2]! + c) >>> 0;
  state[3] = (state[3]! + d) >>> 0;
  state[4] = (state[4]! + e) >>> 0;
  state[5] = (state[5]! + f) >>> 0;
  state[6] = (state[6]! + g) >>> 0;
  state[7] = (state[7]! + h) >>> 0;
}

function padMessage(message: Uint8Array): Uint8Array {
  const bitLength = message.length * 8;
  const paddedLength = Math.ceil((message.length + 9) / BLOCK_BYTES) * BLOCK_BYTES;
  const padded = new Uint8Array(paddedLength);

  padded.set(message);
  padded[message.length] = 0x80;

  const view = new DataView(padded.buffer);
  view.setUint32(paddedLength - 8, Math.floor(bitLength / 2 ** 32), false);
  view.setUint32(paddedLength - 4, bitLength >>> 0, false);

  return padded;
}

export function sha256(message: Uint8Array): Uint8Array {
  const padded = padMessage(message);
  const view = new DataView(padded.buffer);
  const state = Uint32Array.from(INITIAL_STATE);
  const w = new Uint32Array(64);

  for (let offset = 0; offset < padded.length; offset += BLOCK_BYTES) {
    compressBlock(state, view, offset, w);
  }

  const digest = new Uint8Array(DIGEST_BYTES);
  const digestView = new DataView(digest.buffer);

  for (let i = 0; i < 8; i += 1) {
    digestView.setUint32(i * 4, state[i]!, false);
  }

  return digest;
}

function stateToDigest(state: Uint32Array): Uint8Array {
  const digest = new Uint8Array(DIGEST_BYTES);
  const digestView = new DataView(digest.buffer);

  for (let i = 0; i < 8; i += 1) {
    digestView.setUint32(i * 4, state[i]!, false);
  }

  return digest;
}

function normalizeKey(key: Uint8Array): Uint8Array {
  const hashed = key.length > BLOCK_BYTES ? sha256(key) : key;

  if (hashed.length === BLOCK_BYTES) {
    return hashed;
  }

  const padded = new Uint8Array(BLOCK_BYTES);
  padded.set(hashed);
  return padded;
}

export type KeyedHmacSha256 = (message: Uint8Array) => Uint8Array;

export function createHmacSha256(key: Uint8Array): KeyedHmacSha256 {
  const block = normalizeKey(key);
  const ipad = new Uint8Array(BLOCK_BYTES);
  const opad = new Uint8Array(BLOCK_BYTES);

  for (let i = 0; i < BLOCK_BYTES; i += 1) {
    ipad[i] = block[i]! ^ 0x36;
    opad[i] = block[i]! ^ 0x5c;
  }

  const w = new Uint32Array(64);
  const midInner = Uint32Array.from(INITIAL_STATE);
  const midOuter = Uint32Array.from(INITIAL_STATE);

  const padView = new DataView(new ArrayBuffer(BLOCK_BYTES));

  for (let i = 0; i < BLOCK_BYTES; i += 1) {
    padView.setUint8(i, ipad[i]!);
  }

  compressBlock(midInner, padView, 0, w);

  for (let i = 0; i < BLOCK_BYTES; i += 1) {
    padView.setUint8(i, opad[i]!);
  }

  compressBlock(midOuter, padView, 0, w);

  const scratch = new Uint8Array(BLOCK_BYTES * 2);
  const scratchView = new DataView(scratch.buffer);
  const outerBlock = new Uint8Array(BLOCK_BYTES);
  const outerView = new DataView(outerBlock.buffer);
  const state = new Uint32Array(8);

  return (message: Uint8Array): Uint8Array => {
    const len = message.length;
    const scratchLength = Math.ceil((len + 9) / BLOCK_BYTES) * BLOCK_BYTES;

    let bytes = scratch;
    let view = scratchView;

    if (scratchLength > bytes.length) {
      bytes = new Uint8Array(scratchLength);
      view = new DataView(bytes.buffer);
    }

    bytes.set(message, 0);
    bytes[len] = 0x80;
    bytes.fill(0, len + 1, scratchLength - 8);

    const bitLength = (BLOCK_BYTES + len) * 8;
    view.setUint32(scratchLength - 8, Math.floor(bitLength / 2 ** 32), false);
    view.setUint32(scratchLength - 4, bitLength >>> 0, false);

    state.set(midInner);

    for (let offset = 0; offset < scratchLength; offset += BLOCK_BYTES) {
      compressBlock(state, view, offset, w);
    }

    const innerDigest = stateToDigest(state);
    outerBlock.set(innerDigest, 0);
    innerDigest.fill(0);
    outerBlock[DIGEST_BYTES] = 0x80;
    outerBlock.fill(0, DIGEST_BYTES + 1, BLOCK_BYTES - 8);
    outerView.setUint32(BLOCK_BYTES - 8, 0, false);
    outerView.setUint32(BLOCK_BYTES - 4, ((BLOCK_BYTES + DIGEST_BYTES) * 8) >>> 0, false);

    state.set(midOuter);
    compressBlock(state, outerView, 0, w);

    const digest = stateToDigest(state);

    bytes.fill(0, 0, scratchLength);
    outerBlock.fill(0, 0, BLOCK_BYTES);
    w.fill(0);

    return digest;
  };
}

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);

  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }

  return bytes;
}

const HEX_DIGITS = '0123456789abcdef';

export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';

  for (let i = 0; i < bytes.length; i += 1) {
    const byte = bytes[i]!;
    hex += HEX_DIGITS[byte >>> 4]! + HEX_DIGITS[byte & 15]!;
  }

  return hex;
}
