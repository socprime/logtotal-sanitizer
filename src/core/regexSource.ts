export function matchParen(source: string, openIndex: number): number {
  let depth = 0;
  let inClass = false;

  for (let index = openIndex; index < source.length; index += 1) {
    const char = source[index];

    if (char === '\\') {
      index += 1;
      continue;
    }

    if (inClass) {
      if (char === ']') {
        inClass = false;
      }

      continue;
    }

    if (char === '[') {
      inClass = true;
      continue;
    }

    if (char === '(') {
      depth += 1;
    } else if (char === ')') {
      depth -= 1;

      if (depth === 0) {
        return index;
      }
    }
  }

  return -1;
}

export function countCapturingGroups(source: string): number {
  let count = 0;
  let inClass = false;

  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];

    if (char === '\\') {
      index += 1;
      continue;
    }

    if (inClass) {
      if (char === ']') {
        inClass = false;
      }

      continue;
    }

    if (char === '[') {
      inClass = true;
      continue;
    }

    if (char !== '(') {
      continue;
    }

    const next = source.slice(index, index + 4);

    if (
      next.startsWith('(?:') ||
      next.startsWith('(?=') ||
      next.startsWith('(?!') ||
      next.startsWith('(?<=') ||
      next.startsWith('(?<!')
    ) {
      continue;
    }

    count += 1;
  }

  return count;
}

export function deriveGateSource(source: string): string {
  let output = '';
  let inClass = false;

  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];

    if (char === '\\') {
      output += source.slice(index, index + 2);
      index += 1;
      continue;
    }

    if (inClass) {
      output += char;

      if (char === ']') {
        inClass = false;
      }

      continue;
    }

    if (char === '[') {
      inClass = true;
      output += char;
      continue;
    }

    if (char === '(' && source.startsWith('(?<=', index)) {
      const close = matchParen(source, index);

      if (close === -1) {
        output += char;
        continue;
      }

      output += `(?:${source.slice(index + 4, close)})`;
      index = close;
      continue;
    }

    if (
      char === '(' &&
      (source.startsWith('(?<!', index) ||
        source.startsWith('(?=', index) ||
        source.startsWith('(?!', index))
    ) {
      const close = matchParen(source, index);

      if (close === -1) {
        output += char;
        continue;
      }

      index = close;
      continue;
    }

    output += char;
  }

  return output;
}

const asciiMaskCache = new Map<string, Uint8Array>();

function asciiMaskFor(chars: string): Uint8Array | null {
  const cached = asciiMaskCache.get(chars);

  if (cached !== undefined) {
    return cached;
  }

  const mask = new Uint8Array(128);

  for (let i = 0; i < chars.length; i += 1) {
    const code = chars.charCodeAt(i);

    if (code >= 128) {
      return null;
    }

    mask[code] = 1;
  }

  asciiMaskCache.set(chars, mask);
  return mask;
}

export function lineHasAnyChar(line: string, chars: string): boolean {
  const mask = asciiMaskFor(chars);

  if (mask !== null) {
    for (let index = 0; index < line.length; index += 1) {
      const code = line.charCodeAt(index);

      if (code < 128 && mask[code] === 1) {
        return true;
      }
    }

    return false;
  }

  for (let index = 0; index < line.length; index += 1) {
    if (chars.includes(line[index]!)) {
      return true;
    }
  }

  return false;
}
