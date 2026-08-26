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

export function lineHasAnyChar(line: string, chars: string): boolean {
  for (let index = 0; index < line.length; index += 1) {
    if (chars.includes(line[index]!)) {
      return true;
    }
  }

  return false;
}
