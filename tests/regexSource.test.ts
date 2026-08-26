import { describe, expect, it } from 'vitest';

import { countCapturingGroups, deriveGateSource, matchParen } from '../src/core/regexSource.js';

describe('countCapturingGroups', () => {
  it('ignores non-capturing groups and lookaround', () => {
    expect(countCapturingGroups('(?:foo)(?=bar)(?!baz)(?<=a)(?<!b)')).toBe(0);
  });

  it('counts a single capturing group', () => {
    expect(countCapturingGroups('(?:/home/([^/]+))')).toBe(1);
  });

  it('counts two capturing groups', () => {
    expect(countCapturingGroups('(foo)(bar)')).toBe(2);
  });

  it('does not count parentheses inside a character class', () => {
    expect(countCapturingGroups('[()](value)')).toBe(1);
  });
});

describe('deriveGateSource', () => {
  it('turns a positive lookbehind into a consumed prefix', () => {
    expect(deriveGateSource('(?:(?<=/home/)alice)')).toBe('(?:(?:/home/)alice)');
  });

  it('strips negative lookbehind and lookahead', () => {
    expect(deriveGateSource('(?:(?<![A-Z])foo(?!bar))')).toBe('(?:foo)');
  });
});

describe('matchParen', () => {
  it('finds the matching close paren', () => {
    expect(matchParen('(foo(bar))', 0)).toBe(9);
    expect(matchParen('(foo(bar))', 4)).toBe(8);
  });
});
