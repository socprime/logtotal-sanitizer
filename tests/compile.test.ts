import { describe, expect, it } from 'vitest';

import { compileRules } from '../src/core/compile.js';
import { type SanitizeRule } from '../src/types.js';

const ruleWithAggressive: SanitizeRule = {
  id: 'ips',
  label: 'IP addresses',
  description: '',
  mode: 'pseudo',
  token: 'IP',
  patterns: ['(?:\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b)'],
  aggressivePatterns: ['(?:\\bwide-\\w+\\b)'],
};

function fragmentMatches(fragment: { regex: RegExp }, text: string): boolean {
  fragment.regex.lastIndex = 0;
  return fragment.regex.test(text);
}

describe('compileRules', () => {
  it('omits aggressivePatterns by default', () => {
    const compiled = compileRules([ruleWithAggressive], false);
    expect(compiled).toHaveLength(1);
    expect(compiled[0]!.fragments).toHaveLength(1);
    expect(fragmentMatches(compiled[0]!.fragments[0]!, '10.0.0.1')).toBe(true);
    expect(fragmentMatches(compiled[0]!.fragments[0]!, 'wide-thing')).toBe(false);
  });

  it('includes aggressivePatterns when aggressive is true', () => {
    const compiled = compileRules([ruleWithAggressive], true);
    expect(compiled[0]!.fragments).toHaveLength(2);
    expect(fragmentMatches(compiled[0]!.fragments[1]!, 'wide-thing')).toBe(true);
  });

  it('does not throw on a duplicate id; createSanitizer replaces by identifier', () => {
    expect(() =>
      compileRules([ruleWithAggressive, { ...ruleWithAggressive }], false),
    ).not.toThrow();
  });

  it('throws on an invalid pattern', () => {
    expect(() => compileRules([{ ...ruleWithAggressive, patterns: ['(?:'] }], false)).toThrow(
      /compile/i,
    );
  });

  it('records the capturing group that marks the replacement value', () => {
    const compiled = compileRules(
      [
        {
          ...ruleWithAggressive,
          id: 'paths',
          patterns: ['(?:/home/([^/]+))', '(?:\\bplain\\b)'],
        },
      ],
      false,
    );

    const [withGroup, withoutGroup] = compiled[0]!.fragments;
    expect(withGroup!.hasValueGroup).toBe(true);
    expect(withoutGroup!.hasValueGroup).toBe(false);
    expect(withGroup!.regex.exec('/home/alice')?.[1]).toBe('alice');
  });
});
