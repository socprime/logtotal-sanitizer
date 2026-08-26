import type { SanitizeRule } from '../types';
import type { AllowList } from './allowlist';
import { InvalidRuleError } from './errors';
import { replacementPrefix, type Pseudonymizer } from './pseudonymize';
import { countCapturingGroups, deriveGateSource } from './regexSource';

export interface CompiledFragment {
  regex: RegExp;
  hasValueGroup: boolean;
}

export interface CompiledRule {
  id: string;
  fragments: CompiledFragment[];
  gate: RegExp | null;
  gateChars: string | null;
}

export interface RuleContext {
  compiled: CompiledRule[];
  rules: SanitizeRule[];
  ruleIds: string[];
  rulesById: Map<string, SanitizeRule>;
  prefixById: Map<string, string>;
  pseudonymize: Pseudonymizer;
  allow: AllowList;
  contextChars: number;
  json: boolean;
}

const SKIP_REGEX_GATE = new Set(['ips', 'hosts']);

function gateCharsFor(ruleId: string, aggressive: boolean): string | null {
  if (ruleId === 'phoneNumbers') {
    return '0123456789';
  }

  if (ruleId === 'paymentInfo' && !aggressive) {
    return '0123456789';
  }

  return null;
}

function compileOne(rule: SanitizeRule, aggressive: boolean): CompiledRule | null {
  const patterns = aggressive
    ? [...rule.patterns, ...(rule.aggressivePatterns ?? [])]
    : rule.patterns;

  if (patterns.length === 0) {
    return null;
  }

  const source = patterns.join('|');
  const fragments: CompiledFragment[] = [];

  for (const pattern of patterns) {
    try {
      fragments.push({
        regex: new RegExp(pattern, 'gu'),
        hasValueGroup: countCapturingGroups(pattern) === 1,
      });
    } catch (cause) {
      throw new InvalidRuleError(`Failed to compile rule "${rule.id}": ${String(cause)}`);
    }
  }

  const gateSource = patterns.map(deriveGateSource).join('|');
  let gate: RegExp | null = null;

  if (!SKIP_REGEX_GATE.has(rule.id) && gateSource.length > 0 && gateSource !== source) {
    try {
      gate = new RegExp(gateSource, 'gu');
    } catch {
      gate = null;
    }
  }

  return {
    id: rule.id,
    fragments,
    gate,
    gateChars: gateCharsFor(rule.id, aggressive),
  };
}

export function compileRules(rules: SanitizeRule[], aggressive: boolean): CompiledRule[] {
  const compiled: CompiledRule[] = [];

  for (const rule of rules) {
    const one = compileOne(rule, aggressive);

    if (one) {
      compiled.push(one);
    }
  }

  return compiled;
}

export interface RuleContextInput {
  rules: SanitizeRule[];
  aggressive: boolean;
  pseudonymize: Pseudonymizer;
  allow: AllowList;
  contextChars: number;
  json: boolean;
}

export function createRuleContext(input: RuleContextInput): RuleContext {
  const { rules } = input;

  return {
    compiled: compileRules(rules, input.aggressive),
    rules,
    ruleIds: rules.map((rule) => rule.id),
    rulesById: new Map(rules.map((rule) => [rule.id, rule])),
    prefixById: new Map(rules.map((rule) => [rule.id, replacementPrefix(rule)])),
    pseudonymize: input.pseudonymize,
    allow: input.allow,
    contextChars: input.contextChars,
    json: input.json,
  };
}

export function buildReplacement(ctx: RuleContext, ruleId: string, value: string): string {
  return `<${ctx.prefixById.get(ruleId) ?? ruleId.toUpperCase()}:${ctx.pseudonymize(ruleId, value)}>`;
}
