import { InvalidRuleError } from '../core/errors';
import { countCapturingGroups } from '../core/regexSource';
import type { SanitizeRule } from '../types';

const RULE_ID_PATTERN = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
const TOKEN_PATTERN = /^[A-Z][A-Z0-9]*$/;
const NAMED_GROUP_PATTERN = /\(\?<[^=!]/;

function requireText(value: unknown, rule: string, field: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new InvalidRuleError(`Rule "${rule}": \`${field}\` must be a non-empty string.`);
  }

  return value;
}

function assertPatterns(patterns: unknown, ruleId: string, field: string): string[] {
  if (patterns === undefined) {
    return [];
  }

  if (!Array.isArray(patterns)) {
    throw new InvalidRuleError(`Rule "${ruleId}": \`${field}\` must be an array of strings.`);
  }

  return patterns.map((pattern: unknown, index) => {
    if (typeof pattern !== 'string' || pattern.length === 0) {
      throw new InvalidRuleError(
        `Rule "${ruleId}": \`${field}[${index}]\` must be a non-empty regular expression source.`,
      );
    }

    if (NAMED_GROUP_PATTERN.test(pattern)) {
      throw new InvalidRuleError(
        `Rule "${ruleId}": \`${field}[${index}]\` must not declare a named capture group.`,
      );
    }

    try {
      new RegExp(pattern, 'u');
    } catch (cause) {
      throw new InvalidRuleError(
        `Rule "${ruleId}": \`${field}[${index}]\` is not a valid Unicode regular expression: ${String(cause)}`,
      );
    }

    if (countCapturingGroups(pattern) > 1) {
      throw new InvalidRuleError(
        `Rule "${ruleId}": \`${field}[${index}]\` must contain at most one capturing group, which marks the value to replace.`,
      );
    }

    return pattern;
  });
}

export function validateRule(rule: SanitizeRule): SanitizeRule {
  if (typeof rule !== 'object' || rule === null) {
    throw new InvalidRuleError('A rule must be an object.');
  }

  const id = requireText(rule.id, String(rule.id), 'id');

  if (!RULE_ID_PATTERN.test(id)) {
    throw new InvalidRuleError(
      `Rule "${id}": \`id\` must be a valid ASCII identifier matching ${RULE_ID_PATTERN.source}.`,
    );
  }

  requireText(rule.label, id, 'label');
  requireText(rule.description, id, 'description');

  if (rule.mode !== 'pseudo' && rule.mode !== 'mask') {
    throw new InvalidRuleError(`Rule "${id}": \`mode\` must be either "pseudo" or "mask".`);
  }

  if (rule.token !== undefined && !TOKEN_PATTERN.test(rule.token)) {
    throw new InvalidRuleError(
      `Rule "${id}": \`token\` must match ${TOKEN_PATTERN.source}, so replacement tokens stay recognizable.`,
    );
  }

  const patterns = assertPatterns(rule.patterns, id, 'patterns');
  const aggressivePatterns = assertPatterns(rule.aggressivePatterns, id, 'aggressivePatterns');

  if (patterns.length === 0 && aggressivePatterns.length === 0) {
    throw new InvalidRuleError(`Rule "${id}": at least one pattern is required.`);
  }

  if (rule.jsonKeys !== undefined) {
    if (!Array.isArray(rule.jsonKeys)) {
      throw new InvalidRuleError(`Rule "${id}": \`jsonKeys\` must be an array of strings.`);
    }

    for (const [index, key] of rule.jsonKeys.entries()) {
      requireText(key, id, `jsonKeys[${index}]`);
    }
  }

  if (rule.validate !== undefined && typeof rule.validate !== 'function') {
    throw new InvalidRuleError(`Rule "${id}": \`validate\` must be a function.`);
  }

  return rule;
}
