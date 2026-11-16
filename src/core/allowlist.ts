import { isPrivateIpValue } from '../rules/shared/privateIp';
import type { NeverRedactOptions } from '../types';
import { InvalidOptionError } from './errors';

export interface AllowList {
  empty: boolean;
  keepPrivateIps: boolean;
  values: ReadonlySet<string>;
  pattern: RegExp | null;
  byRule: ReadonlyMap<string, ReadonlySet<string>>;
}

export function patternSource(pattern: string | RegExp): string {
  return typeof pattern === 'string' ? pattern : pattern.source;
}

function compileAnchored(patterns: readonly (string | RegExp)[]): RegExp | null {
  const sources = patterns.map(patternSource).filter((source) => source.length > 0);

  if (sources.length === 0) {
    return null;
  }

  const combined = sources.map((source) => `(?:${source})`).join('|');

  try {
    return new RegExp(`^(?:${combined})$`, 'u');
  } catch (cause) {
    throw new InvalidOptionError(
      `neverRedact.patterns contains an invalid regular expression: ${String(cause)}`,
    );
  }
}

export function createAllowList(
  options: NeverRedactOptions | undefined,
  keepPrivateIps = false,
): AllowList {
  const values = new Set((options?.values ?? []).filter((value) => value.length > 0));
  const pattern = compileAnchored(options?.patterns ?? []);
  const byRule = new Map<string, Set<string>>();

  for (const entry of options?.byRule ?? []) {
    const existing = byRule.get(entry.ruleId) ?? new Set<string>();

    for (const value of entry.values) {
      if (value.length > 0) {
        existing.add(value);
      }
    }

    byRule.set(entry.ruleId, existing);
  }

  return {
    empty: values.size === 0 && pattern === null && byRule.size === 0 && !keepPrivateIps,
    keepPrivateIps,
    values,
    pattern,
    byRule,
  };
}

export function isAllowed(allow: AllowList, ruleId: string, value: string): boolean {
  if (allow.keepPrivateIps && ruleId === 'ips' && isPrivateIpValue(value)) {
    return true;
  }

  if (allow.empty) {
    return false;
  }

  if (allow.values.has(value)) {
    return true;
  }

  if (allow.byRule.get(ruleId)?.has(value) === true) {
    return true;
  }

  return allow.pattern !== null && allow.pattern.test(value);
}
