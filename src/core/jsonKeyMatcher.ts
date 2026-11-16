import type { SanitizeRule } from '../types';
import {
  ECS_EXPLICIT_NONE,
  normalizeKey,
  resolveEcsFieldHint,
  splitFieldPath,
} from './ecsFieldHints';

export { normalizeKey };

const RESOLVE_CACHE_LIMIT = 10_000;

/** Empty and `-` values are placeholders (Windows events use `-` for "not applicable"). */
export function shouldPreserveJsonValue(value: string): boolean {
  return value.length === 0 || value === '-';
}

export interface JsonKeyMatcher {
  /**
   * Finds the rule that owns a field by name. `parent` is the key of the enclosing object, so a
   * nested `{"user": {"name": …}}` resolves like a flat `user_name`. A dotted key such as
   * `source.ip` supplies its own parent.
   */
  resolve(key: string, parent?: string): SanitizeRule | undefined;
}

interface KeyTables {
  exact: Map<string, SanitizeRule>;
  contains: Array<{ fragment: string; rule: SanitizeRule }>;
  byId: Map<string, SanitizeRule>;
  activeIds: Set<string>;
}

function buildTables(rules: SanitizeRule[]): KeyTables {
  const exact = new Map<string, SanitizeRule>();
  const contains: Array<{ fragment: string; rule: SanitizeRule }> = [];
  const byId = new Map<string, SanitizeRule>();
  const activeIds = new Set<string>();

  for (const rule of rules) {
    byId.set(rule.id, rule);
    activeIds.add(rule.id);

    for (const key of rule.jsonKeys ?? []) {
      const normalized = normalizeKey(key);

      if (!exact.has(normalized)) {
        exact.set(normalized, rule);
      }
    }

    for (const fragment of rule.jsonKeyContains ?? []) {
      contains.push({ fragment: normalizeKey(fragment), rule });
    }
  }

  return { exact, contains, byId, activeIds };
}

function lastSegment(key: string): string {
  const dot = key.lastIndexOf('.');
  return dot === -1 ? key : key.slice(dot + 1);
}

function resolveUncached(
  tables: KeyTables,
  key: string,
  parent: string | undefined,
): SanitizeRule | null {
  const { dotted, leaf } = splitFieldPath(key, parent);
  const leafKey = normalizeKey(leaf);

  if (leafKey.length === 0) {
    return null;
  }

  const hint = resolveEcsFieldHint(key, parent, tables.activeIds);

  if (hint === ECS_EXPLICIT_NONE) {
    return null;
  }

  if (hint !== undefined) {
    return tables.byId.get(hint) ?? null;
  }

  const dot = dotted.lastIndexOf('.');
  const parentRaw = dot === -1 ? parent : dotted.slice(0, dot);

  // The scoped name goes first: `source.address` is an IP and `email.address` a mailbox, while a
  // bare `address` is a street address.
  if (parentRaw !== undefined) {
    const scoped = tables.exact.get(normalizeKey(lastSegment(parentRaw)) + leafKey);

    if (scoped) {
      return scoped;
    }
  }

  const exact = tables.exact.get(leafKey);

  if (exact) {
    return exact;
  }

  for (const entry of tables.contains) {
    if (leafKey.includes(entry.fragment)) {
      return entry.rule;
    }
  }

  return null;
}

function buildMatcher(rules: SanitizeRule[]): JsonKeyMatcher {
  const tables = buildTables(rules);
  // Field names repeat on every record, so resolution is memoized; the bound keeps inputs with
  // generated key names from growing it without limit.
  const cache = new Map<string, SanitizeRule | null>();

  return {
    resolve(key, parent) {
      const cacheKey = parent === undefined ? key : `${parent}\u0000${key}`;
      let rule = cache.get(cacheKey);

      if (rule === undefined) {
        rule = resolveUncached(tables, key, parent);

        if (cache.size >= RESOLVE_CACHE_LIMIT) {
          cache.clear();
        }

        cache.set(cacheKey, rule);
      }

      return rule ?? undefined;
    },
  };
}

const matcherCache = new WeakMap<SanitizeRule[], JsonKeyMatcher>();

export function jsonKeyMatcher(rules: SanitizeRule[]): JsonKeyMatcher {
  const cached = matcherCache.get(rules);

  if (cached) {
    return cached;
  }

  const matcher = buildMatcher(rules);
  matcherCache.set(rules, matcher);
  return matcher;
}
