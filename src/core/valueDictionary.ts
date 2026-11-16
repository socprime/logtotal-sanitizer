import { isWellKnownPrincipal } from '../rules/shared/wellKnownPrincipals';
import type { SanitizeSegment } from '../types';
import type { RedactMatch, RedactOptions, RedactResult } from './redactLine';
import { sliceContext } from './redactLine';

const MAX_ENTRIES = 10_000;
const WORD_CHAR = /[A-Za-z0-9_$-]/;
const LEADING_RUN = /^[A-Za-z0-9_$-]+/;

interface DictEntry {
  key: string;
  replacement: string;
  ruleId: string;
}

export interface ValueDictionary {
  remember(ruleId: string, original: string, replacement: string): void;
  apply(text: string, contextChars: number, options: RedactOptions): RedactResult;
}

function isWordChar(char: string | undefined): boolean {
  return char !== undefined && WORD_CHAR.test(char);
}

export function createValueDictionary(): ValueDictionary {
  const entries = new Map<string, DictEntry>();
  // Matches can only start where a maximal word run starts, and that run must equal the key's
  // leading run, so candidates are indexed by it (longest key first).
  const byLeadingRun = new Map<string, DictEntry[]>();

  function add(key: string, replacement: string, ruleId: string): void {
    if (entries.has(key) || entries.size >= MAX_ENTRIES) {
      return;
    }

    const leading = LEADING_RUN.exec(key)?.[0];

    if (leading === undefined || !isWordChar(key.at(-1))) {
      return;
    }

    const entry: DictEntry = { key, replacement, ruleId };
    entries.set(key, entry);

    const bucket = byLeadingRun.get(leading);

    if (bucket === undefined) {
      byLeadingRun.set(leading, [entry]);
    } else {
      bucket.push(entry);
      bucket.sort((a, b) => b.key.length - a.key.length);
    }
  }

  function remember(ruleId: string, original: string, replacement: string): void {
    if (ruleId !== 'users' && ruleId !== 'hosts') {
      return;
    }

    if (original.length < 3 || isWellKnownPrincipal(original)) {
      return;
    }

    add(original, replacement, ruleId);

    if (ruleId === 'users' && original.endsWith('$') && replacement.endsWith('$')) {
      const bare = original.slice(0, -1);

      if (bare.length >= 3) {
        add(bare, replacement.slice(0, -1), ruleId);
      }
    }
  }

  function apply(text: string, contextChars: number, options: RedactOptions): RedactResult {
    if (entries.size === 0 || text.length === 0) {
      return { output: text, counts: {}, matches: [] };
    }

    const withSegments = options.withSegments === true;
    const withMatches = options.withMatches === true;
    const counts: Record<string, number> = {};
    const matches: RedactMatch[] = [];
    const before: SanitizeSegment[] = [];
    const after: SanitizeSegment[] = [];
    const runs = /[A-Za-z0-9_$-]+/g;
    let output = '';
    let lastIndex = 0;
    let run: RegExpExecArray | null;

    while ((run = runs.exec(text)) !== null) {
      const bucket = byLeadingRun.get(run[0]);

      if (bucket === undefined) {
        continue;
      }

      const index = run.index;
      const entry = bucket.find(
        (candidate) =>
          text.startsWith(candidate.key, index) && !isWordChar(text[index + candidate.key.length]),
      );

      if (entry === undefined) {
        continue;
      }

      if (index > lastIndex) {
        const gap = text.slice(lastIndex, index);
        output += gap;

        if (withSegments) {
          before.push({ text: gap, changed: false });
          after.push({ text: gap, changed: false });
        }
      }

      output += entry.replacement;
      lastIndex = index + entry.key.length;
      runs.lastIndex = lastIndex;
      counts[entry.ruleId] = (counts[entry.ruleId] ?? 0) + 1;

      if (withSegments) {
        before.push({ text: entry.key, changed: true });
        after.push({ text: entry.replacement, changed: true });
      }

      if (withMatches) {
        matches.push({
          ruleId: entry.ruleId,
          original: entry.key,
          replacement: entry.replacement,
          index,
          ...(contextChars > 0 ? sliceContext(text, index, entry.key.length, contextChars) : {}),
        });
      }
    }

    if (lastIndex === 0) {
      return { output: text, counts: {}, matches: [] };
    }

    if (lastIndex < text.length) {
      const tail = text.slice(lastIndex);
      output += tail;

      if (withSegments) {
        before.push({ text: tail, changed: false });
        after.push({ text: tail, changed: false });
      }
    }

    return {
      output,
      counts,
      matches,
      ...(withSegments ? { segments: { before, after } } : {}),
    };
  }

  return { remember, apply };
}
