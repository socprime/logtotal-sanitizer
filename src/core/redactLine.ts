import type { SanitizeSegment } from '../types';
import { isAllowed } from './allowlist';
import { buildReplacement, type CompiledRule, type RuleContext } from './compile';
import { lineHasAnyChar } from './regexSource';

export interface RedactMatch {
  ruleId: string;
  original: string;
  replacement: string;
  index: number;
  contextBefore?: string;
  contextAfter?: string;
}

export interface RedactResult {
  output: string;
  counts: Record<string, number>;
  matches: RedactMatch[];
  segments?: {
    before: SanitizeSegment[];
    after: SanitizeSegment[];
  };
}

export interface RedactOptions {
  withSegments?: boolean;
  withMatches?: boolean;
}

export function sliceContext(
  text: string,
  index: number,
  length: number,
  chars: number,
): { contextBefore: string; contextAfter: string } {
  return {
    contextBefore: text.slice(Math.max(0, index - chars), index),
    contextAfter: text.slice(index + length, index + length + chars),
  };
}

/**
 * One live match per pattern fragment. Fragments are scanned separately rather than as a single
 * alternation, so that a fragment whose consumed prefix begins earlier cannot pre-empt a
 * higher-priority fragment that matches the same value offset.
 */
interface FragmentCursor {
  ruleIndex: number;
  fragmentIndex: number;
  ruleId: string;
  regex: RegExp;
  hasValueGroup: boolean;
  active: boolean;
  start: number;
  original: string;
}

/** Moves a cursor to its next match whose value starts at or after `minStart`. */
function advance(cursor: FragmentCursor, line: string, minStart: number): void {
  const { regex } = cursor;

  for (;;) {
    // Never scan past the floor: a fragment that overshot it would hide a shorter match starting
    // inside the text its own previous match covered.
    if (regex.lastIndex > minStart) {
      regex.lastIndex = minStart;
    }

    const match = regex.exec(line);

    if (match === null) {
      cursor.active = false;
      return;
    }

    const original = (cursor.hasValueGroup ? match[1] : undefined) ?? match[0];
    const start = match.index + match[0].length - original.length;

    if (match[0].length === 0) {
      regex.lastIndex += 1;
    } else if (start > match.index) {
      // Resume at the value rather than past it: a consumed prefix has to stay available to the
      // next occurrence, the way a lookbehind can re-read text the scan already passed.
      regex.lastIndex = start;
    }

    if (start >= minStart) {
      cursor.active = true;
      cursor.start = start;
      cursor.original = original;
      return;
    }
  }
}

function openCursors(line: string, compiled: CompiledRule[]): FragmentCursor[] {
  const cursors: FragmentCursor[] = [];

  for (let ruleIndex = 0; ruleIndex < compiled.length; ruleIndex += 1) {
    const rule = compiled[ruleIndex]!;

    if (rule.gateChars !== null && !lineHasAnyChar(line, rule.gateChars)) {
      continue;
    }

    if (rule.gate !== null) {
      rule.gate.lastIndex = 0;

      if (!rule.gate.test(line)) {
        continue;
      }
    }

    for (let fragmentIndex = 0; fragmentIndex < rule.fragments.length; fragmentIndex += 1) {
      const fragment = rule.fragments[fragmentIndex]!;
      fragment.regex.lastIndex = 0;

      const cursor: FragmentCursor = {
        ruleIndex,
        fragmentIndex,
        ruleId: rule.id,
        regex: fragment.regex,
        hasValueGroup: fragment.hasValueGroup,
        active: false,
        start: 0,
        original: '',
      };

      advance(cursor, line, 0);

      if (cursor.active) {
        cursors.push(cursor);
      }
    }
  }

  return cursors;
}

/** Leftmost value wins; ties go to the earlier rule, then the earlier pattern fragment. */
function pickNext(cursors: FragmentCursor[]): FragmentCursor | null {
  let best: FragmentCursor | null = null;

  for (const cursor of cursors) {
    if (!cursor.active) {
      continue;
    }

    if (
      best === null ||
      cursor.start < best.start ||
      (cursor.start === best.start &&
        (cursor.ruleIndex < best.ruleIndex ||
          (cursor.ruleIndex === best.ruleIndex && cursor.fragmentIndex < best.fragmentIndex)))
    ) {
      best = cursor;
    }
  }

  return best;
}

export function redactLine(
  line: string,
  ctx: RuleContext,
  options: RedactOptions = {},
): RedactResult {
  const { compiled, rulesById, allow, contextChars } = ctx;
  const withSegments = options.withSegments ?? false;
  const withMatches = options.withMatches ?? false;

  if (compiled.length === 0) {
    return {
      output: line,
      counts: {},
      matches: [],
      segments: withSegments
        ? { before: [{ text: line, changed: false }], after: [{ text: line, changed: false }] }
        : undefined,
    };
  }

  const cursors = openCursors(line, compiled);
  const counts: Record<string, number> = {};
  const matches: RedactMatch[] = [];
  const before: SanitizeSegment[] = [];
  const after: SanitizeSegment[] = [];
  let output = '';
  let cursor = 0;

  for (;;) {
    const next = pickNext(cursors);

    if (next === null) {
      break;
    }

    const { start, original, ruleId } = next;
    // A rejected candidate still occupies its span, so a lower-priority match inside it is not
    // retried. Empty values advance by one so the walk always makes progress.
    const spanEnd = start + Math.max(original.length, 1);
    const rule = rulesById.get(ruleId);
    const accepted =
      rule !== undefined &&
      !(rule.validate !== undefined && !rule.validate(original)) &&
      !isAllowed(allow, rule.id, original);

    if (accepted) {
      const replacement = buildReplacement(ctx, rule.id, original);

      if (withSegments) {
        if (start > cursor) {
          const gap = line.slice(cursor, start);
          before.push({ text: gap, changed: false });
          after.push({ text: gap, changed: false });
        }

        before.push({ text: original, changed: true });
        after.push({ text: replacement, changed: true });
      }

      output += line.slice(cursor, start) + replacement;
      cursor = start + original.length;
      counts[rule.id] = (counts[rule.id] ?? 0) + 1;

      if (withMatches) {
        matches.push({
          ruleId: rule.id,
          original,
          replacement,
          index: start,
          ...(contextChars > 0 ? sliceContext(line, start, original.length, contextChars) : {}),
        });
      }
    }

    for (const candidate of cursors) {
      if (candidate.active && candidate.start < spanEnd) {
        advance(candidate, line, spanEnd);
      }
    }
  }

  output += line.slice(cursor);

  if (withSegments && cursor < line.length) {
    const tail = line.slice(cursor);
    before.push({ text: tail, changed: false });
    after.push({ text: tail, changed: false });
  }

  return {
    output,
    counts,
    matches,
    segments: withSegments ? { before, after } : undefined,
  };
}
