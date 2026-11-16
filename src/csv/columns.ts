import type { RuleContext } from '../core/compile';
import { jsonKeyMatcher } from '../core/jsonKeyMatcher';

export interface CsvColumnPlan {
  name: string;
  action: 'rule' | 'scan';
  ruleId: string | null;
}

export function buildColumnPlan(ctx: RuleContext, headers: readonly string[]): CsvColumnPlan[] {
  const matcher = jsonKeyMatcher(ctx.rules);

  return headers.map((name) => {
    const rule = matcher.resolve(name);

    if (rule) {
      return { name, action: 'rule', ruleId: rule.id };
    }

    return { name, action: 'scan', ruleId: null };
  });
}
