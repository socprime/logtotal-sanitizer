import { isWellKnownPrincipal } from '../rules/shared/wellKnownPrincipals';
import { buildReplacement, type RuleContext } from './compile';

export interface KeyedReplacementParts {
  skip: boolean;
  pseudonymInput: string;
  suffix: string;
}

export function keyedReplacementParts(ruleId: string, value: string): KeyedReplacementParts {
  if ((ruleId === 'users' || ruleId === 'hosts') && isWellKnownPrincipal(value)) {
    return { skip: true, pseudonymInput: value, suffix: '' };
  }

  if (ruleId === 'users' && value.endsWith('$')) {
    return { skip: false, pseudonymInput: value.slice(0, -1), suffix: '$' };
  }

  return { skip: false, pseudonymInput: value, suffix: '' };
}

export function buildKeyedReplacement(
  ctx: RuleContext,
  ruleId: string,
  value: string,
): string | null {
  const parts = keyedReplacementParts(ruleId, value);

  if (parts.skip) {
    return null;
  }

  return buildReplacement(ctx, ruleId, parts.pseudonymInput) + parts.suffix;
}
