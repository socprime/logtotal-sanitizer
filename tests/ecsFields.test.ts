import { describe, expect, it } from 'vitest';

import { jsonKeyMatcher } from '../src/core/jsonKeyMatcher.js';
import { builtinRules } from '../src/rules/registry.js';
import { sanitizeText } from '../src/index.js';
import type { SanitizerOptions } from '../src/types.js';

const KEY = '0123456789abcdef'.repeat(4);
const OPTIONS: SanitizerOptions = { key: KEY, keyEncoding: 'hex' };
const TOKEN = (prefix: string): RegExp => new RegExp(`^<${prefix}:[0-9a-f]{16}>$`);
const TOKEN_USER = TOKEN('USER');
const TOKEN_HOST = TOKEN('HOST');

const matcher = jsonKeyMatcher([...builtinRules]);

function ruleId(column: string): string | null {
  return matcher.resolve(column)?.id ?? null;
}

describe('ECS column name classification', () => {
  it.each([
    ['source.ip', 'ips'],
    ['source.address', 'ips'],
    ['destination.ip', 'ips'],
    ['destination.address', 'ips'],
    ['host.ip', 'ips'],
    ['host.mac', 'ips'],
    ['log.source.address', 'ips'],
    ['process.Ext.session_info.client_address', 'ips'],
    ['host.name', 'hosts'],
    ['host.hostname', 'hosts'],
    ['host.domain', 'hosts'],
    ['user.domain', 'hosts'],
    ['user.effective.domain', 'hosts'],
    ['winlog.event_data.WorkstationName', 'hosts'],
    ['user.name', 'users'],
    ['user.id', 'users'],
    ['user.effective.name', 'users'],
    ['user.effective.id', 'users'],
    ['user.effective.name.keyword', 'users'],
    ['dns.question.name', 'hosts'],
    ['dns.resolved_ip', 'ips'],
    ['agent.name', 'hosts'],
    ['related.ip', 'ips'],
    ['winlog.event_data.TargetUserName', 'users'],
    ['host.os.name', null],
    ['process.name', null],
    ['dll.name', null],
    ['event.id', null],
    ['process.Ext.session_info.relative_password_age', null],
    ['agent.version', null],
  ] as const)('classifies %s as %s', (column, expected) => {
    expect(ruleId(column)).toBe(expected);
  });
});

describe('ECS-oriented JSON redaction', () => {
  it('preserves the machine-account suffix on user fields', () => {
    const { output } = sanitizeText(
      JSON.stringify({ 'user.effective.name': 'WKS-0042$' }),
      OPTIONS,
    );
    const parsed = JSON.parse(output) as Record<string, string>;

    expect(parsed['user.effective.name']).toMatch(/^<USER:[0-9a-f]{16}>\$$/);
  });

  it('leaves well-known Windows principals unchanged under user fields', () => {
    const line = JSON.stringify({ user: { name: 'SYSTEM' } });
    expect(sanitizeText(line, OPTIONS).output).toBe(line);
  });

  it('redacts ECS user hostnames', () => {
    const parsed = JSON.parse(
      sanitizeText(JSON.stringify({ 'user.effective.domain': 'CONTOSO.LAB' }), OPTIONS).output,
    ) as Record<string, string>;

    expect(parsed['user.effective.domain']).toMatch(TOKEN_HOST);
  });

  it('redacts nested ECS user paths', () => {
    const parsed = JSON.parse(
      sanitizeText(JSON.stringify({ user: { effective: { name: 'jdoe' } } }), OPTIONS).output,
    ) as Record<string, Record<string, Record<string, string>>>;

    expect(parsed.user!.effective!.name).toMatch(TOKEN_USER);
  });

  it('uses the same token for machine accounts with or without a trailing dollar sign', () => {
    const withDollar = sanitizeText(JSON.stringify({ 'user.name': 'WKS-0042$' }), OPTIONS).output;
    const withoutDollar = sanitizeText(JSON.stringify({ 'user.name': 'WKS-0042' }), OPTIONS).output;

    const tokenWith = withDollar.match(/<USER:([0-9a-f]{16})>\$/)![1];
    const tokenWithout = withoutDollar.match(/<USER:([0-9a-f]{16})>/)![1];

    expect(tokenWith).toBe(tokenWithout);
  });
});
