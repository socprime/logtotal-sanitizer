import { describe, expect, it } from 'vitest';

import { sanitizeText } from '../src/index.js';

const KEY = '0123456789abcdef'.repeat(4);
const HOSTS_OPTIONS = { key: KEY, keyEncoding: 'hex' as const, rules: ['hosts'] as const };

describe('hostnames rule', () => {
  it('leaves ECS CSV column headers unchanged under default rules', () => {
    const header = [
      '@timestamp',
      'agent.name',
      'host.name',
      'host.os.name',
      'user.name',
      'user.effective.name',
      'process.name',
      'process.parent.name',
      'dll.name',
      'dns.question.name',
      'Endpoint.metrics.threads.name',
      'Endpoint.policy.applied.name',
      'Endpoint.policy.applied.actions.name',
      'process.Ext.api.name',
      'user.id',
      'user.effective.id',
      'host.id',
      'agent.id',
      'elastic.agent.id',
      'event.id',
      'Endpoint.policy.applied.id',
      'Endpoint.policy.applied.artifacts.global.channel',
      'host.name.keyword',
      'user.effective.domain',
      'source.ip',
      'message',
    ]
      .map((name) => `"${name}"`)
      .join(',');

    const { output, report } = sanitizeText(header, { key: KEY, keyEncoding: 'hex' });

    expect(output).toBe(header);
    expect(report.counts.hosts ?? 0).toBe(0);
  });

  it('leaves ECS-like dataset tokens unchanged', () => {
    const line = 'dataset endpoint.events.network and endpoint.events.process';

    const { output, report } = sanitizeText(line, HOSTS_OPTIONS);

    expect(output).toBe(line);
    expect(report.counts.hosts ?? 0).toBe(0);
  });

  it('redacts AD lab domains regardless of label case', () => {
    const cases = [
      { input: 'joined CONTOSO.LAB domain', expected: /^joined <HOST:[0-9a-f]{16}> domain$/ },
      { input: 'joined contoso.lab domain', expected: /^joined <HOST:[0-9a-f]{16}> domain$/ },
      {
        input: 'dc DC01.CONTOSO.LAB ready',
        expected: /^dc <HOST:[0-9a-f]{16}> ready$/,
      },
      {
        input: 'pc WKS-0042.contoso.lab online',
        expected: /^pc <HOST:[0-9a-f]{16}> online$/,
      },
    ];

    for (const { input, expected } of cases) {
      const { output, report } = sanitizeText(input, HOSTS_OPTIONS);
      expect(output).toMatch(expected);
      expect(report.counts.hosts).toBe(1);
    }
  });

  it('still redacts real hostnames with ECS-looking prefixes or corp TLDs', () => {
    const { output: agentOut } = sanitizeText('upstream agent.example.com ok', HOSTS_OPTIONS);
    expect(agentOut).toMatch(/^upstream <HOST:[0-9a-f]{16}> ok$/);

    const { output: corpOut } = sanitizeText('db srv01.corp online', HOSTS_OPTIONS);
    expect(corpOut).toMatch(/^db <HOST:[0-9a-f]{16}> online$/);
  });
});
