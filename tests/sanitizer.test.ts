import { describe, expect, it } from 'vitest';

import {
  defineRule,
  fromString,
  generateKey,
  sanitizeStream,
  sanitizeText,
  toStringSink,
} from '../src/index.js';

const KEY = '0123456789abcdef'.repeat(4);

describe('sanitizeText', () => {
  it('redacts an IPv4 address with a stable IP token', () => {
    const { output, report } = sanitizeText('login from 10.0.0.1', {
      key: KEY,
      keyEncoding: 'hex',
      rules: ['ips'],
    });

    expect(output).toMatch(/^login from <IP:[0-9a-f]{16}>$/);
    expect(report.counts.ips).toBe(1);
    expect(report.totalMatches).toBe(1);
  });

  it('keeps the same token for the same value', () => {
    const { output } = sanitizeText('10.0.0.1 and 10.0.0.1', {
      key: KEY,
      keyEncoding: 'hex',
      rules: ['ips'],
    });
    const tokens = output.match(/<IP:[0-9a-f]{16}>/g);
    expect(tokens).toHaveLength(2);
    expect(tokens?.[0]).toBe(tokens?.[1]);
  });

  it('neverRedact values win over rules', () => {
    const { output, report } = sanitizeText('login from 10.0.0.1 and 10.0.0.2', {
      key: KEY,
      keyEncoding: 'hex',
      rules: ['ips'],
      neverRedact: { values: ['10.0.0.1'] },
    });

    expect(output).toMatch(/^login from 10\.0\.0\.1 and <IP:[0-9a-f]{16}>$/);
    expect(report.counts.ips).toBe(1);
  });

  it('neverRedact byRule only skips that rule', () => {
    const { output } = sanitizeText('10.0.0.1 host=app.internal.example', {
      key: KEY,
      keyEncoding: 'hex',
      rules: ['ips', 'hosts'],
      neverRedact: { byRule: [{ ruleId: 'ips', values: ['10.0.0.1'] }] },
    });

    expect(output).toContain('10.0.0.1');
    expect(output).toMatch(/<HOST:[0-9a-f]{16}>/);
  });

  it('alwaysRedact values are redacted even without a matching built-in rule', () => {
    const { output, report } = sanitizeText('seen acme-internal-host in the log', {
      key: KEY,
      keyEncoding: 'hex',
      rules: [],
      alwaysRedact: { values: ['acme-internal-host'] },
    });

    expect(output).toMatch(/^seen <CUSTOM:[0-9a-f]{16}> in the log$/);
    expect(report.counts.custom).toBe(1);
  });

  it('neverRedact wins over alwaysRedact', () => {
    const { output, report } = sanitizeText('keep acme-internal-host here', {
      key: KEY,
      keyEncoding: 'hex',
      rules: [],
      alwaysRedact: { values: ['acme-internal-host'] },
      neverRedact: { values: ['acme-internal-host'] },
    });

    expect(output).toBe('keep acme-internal-host here');
    expect(report.totalMatches).toBe(0);
  });

  it('redacts JSON fields by name', () => {
    const { report, output } = sanitizeText(
      JSON.stringify({ password: 'correct-horse', token: 'correct-horse' }),
      { key: KEY, keyEncoding: 'hex', rules: ['secrets'] },
    );

    const parsed = JSON.parse(output) as { password: string; token: string };
    expect(parsed.password).toMatch(/^<R:[0-9a-f]{16}>$/);
    expect(parsed.token).toBe(parsed.password);
    expect(report.counts.secrets).toBe(2);
  });

  it('redacts Windows Event Computer and owner-like JSON fields by name', () => {
    const line = JSON.stringify({
      Event: {
        System: { Computer: 'MSEDGEWIN10' },
        EventData: {
          User: 'MSEDGEWIN10\\IEUser',
          jobOwner: 'MSEDGEWIN10\\IEUser',
        },
      },
    });
    const { output, report } = sanitizeText(line, {
      key: KEY,
      keyEncoding: 'hex',
      rules: ['hosts', 'users'],
    });

    const parsed = JSON.parse(output) as {
      Event: {
        System: { Computer: string };
        EventData: { User: string; jobOwner: string };
      };
    };

    expect(parsed.Event.System.Computer).toMatch(/^<HOST:[0-9a-f]{16}>$/);
    expect(parsed.Event.EventData.User).toMatch(/^<USER:[0-9a-f]{16}>$/);
    expect(parsed.Event.EventData.jobOwner).toMatch(/^<USER:[0-9a-f]{16}>$/);
    expect(parsed.Event.EventData.User).toBe(parsed.Event.EventData.jobOwner);
    expect(report.counts.hosts).toBe(1);
    expect(report.counts.users).toBe(2);
  });

  it('redacts Windows Security Event subject fields by name', () => {
    const line = JSON.stringify({
      Event: {
        System: { Computer: 'IEWIN7' },
        EventData: {
          SubjectUserSid: 'S-1-5-21-3583694148-1414552638-2922671848-1000',
          SubjectUserName: 'IEUser',
          SubjectDomainName: 'IEWIN7',
          ObjectName:
            'C:\\Users\\IEUser\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\kushu3sd.default\\key4.db',
          ProcessName: 'C:\\Users\\Defau1t\\wsus.exe',
        },
      },
    });
    const { output, report } = sanitizeText(line, {
      key: KEY,
      keyEncoding: 'hex',
      rules: ['hosts', 'users', 'paths'],
    });

    const parsed = JSON.parse(output) as {
      Event: {
        System: { Computer: string };
        EventData: {
          SubjectUserSid: string;
          SubjectUserName: string;
          SubjectDomainName: string;
          ObjectName: string;
          ProcessName: string;
        };
      };
    };

    expect(parsed.Event.System.Computer).toMatch(/^<HOST:[0-9a-f]{16}>$/);
    expect(parsed.Event.EventData.SubjectUserSid).toMatch(/^<USER:[0-9a-f]{16}>$/);
    expect(parsed.Event.EventData.SubjectUserName).toMatch(/^<USER:[0-9a-f]{16}>$/);
    expect(parsed.Event.EventData.SubjectDomainName).toMatch(/^<HOST:[0-9a-f]{16}>$/);
    expect(parsed.Event.System.Computer).toBe(parsed.Event.EventData.SubjectDomainName);
    expect(parsed.Event.EventData.ObjectName).toContain('\\Users\\<R:');
    expect(parsed.Event.EventData.ProcessName).toContain('\\Users\\<R:');
    expect(output).not.toContain('IEWIN7');
    expect(output).not.toContain('IEUser');
    expect(output).not.toContain('Defau1t');
    expect(report.counts.hosts).toBeGreaterThanOrEqual(2);
    expect(report.counts.users).toBeGreaterThanOrEqual(2);
  });

  it('highlights jsonKeys values in the before preview even when regex would skip them', () => {
    const line = JSON.stringify({ UserName: 'NT AUTHORITY\\SYSTEM' });
    const { output, report } = sanitizeText(line, {
      key: KEY,
      keyEncoding: 'hex',
      rules: ['users'],
    });

    const parsed = JSON.parse(output) as { UserName: string };
    expect(parsed.UserName).toMatch(/^<USER:[0-9a-f]{16}>$/);

    const beforeChanged = report.preview.before
      .filter((segment) => segment.changed)
      .map((segment) => segment.text);
    const afterChanged = report.preview.after
      .filter((segment) => segment.changed)
      .map((segment) => segment.text);

    expect(beforeChanged).toEqual([JSON.stringify('NT AUTHORITY\\SYSTEM').slice(1, -1)]);
    expect(afterChanged).toEqual([parsed.UserName]);
    expect(report.preview.before.map((segment) => segment.text).join('')).toBe(line);
  });

  it('highlights regex matches inside JSON string fields in the before preview', () => {
    const line = JSON.stringify({ message: 'from alice@example.test' });
    const { output, report } = sanitizeText(line, {
      key: KEY,
      keyEncoding: 'hex',
      rules: ['users'],
    });

    const parsed = JSON.parse(output) as { message: string };
    expect(parsed.message).toMatch(/^from <USER:[0-9a-f]{16}>$/);

    const beforeChanged = report.preview.before
      .filter((segment) => segment.changed)
      .map((segment) => segment.text);
    const afterChanged = report.preview.after
      .filter((segment) => segment.changed)
      .map((segment) => segment.text);

    expect(beforeChanged).toEqual(['alice@example.test']);
    expect(afterChanged).toHaveLength(1);
    expect(parsed.message).toContain(afterChanged[0]);
    expect(report.preview.before.map((segment) => segment.text).join('')).toBe(line);
  });

  it('accepts a custom rule via defineRule', () => {
    const ticket = defineRule({
      id: 'ticket',
      label: 'Tickets',
      description: 'Synthetic ticket ids',
      mode: 'pseudo',
      token: 'TICKET',
      patterns: ['(?:CASE-\\d{6})'],
    });

    const { output, report } = sanitizeText('opened CASE-123456 today', {
      key: KEY,
      keyEncoding: 'hex',
      rules: [ticket],
    });

    expect(output).toMatch(/^opened <TICKET:[0-9a-f]{16}> today$/);
    expect(report.counts.ticket).toBe(1);
  });

  it('rejects an invalid custom rule id', () => {
    expect(() =>
      defineRule({
        id: 'not-valid',
        label: 'Bad',
        description: '',
        mode: 'pseudo',
        token: 'BAD',
        patterns: ['(?:x)'],
      }),
    ).toThrow(/identifier/);
  });

  it('omits replacement context unless report.contextChars is set', () => {
    const without = sanitizeText('10.0.0.1', { key: KEY, keyEncoding: 'hex', rules: ['ips'] });
    expect(without.report.replacements[0]?.contextBefore).toBeUndefined();

    const withCtx = sanitizeText('pre 10.0.0.1 post', {
      key: KEY,
      keyEncoding: 'hex',
      rules: ['ips'],
      report: { contextChars: 10 },
    });
    expect(withCtx.report.replacements[0]?.contextBefore).toBe('pre ');
  });

  it('caps distinct replacements per rule without dropping counts', () => {
    const lines = Array.from({ length: 5 }, (_, i) => `10.0.0.${i + 1}`).join('\n');
    const { report } = sanitizeText(lines, {
      key: KEY,
      keyEncoding: 'hex',
      rules: ['ips'],
      report: { maxReplacementsPerRule: 2 },
    });

    expect(report.counts.ips).toBe(5);
    expect(report.totalMatches).toBe(5);
    expect(report.replacements).toHaveLength(2);
    expect(report.replacementsTruncated).toBe(true);
    expect(report.replacements.map((row) => row.original)).toEqual(['10.0.0.1', '10.0.0.2']);
  });

  it('still increments count for a value already stored after the cap', () => {
    const { report } = sanitizeText('10.0.0.1\n10.0.0.2\n10.0.0.3\n10.0.0.1', {
      key: KEY,
      keyEncoding: 'hex',
      rules: ['ips'],
      report: { maxReplacementsPerRule: 2 },
    });

    expect(report.replacements).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ original: '10.0.0.1', count: 2 }),
        expect.objectContaining({ original: '10.0.0.2', count: 1 }),
      ]),
    );
    expect(report.replacements).toHaveLength(2);
    expect(report.counts.ips).toBe(4);
  });

  it('omits replacementsTruncated when every distinct value fits', () => {
    const { report } = sanitizeText('10.0.0.1', {
      key: KEY,
      keyEncoding: 'hex',
      rules: ['ips'],
      report: { maxReplacementsPerRule: 10 },
    });

    expect(report.replacementsTruncated).toBeUndefined();
  });
});

describe('sanitizeStream', () => {
  it('matches sanitizeText for the same input', async () => {
    const text = 'connect 10.0.0.1\nconnect 10.0.0.2\n';
    const options = { key: KEY, keyEncoding: 'hex' as const, rules: ['ips'] as const };
    const inMemory = sanitizeText(text, options);
    const sink = toStringSink();
    const report = await sanitizeStream(fromString(text), sink, options);

    expect(sink.text).toBe(inMemory.output);
    expect(report.totalMatches).toBe(inMemory.report.totalMatches);
  });
});

describe('generateKey', () => {
  it('returns 64 hex characters', () => {
    const key = generateKey();
    expect(key).toMatch(/^[0-9a-f]{64}$/);
  });
});
