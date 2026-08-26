import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { createAllowList } from '../src/core/allowlist.js';
import { createRuleContext } from '../src/core/compile.js';
import { redactLine } from '../src/core/redactLine.js';
import { sanitizeText } from '../src/index.js';
import { defineRule } from '../src/rules/defineRule.js';
import { builtinRules, getBuiltinRule } from '../src/rules/registry.js';
import type { BuiltinRuleId, SanitizeRule } from '../src/types.js';

const KEY = '0123456789abcdef'.repeat(4);

function spans(
  line: string,
  ruleIds?: readonly BuiltinRuleId[],
): { ruleId: string; original: string; index: number }[] {
  const rules: SanitizeRule[] = ruleIds
    ? ruleIds.map((id) => getBuiltinRule(id)!)
    : [...builtinRules];

  const ctx = createRuleContext({
    rules,
    aggressive: false,
    pseudonymize: () => 'deadbeefdeadbeef',
    allow: createAllowList(undefined),
    contextChars: 0,
    json: false,
  });

  return redactLine(line, ctx, { withMatches: true }).matches.map((match) => ({
    ruleId: match.ruleId,
    original: match.original,
    index: match.index,
  }));
}

describe('lookbehind rewrite: value spans', () => {
  it('redacts only the username segment of a home path', () => {
    expect(spans('path=/home/alice/app.log', ['paths'])).toEqual([
      { ruleId: 'paths', original: 'alice', index: 'path=/home/'.length },
    ]);

    const { output } = sanitizeText('path=/home/alice/app.log', {
      key: KEY,
      keyEncoding: 'hex',
      rules: ['paths'],
    });
    expect(output).toMatch(/^path=\/home\/<R:[0-9a-f]{16}>\/app\.log$/);
  });

  it('keeps Bearer/Basic prefixes and the URL scheme', () => {
    expect(spans('Authorization: Bearer abcdefghijkl', ['secrets'])[0]).toMatchObject({
      ruleId: 'secrets',
      original: 'abcdefghijkl',
    });
    expect(spans('https://user:pass@example.test/x', ['secrets'])[0]).toMatchObject({
      ruleId: 'secrets',
      original: 'user:pass@',
    });
  });

  it('keeps syslog timestamps and host= keys', () => {
    const syslog =
      'Nov 15 09:19:41 srv-app-07 sshd[4070]: Failed password for invalid user ubuntu from 192.0.2.1 port 2222 ssh2';
    expect(spans(syslog, ['hosts'])).toEqual([
      { ruleId: 'hosts', original: 'srv-app-07', index: 'Nov 15 09:19:41 '.length },
    ]);

    expect(spans('host=app-node-1 ignored', ['hosts'])[0]).toMatchObject({
      ruleId: 'hosts',
      original: 'app-node-1',
    });
  });

  it('keeps DOMAIN\\ and uid= prefixes around usernames', () => {
    expect(spans('login CORP\\jdoe ok', ['users'])[0]).toMatchObject({
      ruleId: 'users',
      original: 'jdoe',
    });
    expect(spans('bind uid=alice,ou=People', ['users'])[0]).toMatchObject({
      ruleId: 'users',
      original: 'alice',
    });
  });

  it('keeps context keys for secrets, phones, geo and payment', () => {
    expect(
      spans('aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', ['secrets'])[0],
    ).toMatchObject({
      original: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    });
    expect(spans('phone=+1 202 555 0100 extra', ['phoneNumbers'])[0]).toMatchObject({
      original: '+1 202 555 0100',
    });
    expect(spans('latitude=50.4501', ['geoLocation'])[0]).toMatchObject({ original: '50.4501' });
    expect(spans('Set-Cookie: sid=s3ssionvalue9 extra', ['sessionCookies'])[0]).toMatchObject({
      original: 'sid=s3ssionvalue9',
    });
    expect(spans('mrn=AB-998877 extra', ['healthInfo'])[0]).toMatchObject({
      original: 'AB-998877',
    });
    expect(spans('ssn=123456789 extra', ['govIds'])[0]).toMatchObject({ original: '123456789' });
    expect(spans('sudo: alice : TTY=pts/0 ;', ['users'])[0]).toMatchObject({ original: 'alice' });
    expect(spans('tel:+14155552671 extra', ['phoneNumbers'])[0]).toMatchObject({
      original: '+14155552671',
    });
    expect(spans('\\\\FILESRV01\\share\\q', ['hosts'])[0]).toMatchObject({ original: 'FILESRV01' });
    expect(spans('zipCode=94105 extra', ['geoLocation'])[0]).toMatchObject({ original: '94105' });
  });

  it('lets a higher-priority rule win at an earlier value offset', () => {
    const line = 'https://user:secret@evil.it/login';
    const found = spans(line, ['secrets', 'hosts']);
    expect(found[0]).toMatchObject({ ruleId: 'secrets', original: 'user:secret@' });
    expect(found.some((match) => match.original === 'evil.it')).toBe(true);
  });

  it('accepts a custom rule whose capturing group marks the value', () => {
    const ticket = defineRule({
      id: 'ticket',
      label: 'Tickets',
      description: 'Synthetic ticket ids',
      mode: 'pseudo',
      token: 'TICKET',
      patterns: ['(?:CASE-(\\d{6}))'],
    });

    const { output } = sanitizeText('opened CASE-123456 today', {
      key: KEY,
      keyEncoding: 'hex',
      rules: [ticket],
    });
    expect(output).toMatch(/^opened CASE-<TICKET:[0-9a-f]{16}> today$/);
  });

  it('still excludes well-known Windows accounts after a domain prefix', () => {
    expect(spans('BUILTIN\\NT AUTHORITY\\', ['users'])).toEqual([]);
    expect(spans('BUILTIN\\Administrators', ['users'])).toEqual([]);
    expect(spans('C:\\Users\\alice', ['users'])).toEqual([]);
    expect(spans('CORP\\jdoe', ['users'])[0]).toMatchObject({ original: 'jdoe' });
  });

  it('reuses a prefix that an earlier match already covered', () => {
    // "C:" belongs to the first value and to the second match's prefix.
    expect(spans('/home/aC:\\Users\\INFO', ['paths']).map((match) => match.original)).toEqual([
      'aC:',
      'INFO',
    ]);

    // "--api-key" is the value of api_key= and the prefix of the CLI flag that follows.
    expect(
      spans('api_key=--api-key "s3cretvalue', ['secrets']).map((match) => match.original),
    ).toEqual(['--api-key', 's3cretvalue']);
  });

  it('keeps fragment order as the tie-break at one value offset', () => {
    // The SID fragment precedes the LDAP one, so it wins even though sAMAccountName= starts earlier.
    expect(spans('sAMAccountName=S-1-5-21-1-2-3acct:', ['users'])[0]).toMatchObject({
      original: 'S-1-5-21-1-2',
    });
  });

  it('does not let a shadowed match hide a shorter one inside its span', () => {
    // The JWT fragment matches the whole run, loses to Basic, and must fall back to the tail.
    expect(
      spans('Basic eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.sigInvalid', ['secrets']).map(
        (match) => match.original,
      ),
    ).toEqual(['eyJhbGciOiJub25lIn0', 'eyJzdWIiOiJhIn0.sigInvalid']);
  });

  it('applies a nearby-keyword lookbehind to every identifier that follows it', () => {
    // Built at runtime so GitHub secret scanning does not treat a fixture SID as a real secret.
    const sid = `AC${'0123456789abcdef'.repeat(2)}`;
    expect(spans(`Twilio ${sid}${sid}`, ['secrets']).map((match) => match.original)).toEqual([
      sid,
      sid,
    ]);
  });

  it('rejects a fragment with more than one capturing group', () => {
    expect(() =>
      defineRule({
        id: 'bad',
        label: 'Bad',
        description: 'Too many groups',
        mode: 'pseudo',
        token: 'BAD',
        patterns: ['((foo)(bar))'],
      }),
    ).toThrow(/at most one capturing group/);
  });
});

describe('lookbehind rewrite: aggressive patterns', () => {
  function output(line: string, rules: BuiltinRuleId[]): string {
    return sanitizeText(line, { key: KEY, keyEncoding: 'hex', rules, aggressive: true }).output;
  }

  it('keeps blanks between an address key and its value out of the prefix', () => {
    expect(output('street= 10 Main Street', ['geoLocation'])).toMatch(
      /^street=<GEO:[0-9a-f]{16}>$/,
    );
  });

  it('finds a cookie inside the span an address match gave up', () => {
    const line = 'street= token=mentsand token="token=ple.test';
    expect(output(line, ['geoLocation', 'sessionCookies'])).toMatch(
      /^street=<GEO:[0-9a-f]{16}>"<R:[0-9a-f]{16}>$/,
    );
  });
});

const CORPUS = fileURLToPath(new URL('../windows-powershell.txt', import.meta.url));

describe.skipIf(!existsSync(CORPUS))('span parity on a real log corpus', () => {
  it('redacts home-path user segments without consuming the prefix', () => {
    const text = readFileSync(CORPUS, 'utf8').slice(0, 8_000_000);
    const { output, report } = sanitizeText(text, {
      key: KEY,
      keyEncoding: 'hex',
      rules: ['paths'],
      json: false,
      report: { previewBytes: 0, replacements: true },
    });

    expect(output).not.toMatch(/\/home\/<R:[0-9a-f]{16}>[^/\s]/);

    for (const replacement of report.replacements) {
      expect(replacement.original).not.toMatch(/[/\\]/);
    }
  });

  it('keeps consumed prefixes out of value spans on sampled lines', () => {
    const lines = readFileSync(CORPUS, 'utf8').slice(0, 2_000_000).split(/\r?\n/).slice(0, 3000);

    for (const line of lines) {
      if (line.length === 0) {
        continue;
      }

      for (const match of spans(line)) {
        if (match.ruleId === 'paths') {
          expect(match.original).not.toMatch(/[/\\]/);
        }

        expect(match.original.startsWith('Bearer ')).toBe(false);
        expect(match.original.startsWith('host=')).toBe(false);
        expect(match.original.startsWith('username=')).toBe(false);
      }
    }
  });
});
