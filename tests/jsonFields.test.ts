import { describe, expect, it } from 'vitest';

import { sanitizeText } from '../src/index.js';
import type { SanitizerOptions } from '../src/types.js';

const KEY = '0123456789abcdef'.repeat(4);
const OPTIONS: SanitizerOptions = { key: KEY, keyEncoding: 'hex' };
const TOKEN = (prefix: string): RegExp => new RegExp(`^<${prefix}:[0-9a-f]{16}>$`);

const AUTH_EVENT = {
  timestamp: '2026-10-14T08:15:32Z',
  level: 'ERROR',
  service: 'auth-api',
  environment: 'staging',
  message:
    'Login failed for user maria.novak@example.test from 203.0.113.42. Host auth-staging.example.test. Session cookie: sessionid=FAKE_SESSION_COOKIE_7f3a91; access_token=FAKE_ACCESS_TOKEN_abc123; password=FakePass!234. Contact: +421 900 123 456.',
  user: {
    username: 'maria.novak',
    email: 'maria.novak@example.test',
    home_directory: '/home/maria.novak',
    windows_home: 'C:\\Users\\mnovak',
  },
  network: {
    source_ip: '203.0.113.42',
    destination_ip: '198.51.100.27',
    hostname: 'auth-staging.example.test',
    domain: 'example.test',
  },
  auth: {
    session_cookie: 'FAKE_SESSION_COOKIE_7f3a91',
    access_token: 'FAKE_ACCESS_TOKEN_abc123',
    api_key: 'FAKE_API_KEY_xyz789',
    username: 'maria.novak',
    password: 'FakePass!234',
  },
  identity: {
    passport_number: 'TEST-PASSPORT-123456',
    tax_id: 'TEST-TAX-987654321',
    ssn: '000-12-3456',
  },
  location: {
    latitude: 48.1486,
    longitude: 17.1077,
    address: '123 Example Street, Bratislava, 811 01, Slovakia',
  },
  payment: { iban: 'SK00 0000 0000 0000 0000 0000', pan: '4111111111111111', cvv: '123' },
  health: {
    diagnosis: 'TEST_DIAGNOSIS: hypertension',
    prescription: 'TEST_MEDICATION 10 mg once daily',
  },
  metadata: { request_id: 'req-test-20261014-001', http_status: 401, retry_count: 2 },
};

const SENSITIVE = [
  'maria',
  'mnovak',
  '203.0.113.42',
  '198.51.100.27',
  'example.test',
  'FAKE_',
  'FakePass',
  'TEST-PASSPORT',
  'TEST-TAX',
  '000-12-3456',
  '48.1486',
  '17.1077',
  'Example Street',
  'SK00',
  '4111111111111111',
  '"123"',
  'hypertension',
  'TEST_MEDICATION',
  '900 123 456',
];

describe('JSON field redaction', () => {
  it.each([
    ['compact', JSON.stringify(AUTH_EVENT)],
    ['pretty-printed', JSON.stringify(AUTH_EVENT, null, 2)],
  ])('leaves no sensitive value in a %s record', (_form, text) => {
    const { output } = sanitizeText(text, OPTIONS);

    for (const value of SENSITIVE) {
      expect(output).not.toContain(value);
    }

    const parsed = JSON.parse(output) as typeof AUTH_EVENT;
    expect(parsed.metadata).toEqual(AUTH_EVENT.metadata);
    expect(parsed.service).toBe('auth-api');
  });

  it('gives a pretty-printed record the same tokens as its compact form', () => {
    const pretty = sanitizeText(JSON.stringify(AUTH_EVENT, null, 2), OPTIONS).output;
    const compact = sanitizeText(JSON.stringify(AUTH_EVENT), OPTIONS).output;

    expect(JSON.parse(pretty)).toEqual(JSON.parse(compact));
  });

  it('replaces numeric values of sensitive keys with a string token', () => {
    const line = JSON.stringify({ latitude: 48.1486, pan: 4111111111111111, retry_count: 2 });
    const { output, report } = sanitizeText(line, OPTIONS);
    const parsed = JSON.parse(output) as Record<string, unknown>;

    expect(parsed.latitude).toMatch(TOKEN('GEO'));
    expect(parsed.pan).toMatch(TOKEN('R'));
    expect(parsed.retry_count).toBe(2);
    expect(report.counts.geoLocation).toBe(1);
    expect(report.counts.paymentInfo).toBe(1);
  });

  it('quotes the token that replaces a bare number in a pretty-printed line', () => {
    const { output } = sanitizeText('  "latitude": 48.1486,\n  "count": 3\n', OPTIONS);

    expect(output).toMatch(/^ {2}"latitude": "<GEO:[0-9a-f]{16}>",\n {2}"count": 3\n$/);
  });

  it('lets array items inherit the key of their array', () => {
    const line = JSON.stringify({
      emails: ['a.one@corp.example', 'b.two@corp.example'],
      coordinates: [17.1077, 48.1486],
      tags: ['blue', 'green'],
    });
    const parsed = JSON.parse(sanitizeText(line, OPTIONS).output) as Record<string, string[]>;

    expect(parsed.emails).toEqual([
      expect.stringMatching(TOKEN('USER')),
      expect.stringMatching(TOKEN('USER')),
    ]);
    expect(parsed.coordinates).toEqual([
      expect.stringMatching(TOKEN('GEO')),
      expect.stringMatching(TOKEN('GEO')),
    ]);
    expect(parsed.tags).toEqual(['blue', 'green']);
  });

  it('resolves a nested field by its parent and leaf names', () => {
    const line = JSON.stringify({
      user: { name: 'maria' },
      client: { ip: '203.0.113.7' },
      session: { id: 'opaque-session' },
      source: { address: '198.51.100.4' },
      email: { address: 'maria' },
      service: { name: 'auth-api' },
    });
    const parsed = JSON.parse(sanitizeText(line, OPTIONS).output) as Record<
      string,
      Record<string, string>
    >;

    expect(parsed.user!.name).toMatch(TOKEN('USER'));
    expect(parsed.client!.ip).toMatch(TOKEN('IP'));
    expect(parsed.session!.id).toMatch(TOKEN('R'));
    expect(parsed.source!.address).toMatch(TOKEN('IP'));
    expect(parsed.email!.address).toMatch(TOKEN('USER'));
    expect(parsed.service!.name).toBe('auth-api');
  });

  it('resolves dotted flat keys the way nested objects resolve', () => {
    const line = JSON.stringify({
      'user.name': 'maria',
      'source.ip': '203.0.113.9',
      'usr.email': 'maria',
      'service.name': 'auth-api',
    });
    const parsed = JSON.parse(sanitizeText(line, OPTIONS).output) as Record<string, string>;

    expect(parsed['user.name']).toMatch(TOKEN('USER'));
    expect(parsed['source.ip']).toMatch(TOKEN('IP'));
    expect(parsed['usr.email']).toMatch(TOKEN('USER'));
    expect(parsed['service.name']).toBe('auth-api');
  });

  it('redacts escaped JSON embedded in a text line', () => {
    const line = 'INFO request body="{\\"password\\":\\"hunter2pass\\",\\"user\\":\\"maria\\"}"';
    const { output, report } = sanitizeText(line, OPTIONS);

    expect(output).not.toContain('hunter2pass');
    expect(output).not.toContain('maria');
    expect(output).toMatch(/\\"password\\":\\"<R:[0-9a-f]{16}>\\"/);
    expect(report.counts.secrets).toBe(1);
    expect(report.counts.users).toBe(1);
  });

  it('redacts JSON serialized inside a JSON string field', () => {
    const line = JSON.stringify({
      log: '{"password":"hunter2pass","lat":48.1486}\n',
      stream: 'stdout',
    });
    const parsed = JSON.parse(sanitizeText(line, OPTIONS).output) as { log: string };

    expect(parsed.log).not.toContain('hunter2pass');
    expect(parsed.log).not.toContain('48.1486');
    expect(JSON.parse(parsed.log)).toEqual({
      password: expect.stringMatching(TOKEN('R')),
      lat: expect.stringMatching(TOKEN('GEO')),
    });
  });

  it('redacts a Python dict repr', () => {
    const line =
      "payload={'password': 'hunter2pass', 'ssn': '000-12-3456', 'lat': 48.1486, 'note': \"it's\"}";
    const { output } = sanitizeText(line, OPTIONS);

    expect(output).not.toContain('hunter2pass');
    expect(output).not.toContain('000-12-3456');
    expect(output).toMatch(/'lat': '<GEO:[0-9a-f]{16}>'/);
    expect(output).toContain(`'note': "it's"`);
  });

  it('keeps placeholders, booleans and nulls under sensitive keys', () => {
    const text = [
      '{',
      '  "password": "",',
      '  "user": "-",',
      '  "phone_verified": true,',
      '  "session": null',
      '}',
    ].join('\n');
    const { output, report } = sanitizeText(text, OPTIONS);

    expect(output).toBe(text);
    expect(report.totalMatches).toBe(0);
  });

  it('leaves look-alike field names alone', () => {
    const record = {
      max_tokens: 1024,
      token_count: 17,
      className: 'Foo',
      zip_file: 'bundle',
      appDisplayName: 'Microsoft Teams',
      storageAccountName: 'acct1',
      sessionDuration: 30,
    };

    for (const text of [JSON.stringify(record), JSON.stringify(record, null, 2)]) {
      const { output, report } = sanitizeText(text, OPTIONS);
      expect(JSON.parse(output)).toEqual(record);
      expect(report.totalMatches).toBe(0);
    }
  });

  it('honours neverRedact for values found by key in a text line', () => {
    const { output } = sanitizeText('  "username": "maria",\n  "email": "maria@corp.example"\n', {
      ...OPTIONS,
      neverRedact: { values: ['maria'] },
    });

    expect(output).toContain('"username": "maria"');
    expect(output).not.toContain('maria@corp.example');
  });

  it('reports the decoded value and keeps preview segments aligned', () => {
    const text = '  "User": "CORP\\\\jdoe",\n  "latitude": 48.1486\n';
    const { output, report } = sanitizeText(text, OPTIONS);
    const compact = sanitizeText(JSON.stringify({ User: 'CORP\\jdoe' }), OPTIONS).output;

    expect(report.replacements.map((row) => row.original).sort()).toEqual([
      '48.1486',
      'CORP\\jdoe',
    ]);
    expect(output).toContain(`"User": "${(JSON.parse(compact) as { User: string }).User}"`);
    expect(report.preview.before.map((segment) => segment.text).join('')).toBe(text);
    expect(report.preview.after.map((segment) => segment.text).join('')).toBe(output);
    expect(
      report.preview.before.filter((segment) => segment.changed).map((segment) => segment.text),
    ).toEqual(['CORP\\\\jdoe', '48.1486']);
  });

  it('leaves key-value pairs to the regex pass when JSON handling is off', () => {
    const { output } = sanitizeText('  "username": "maria",', { ...OPTIONS, json: false });

    expect(output).toBe('  "username": "maria",');
  });

  it('still redacts the mixed AUTH_EVENT regression payload', () => {
    const { output, report } = sanitizeText(JSON.stringify(AUTH_EVENT), OPTIONS);

    for (const value of SENSITIVE) {
      expect(output).not.toContain(value);
    }

    expect(report.totalMatches).toBeGreaterThan(0);
    const parsed = JSON.parse(output) as typeof AUTH_EVENT;
    expect(parsed.metadata).toEqual(AUTH_EVENT.metadata);
    expect(parsed.service).toBe('auth-api');
  });

  it('redacts hosts under the reserved .test, .invalid and .localhost TLDs', () => {
    const { output } = sanitizeText(
      'Host auth-staging.example.test, api.corp.invalid and app.localhost',
      { ...OPTIONS, rules: ['hosts'] },
    );

    expect(output).toMatch(
      /^Host <HOST:[0-9a-f]{16}>, <HOST:[0-9a-f]{16}> and <HOST:[0-9a-f]{16}>$/,
    );
  });
});
