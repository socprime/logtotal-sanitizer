import { describe, expect, it } from 'vitest';
import { sanitizeText } from '../src/index.js';

const KEY = '0123456789abcdef'.repeat(4);
const options = { key: KEY, keyEncoding: 'hex' as const };

describe('built-in rules (smoke)', () => {
  it('redacts a JWT-shaped secret', () => {
    const jwt = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSJ9.signature-placeholder';
    const { output, report } = sanitizeText(`Authorization: Bearer ${jwt}`, {
      ...options,
      rules: ['secrets'],
    });
    expect(output).toMatch(/<R:[0-9a-f]{16}>/);
    expect(report.counts.secrets).toBeGreaterThan(0);
  });

  it('redacts IPv4 and leaves RFC 5737 documentation-style text around it', () => {
    const { output } = sanitizeText('src=10.0.0.1 dst=10.0.0.2', { ...options, rules: ['ips'] });
    expect(output).toMatch(/^src=<IP:[0-9a-f]{16}> dst=<IP:[0-9a-f]{16}>$/);
  });

  it('redacts an email', () => {
    const { output } = sanitizeText('from=alice@example.test', { ...options, rules: ['users'] });
    expect(output).toMatch(/<USER:[0-9a-f]{16}>/);
  });

  it('redacts a hostname', () => {
    const { output } = sanitizeText('host=app.internal.example', { ...options, rules: ['hosts'] });
    expect(output).toMatch(/<HOST:[0-9a-f]{16}>/);
  });

  it('redacts a short hostname in a BSD syslog line', () => {
    const line =
      'Nov 15 09:19:41 srv-app-07 sshd[4070]: Failed password for invalid user ubuntu from 192.0.2.1 port 2222 ssh2';
    const { output } = sanitizeText(line, { ...options, rules: ['hosts'] });
    expect(output).toMatch(
      /^Nov 15 09:19:41 <HOST:[0-9a-f]{16}> sshd\[4070\]: Failed password for invalid user ubuntu from 192\.0\.2\.1 port 2222 ssh2$/,
    );
  });

  it('redacts a short hostname after an ISO-8601 syslog timestamp', () => {
    const line = '2024-11-15T09:19:41.123Z srv-app-07 sshd[4970]: session opened';
    const { output } = sanitizeText(line, { ...options, rules: ['hosts'] });
    expect(output).toMatch(
      /^2024-11-15T09:19:41\.123Z <HOST:[0-9a-f]{16}> sshd\[4970\]: session opened$/,
    );
  });

  it('does not treat a syslog tag as a hostname when the host field is omitted', () => {
    const line = 'Nov 15 09:19:41 kernel: CPU0: temperature above threshold';
    const { output, report } = sanitizeText(line, { ...options, rules: ['hosts'] });
    expect(output).toBe(line);
    expect(report.counts.hosts ?? 0).toBe(0);
  });

  it('redacts inventory-style hostnames in unstructured text only when aggressive', () => {
    const line = 'probe srv-app-07 before failover';
    const { output: defaultOutput, report: defaultReport } = sanitizeText(line, {
      ...options,
      rules: ['hosts'],
    });
    expect(defaultOutput).toBe(line);
    expect(defaultReport.counts.hosts ?? 0).toBe(0);

    const { output } = sanitizeText(line, { ...options, rules: ['hosts'], aggressive: true });
    expect(output).toMatch(/^probe <HOST:[0-9a-f]{16}> before failover$/);
  });

  it('redacts a home-directory user segment', () => {
    const { output } = sanitizeText('path=/home/alice/app.log', { ...options, rules: ['paths'] });
    expect(output).toMatch(/\/home\/<R:[0-9a-f]{16}>\//);
  });

  it('does not redact loopback when validate rejects it', () => {
    const { output, report } = sanitizeText('health 127.0.0.1 ok', { ...options, rules: ['ips'] });
    expect(output).toContain('127.0.0.1');
    expect(report.counts.ips ?? 0).toBe(0);
  });

  it('does not redact a semver string as a secret', () => {
    const { output } = sanitizeText('version=1.2.3', { ...options, rules: ['secrets'] });
    expect(output).toBe('version=1.2.3');
  });

  it('does not read a GUID group or a hex digest as an international number', () => {
    const notPhones = [
      '"SHA256=0043369966E39C40B96C',
      'dbf410b3-0018-6809-0705-000000004',
      'dbf410b3-0086-6806-1509-000000003',
      'CorrelationId=00112233-4455-6677-8899-aabbccddeeff',
      '0018-6809-0705-000000004',
      'thumbprint 0012345678abcdef',
      'md5=00123456789012345678901234567890',
    ];

    for (const line of notPhones) {
      const { output, report } = sanitizeText(line, { ...options, rules: ['phoneNumbers'] });
      expect(output).toBe(line);
      expect(report.counts.phoneNumbers ?? 0).toBe(0);
    }
  });

  it('still redacts international numbers written with 00', () => {
    const phones = [
      'call 0044 20 7123 4567 now',
      'tel 00380671234567 ok',
      'phone: 0049-30-12345678',
      'contact 0044 (20) 7123 4567.',
    ];

    for (const line of phones) {
      const { output } = sanitizeText(line, { ...options, rules: ['phoneNumbers'] });
      expect(output).toMatch(/<PHONE:[0-9a-f]{16}>/);
    }
  });
});
