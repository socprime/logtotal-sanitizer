import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { describe, expect, it } from 'vitest';

import { EXIT_OK, runCli } from '../src/cli.js';
import { sanitizeText } from '../src/index.js';

const KEY = '0123456789abcdef'.repeat(4);
const IPS_ONLY = { key: KEY, keyEncoding: 'hex' as const, rules: ['ips'] as const };

describe('keepPrivateIps', () => {
  it('redacts RFC 1918 addresses by default', () => {
    const { output, report } = sanitizeText('login from 10.0.0.1', IPS_ONLY);
    expect(output).toMatch(/^login from <IP:[0-9a-f]{16}>$/);
    expect(report.counts.ips).toBe(1);
    expect(report.totalMatches).toBe(1);
  });

  it('keeps RFC 1918 IPv4 and related shapes when enabled', () => {
    const input = [
      '10.0.0.1',
      '10.255.255.255',
      '172.16.0.1',
      '172.31.255.255',
      '192.168.1.1',
      '::ffff:192.168.0.1',
      '1.0.0.10.in-addr.arpa',
    ].join(' ');
    const { output, report } = sanitizeText(input, {
      ...IPS_ONLY,
      keepPrivateIps: true,
    });

    expect(output).toBe(input);
    expect(report.counts.ips ?? 0).toBe(0);
    expect(report.totalMatches).toBe(0);
  });

  it('still redacts non-RFC1918 and public addresses when enabled', () => {
    const cases = [
      '172.15.255.255',
      '172.32.0.1',
      '11.0.0.1',
      '192.169.0.1',
      '8.8.8.8',
      'aa:bb:cc:dd:ee:ff',
    ];
    for (const value of cases) {
      const { output, report } = sanitizeText(value, {
        ...IPS_ONLY,
        keepPrivateIps: true,
      });
      expect(output).toMatch(/<IP:[0-9a-f]{16}>/);
      expect(report.counts.ips).toBe(1);
    }
  });

  it('JSON keyed fields keep private src and redact public dst', () => {
    const line = '{"sourceIp":"10.0.0.5","dstIp":"8.8.8.8"}';
    const { output, report } = sanitizeText(line, {
      ...IPS_ONLY,
      keepPrivateIps: true,
    });

    expect(output).toMatch(/"sourceIp":"10\.0\.0\.5"/);
    expect(output).toMatch(/"dstIp":"<IP:[0-9a-f]{16}>"/);
    expect(report.counts.ips).toBe(1);
    expect(report.totalMatches).toBe(1);
  });

  it('keyed KV keeps private src_ip values', () => {
    const line = 'src_ip="10.0.0.5"';
    const { output, report } = sanitizeText(line, {
      ...IPS_ONLY,
      keepPrivateIps: true,
    });

    expect(output).toBe('src_ip="10.0.0.5"');
    expect(report.counts.ips ?? 0).toBe(0);
  });

  it('mixed line keeps only private matches in counts', () => {
    const line = 'seen 10.0.0.1 and 8.8.8.8';
    const { output, report } = sanitizeText(line, {
      ...IPS_ONLY,
      keepPrivateIps: true,
    });

    expect(output).toMatch(/^seen 10\.0\.0\.1 and <IP:[0-9a-f]{16}>$/);
    expect(report.counts.ips).toBe(1);
    expect(report.totalMatches).toBe(1);
  });

  it('CLI --keep-private-ips leaves private addresses in output', async () => {
    const dir = join(tmpdir(), `logtotal-keep-private-${Date.now()}`);
    await mkdir(dir);
    const input = join(dir, 'app.log');
    const outputPath = join(dir, 'out.log');
    await writeFile(input, 'peer 10.0.0.1 public 8.8.8.8\n', 'utf8');

    let stdoutText = '';
    const stdout = new Writable({
      write(chunk, _enc, cb) {
        stdoutText += String(chunk);
        cb();
      },
    });
    const stderr = new Writable({
      write(_chunk, _enc, cb) {
        cb();
      },
    });

    const code = await runCli(
      ['--keep-private-ips', '--rules', 'ips', '-q', input, '-o', outputPath],
      {
        stdin: process.stdin,
        stdout,
        stderr,
      },
    );

    expect(code).toBe(EXIT_OK);
    const out = await readFile(outputPath, 'utf8');
    expect(out).toMatch(/10\.0\.0\.1/);
    expect(out).toMatch(/<IP:[0-9a-f]{16}>/);
    expect(stdoutText).toBe('');

    await rm(dir, { recursive: true });
  });
});
