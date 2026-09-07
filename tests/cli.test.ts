import { mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable, Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { EXIT_OK, EXIT_USAGE, isCliEntryPoint, runCli } from '../src/cli.js';

function collect(options?: { isTTY?: boolean }) {
  let text = '';
  const stream = new Writable({
    write(chunk, _enc, cb) {
      text += String(chunk);
      cb();
    },
  });
  if (options?.isTTY === true) {
    Object.defineProperty(stream, 'isTTY', { value: true });
  }
  return {
    stream,
    text: () => text,
  };
}

describe('runCli', () => {
  it('prints help', async () => {
    const stdout = collect();
    const stderr = collect();
    const code = await runCli(['--help'], {
      stdin: process.stdin,
      stdout: stdout.stream,
      stderr: stderr.stream,
    });
    expect(code).toBe(EXIT_OK);
    expect(stdout.text()).toMatch(/Usage: logtotal-sanitize/);
    expect(stdout.text()).toMatch(/--progress/);
  });

  it('detects entry via npm/npx bin shim symlink', async () => {
    const cliModule = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
    const dir = join(tmpdir(), `logtotal-sanitize-shim-${Date.now()}`);
    await mkdir(dir);
    const shim = join(dir, 'logtotal-sanitize');
    await symlink(cliModule, shim);

    expect(isCliEntryPoint(shim)).toBe(true);
    expect(isCliEntryPoint(join(dir, 'other.js'))).toBe(false);

    await rm(dir, { recursive: true });
  });

  it('returns usage when input is missing', async () => {
    const stdout = collect();
    const stderr = collect();
    const code = await runCli([], {
      stdin: process.stdin,
      stdout: stdout.stream,
      stderr: stderr.stream,
    });
    expect(code).toBe(EXIT_USAGE);
    expect(stderr.text()).toMatch(/Missing input/);
  });

  it('prints file progress when --progress is set', async () => {
    const dir = join(tmpdir(), `logtotal-sanitize-progress-${Date.now()}`);
    await mkdir(dir);
    const input = join(dir, 'app.log');
    await writeFile(input, 'login from 10.0.0.1\n'.repeat(50), 'utf8');

    const stdout = collect();
    const stderr = collect();
    const code = await runCli(['--progress', '-q', input, '-o', join(dir, 'out.log')], {
      stdin: process.stdin,
      stdout: stdout.stream,
      stderr: stderr.stream,
    });

    expect(code).toBe(EXIT_OK);
    expect(stderr.text()).toMatch(/app\.log/);
    expect(stderr.text()).toMatch(/100%/);
    expect(stderr.text()).toMatch(/50 lines/);
    expect(stderr.text()).toMatch(/50 matches/);

    await rm(dir, { recursive: true });
  });

  it('shows progress on a TTY without --progress', async () => {
    const dir = join(tmpdir(), `logtotal-sanitize-progress-tty-${Date.now()}`);
    await mkdir(dir);
    const input = join(dir, 'app.log');
    await writeFile(input, 'ok\n', 'utf8');

    const stdout = collect();
    const stderr = collect({ isTTY: true });
    const code = await runCli([input, '-o', join(dir, 'out.log')], {
      stdin: process.stdin,
      stdout: stdout.stream,
      stderr: stderr.stream,
    });

    expect(code).toBe(EXIT_OK);
    expect(stderr.text()).toMatch(/\r/);
    expect(stderr.text()).toMatch(/100%/);
    expect(stderr.text()).toMatch(/^lines:/m);

    await rm(dir, { recursive: true });
  });

  it('hides the progress bar when --no-progress is set on a TTY', async () => {
    const dir = join(tmpdir(), `logtotal-sanitize-no-progress-${Date.now()}`);
    await mkdir(dir);
    const input = join(dir, 'app.log');
    await writeFile(input, 'ok\n', 'utf8');

    const stdout = collect();
    const stderr = collect({ isTTY: true });
    const code = await runCli(['--no-progress', input, '-o', join(dir, 'out.log')], {
      stdin: process.stdin,
      stdout: stdout.stream,
      stderr: stderr.stream,
    });

    expect(code).toBe(EXIT_OK);
    expect(stderr.text()).not.toMatch(/%/);
    expect(stderr.text()).toMatch(/^lines:/);

    await rm(dir, { recursive: true });
  });

  it('prints stdin progress without a percentage', async () => {
    const stdout = collect();
    const stderr = collect();
    const code = await runCli(['--progress', '--stdout', '-'], {
      stdin: Readable.from(['hello 10.0.0.1\n']),
      stdout: stdout.stream,
      stderr: stderr.stream,
    });

    expect(code).toBe(EXIT_OK);
    expect(stderr.text()).toMatch(/stdin/);
    expect(stderr.text()).toMatch(/1 lines/);
    expect(stderr.text()).not.toMatch(/%/);
    expect(stdout.text()).toMatch(/<IP:/);
  });

  it('preserves replacement details and previews in an explicit JSON report', async () => {
    const dir = join(tmpdir(), `logtotal-sanitize-report-${Date.now()}`);
    await mkdir(dir);
    const input = join(dir, 'app.log');
    const reportPath = join(dir, 'report.json');
    await writeFile(input, 'login from 10.0.0.1\n', 'utf8');

    const stdout = collect();
    const stderr = collect();
    const code = await runCli(['-q', '--report', reportPath, input, '-o', join(dir, 'out.log')], {
      stdin: process.stdin,
      stdout: stdout.stream,
      stderr: stderr.stream,
    });
    const report = JSON.parse(await readFile(reportPath, 'utf8')) as {
      replacements: unknown[];
      preview: { before: unknown[]; after: unknown[] };
    };

    expect(code).toBe(EXIT_OK);
    expect(report.replacements).toHaveLength(1);
    expect(report.preview.before.length).toBeGreaterThan(0);
    expect(report.preview.after.length).toBeGreaterThan(0);

    await rm(dir, { recursive: true });
  });
});
