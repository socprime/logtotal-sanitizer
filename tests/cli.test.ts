import { mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable, Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { EXIT_OK, EXIT_USAGE, isCliEntryPoint, runCli } from '../src/cli.js';
import { InvalidOptionError } from '../src/index.js';
import { sanitizeFile } from '../src/node/index.js';

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
    expect(stdout.text()).toMatch(/--format <fmt>\s+auto \| lines \| csv \(default: auto\)/);
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

  it('sanitizes a .csv file as CSV and keeps the header', async () => {
    const dir = join(tmpdir(), `logtotal-sanitize-csv-${Date.now()}`);
    await mkdir(dir);
    const input = join(dir, 'DATA.CSV');
    const output = join(dir, 'out.log');
    await writeFile(input, 'user.name,note\njdoe,hello\n', 'utf8');

    const stdout = collect();
    const stderr = collect();
    const code = await runCli(['-q', input, '-o', output], {
      stdin: process.stdin,
      stdout: stdout.stream,
      stderr: stderr.stream,
    });
    const text = await readFile(output, 'utf8');
    const [header, row] = text.split('\n');

    expect(code).toBe(EXIT_OK);
    expect(header).toBe('user.name,note');
    expect(row).toMatch(/^<USER:[0-9a-f]{16}>,hello$/);
    expect(text).not.toContain('jdoe');

    await rm(dir, { recursive: true });
  });

  it('keeps a .csv cell when --format lines is set', async () => {
    const dir = join(tmpdir(), `logtotal-sanitize-csv-lines-${Date.now()}`);
    await mkdir(dir);
    const input = join(dir, 'events.csv');
    const output = join(dir, 'out.log');
    await writeFile(input, 'user.name,note\njdoe,hello\n', 'utf8');

    const stdout = collect();
    const stderr = collect();
    const code = await runCli(['-q', '--format', 'lines', input, '-o', output], {
      stdin: process.stdin,
      stdout: stdout.stream,
      stderr: stderr.stream,
    });
    const text = await readFile(output, 'utf8');

    expect(code).toBe(EXIT_OK);
    expect(text).toContain('jdoe');
    expect(text).not.toMatch(/<USER:/);

    await rm(dir, { recursive: true });
  });

  it('sanitizes a .tsv file with a tab delimiter', async () => {
    const dir = join(tmpdir(), `logtotal-sanitize-tsv-${Date.now()}`);
    await mkdir(dir);
    const input = join(dir, 'events.tsv');
    const output = join(dir, 'out.log');
    await writeFile(input, 'user.name\tnote\njdoe\thello\n', 'utf8');

    const stdout = collect();
    const stderr = collect();
    const code = await runCli(['-q', input, '-o', output], {
      stdin: process.stdin,
      stdout: stdout.stream,
      stderr: stderr.stream,
    });
    const text = await readFile(output, 'utf8');
    const [header, row] = text.split('\n');

    expect(code).toBe(EXIT_OK);
    expect(header).toBe('user.name\tnote');
    expect(row).toMatch(/^<USER:[0-9a-f]{16}>\thello$/);
    expect(text).not.toContain('jdoe');

    await rm(dir, { recursive: true });
  });

  it('reads stdin as lines when --format is auto', async () => {
    const stdout = collect();
    const stderr = collect();
    const code = await runCli(['-q', '--stdout', '-'], {
      stdin: Readable.from(['user.name,note\njdoe,hello\n']),
      stdout: stdout.stream,
      stderr: stderr.stream,
    });

    expect(code).toBe(EXIT_OK);
    expect(stdout.text()).toContain('jdoe');
    expect(stdout.text()).not.toMatch(/<USER:/);
  });

  it('rejects an unknown --format value', async () => {
    const stdout = collect();
    const stderr = collect();
    const code = await runCli(['--format', 'bogus', 'events.csv'], {
      stdin: process.stdin,
      stdout: stdout.stream,
      stderr: stderr.stream,
    });

    expect(code).toBe(EXIT_USAGE);
    expect(stderr.text()).toMatch(/Invalid value for --format: "bogus"/);
    expect(stderr.text()).toMatch(/Expected auto, lines, or csv/);
  });
});

describe('sanitizeFile format', () => {
  it('auto-detects csv and tsv unless csv is set', async () => {
    const dir = join(tmpdir(), `logtotal-sanitize-file-format-${Date.now()}`);
    await mkdir(dir);
    const csvPath = join(dir, 'events.csv');
    const logPath = join(dir, 'events.log');
    const tsvPath = join(dir, 'events.TSV');
    const body = 'user.name,note\njdoe,hello\n';
    await writeFile(csvPath, body, 'utf8');
    await writeFile(logPath, body, 'utf8');
    await writeFile(tsvPath, 'user.name\tnote\njdoe\thello\n', 'utf8');

    const csvOut = join(dir, 'csv.out');
    await sanitizeFile({ input: csvPath, output: csvOut });
    expect((await readFile(csvOut, 'utf8')).split('\n')[0]).toBe('user.name,note');
    expect(await readFile(csvOut, 'utf8')).not.toContain('jdoe');

    const linesOut = join(dir, 'lines.out');
    await sanitizeFile({ input: csvPath, output: linesOut, format: 'lines' });
    expect(await readFile(linesOut, 'utf8')).toContain('jdoe');

    const forcedOut = join(dir, 'forced.out');
    await sanitizeFile({ input: logPath, output: forcedOut, format: 'csv' });
    expect(await readFile(forcedOut, 'utf8')).not.toContain('jdoe');

    const disabledOut = join(dir, 'disabled.out');
    await sanitizeFile({ input: csvPath, output: disabledOut, csv: false });
    expect(await readFile(disabledOut, 'utf8')).toContain('jdoe');

    const tsvOut = join(dir, 'tsv.out');
    await sanitizeFile({ input: tsvPath, output: tsvOut });
    const tsvText = await readFile(tsvOut, 'utf8');
    expect(tsvText.split('\n')[0]).toBe('user.name\tnote');
    expect(tsvText).not.toContain('jdoe');

    await expect(
      sanitizeFile({ input: csvPath, format: 'bogus' as 'auto' }),
    ).rejects.toBeInstanceOf(InvalidOptionError);

    await rm(dir, { recursive: true });
  });
});
