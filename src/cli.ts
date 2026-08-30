import { realpathSync } from 'node:fs';
import { readFile, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { type Readable, type Writable } from 'node:stream';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

import { generateKey } from './core/key';
import { createSanitizer } from './core/sanitizer';
import { toNullSink } from './io/sinks';
import { fromFile, fromNodeStream, toFile, toNodeStream } from './node';
import { builtinRuleIds } from './rules/registry';
import type {
  BuiltinRuleId,
  KeyEncoding,
  SanitizeReport,
  SanitizeRule,
  SanitizerOptions,
  TextSink,
  TextSource,
} from './types';

export const EXIT_OK = 0;
export const EXIT_ERROR = 1;
export const EXIT_USAGE = 2;

const HELP = `Usage: logtotal-sanitize [options] <input>

Redact secrets, identifiers and PII from a log file. Input "-" reads stdin.

Options:
  -o, --out <path>           Output file (default: <input>.sanitized)
      --stdout               Write sanitized text to stdout
      --report <path>        Write a JSON report to <path>
      --report-format <fmt>  json | text (default: json)
      --rules <ids>          Comma-separated built-in rule ids (default: all)
      --exclude-rules <ids>  Comma-separated built-in rule ids to skip
      --rules-file <path>    Load extra rules from a JS/JSON module
      --exclude <value>      Never redact this exact value (repeatable)
      --exclude-file <path>  Newline-separated never-redact values
      --redact <value>       Always redact this exact value (repeatable)
      --redact-file <path>   Newline-separated always-redact values
      --aggressive           Enable broader, noisier patterns
      --key <value>          HMAC key (reuse to correlate tokens across files)
      --key-file <path>      Read HMAC key from a file
      --key-encoding <enc>   hex | utf8
      --print-key            Print the key to stderr
      --dry-run              Report only; do not write sanitized output
      --fail-on-match        Exit 1 if anything was redacted
      --progress             Show a live progress bar on stderr
      --no-progress          Do not show a progress bar
  -q, --quiet                Suppress the text summary
  -h, --help                 Show this help
  -v, --version              Show version
`;

interface CliFlags {
  out?: string;
  stdout: boolean;
  report?: string;
  reportFormat: 'json' | 'text';
  rules?: string;
  excludeRules?: string;
  rulesFile?: string;
  exclude: string[];
  excludeFile?: string;
  redact: string[];
  redactFile?: string;
  aggressive: boolean;
  key?: string;
  keyFile?: string;
  keyEncoding?: KeyEncoding;
  printKey: boolean;
  dryRun: boolean;
  failOnMatch: boolean;
  progress: boolean;
  noProgress: boolean;
  quiet: boolean;
  help: boolean;
  version: boolean;
  input?: string;
}

function parseCli(argv: string[]): CliFlags {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      out: { type: 'string', short: 'o' },
      stdout: { type: 'boolean', default: false },
      report: { type: 'string' },
      'report-format': { type: 'string', default: 'json' },
      rules: { type: 'string' },
      'exclude-rules': { type: 'string' },
      'rules-file': { type: 'string' },
      exclude: { type: 'string', multiple: true },
      'exclude-file': { type: 'string' },
      redact: { type: 'string', multiple: true },
      'redact-file': { type: 'string' },
      aggressive: { type: 'boolean', default: false },
      key: { type: 'string' },
      'key-file': { type: 'string' },
      'key-encoding': { type: 'string' },
      'print-key': { type: 'boolean', default: false },
      'dry-run': { type: 'boolean', default: false },
      'fail-on-match': { type: 'boolean', default: false },
      progress: { type: 'boolean', default: false },
      'no-progress': { type: 'boolean', default: false },
      quiet: { type: 'boolean', short: 'q', default: false },
      help: { type: 'boolean', short: 'h', default: false },
      version: { type: 'boolean', short: 'v', default: false },
    },
  });

  const keyEncoding =
    values['key-encoding'] === 'hex' || values['key-encoding'] === 'utf8'
      ? values['key-encoding']
      : undefined;

  return {
    out: values.out,
    stdout: Boolean(values.stdout),
    report: values.report,
    reportFormat: values['report-format'] === 'text' ? 'text' : 'json',
    rules: values.rules,
    excludeRules: values['exclude-rules'],
    rulesFile: values['rules-file'],
    exclude: values.exclude ?? [],
    excludeFile: values['exclude-file'],
    redact: values.redact ?? [],
    redactFile: values['redact-file'],
    aggressive: Boolean(values.aggressive),
    key: values.key,
    keyFile: values['key-file'],
    keyEncoding,
    printKey: Boolean(values['print-key']),
    dryRun: Boolean(values['dry-run']),
    failOnMatch: Boolean(values['fail-on-match']),
    progress: Boolean(values.progress),
    noProgress: Boolean(values['no-progress']),
    quiet: Boolean(values.quiet),
    help: Boolean(values.help),
    version: Boolean(values.version),
    input: positionals[0],
  };
}

async function readLines(path: string): Promise<string[]> {
  const text = await readFile(path, 'utf8');
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

async function loadRulesFile(path: string): Promise<SanitizeRule[]> {
  if (path.endsWith('.json')) {
    const parsed = JSON.parse(await readFile(path, 'utf8')) as unknown;
    return Array.isArray(parsed) ? (parsed as SanitizeRule[]) : [parsed as SanitizeRule];
  }

  const mod = (await import(pathToFileURL(path).href)) as { default?: unknown };
  const value = mod.default;
  if (Array.isArray(value)) {
    return value as SanitizeRule[];
  }
  return [value as SanitizeRule];
}

function formatReportText(report: SanitizeReport): string {
  const lines = [`lines: ${report.lineCount}`, `matches: ${report.totalMatches}`];
  for (const [id, count] of Object.entries(report.counts)) {
    lines.push(`  ${id}: ${count}`);
  }
  return `${lines.join('\n')}\n`;
}

const PROGRESS_BAR_WIDTH = 20;

function streamIsTty(stream: Writable): boolean {
  return Boolean((stream as NodeJS.WriteStream).isTTY);
}

function progressLabel(input: string, useStdin: boolean): string {
  if (useStdin) {
    return 'stdin';
  }
  const name = basename(input);
  return name.length > 32 ? `${name.slice(0, 29)}...` : name;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${Math.round(bytes)} B`;
  }

  const units = ['KB', 'MB', 'GB', 'TB'] as const;
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const digits = value >= 10 ? 1 : 2;
  return `${value.toFixed(digits)} ${units[unit]}`;
}

function formatBar(ratio: number): string {
  const clamped = Math.min(1, Math.max(0, ratio));
  const filled = Math.round(clamped * PROGRESS_BAR_WIDTH);
  const head =
    filled > 0 && filled < PROGRESS_BAR_WIDTH ? '>' : filled === PROGRESS_BAR_WIDTH ? '=' : '';
  const body = '='.repeat(Math.max(0, filled - head.length));
  const empty = ' '.repeat(PROGRESS_BAR_WIDTH - body.length - head.length);
  return `[${body}${head}${empty}]`;
}

function formatProgressLine(state: {
  label: string;
  bytesRead: number;
  totalBytes?: number;
  lineCount: number;
  totalMatches: number;
}): string {
  const stats = `${formatBytes(state.bytesRead)}${
    state.totalBytes !== undefined ? ` / ${formatBytes(state.totalBytes)}` : ''
  }  ${state.lineCount} lines  ${state.totalMatches} matches`;

  if (state.totalBytes === undefined) {
    return `${state.label}  ${stats}`;
  }

  const ratio = state.totalBytes === 0 ? 1 : Math.min(1, state.bytesRead / state.totalBytes);
  const pct = String(Math.min(100, Math.floor(ratio * 100))).padStart(3, ' ');
  return `${state.label}  ${formatBar(ratio)} ${pct}%  ${stats}`;
}

function withByteTracking(source: TextSource, tracked: { bytes: number }): TextSource {
  return {
    async *[Symbol.asyncIterator](): AsyncIterator<string> {
      for await (const chunk of source as AsyncIterable<string>) {
        tracked.bytes += Buffer.byteLength(chunk, 'utf8');
        yield chunk;
      }
    },
  };
}

function createProgressPrinter(
  stderr: Writable,
  options: { tty: boolean; label: string; totalBytes?: number },
): {
  update(bytesRead: number, report: Pick<SanitizeReport, 'lineCount' | 'totalMatches'>): void;
  finish(bytesRead: number, report: Pick<SanitizeReport, 'lineCount' | 'totalMatches'>): void;
} {
  const minIntervalMs = options.tty ? 80 : 500;
  let lastAt = 0;
  let lastLen = 0;
  let lastText = '';

  const lineFor = (
    bytesRead: number,
    report: Pick<SanitizeReport, 'lineCount' | 'totalMatches'>,
  ): string =>
    formatProgressLine({
      label: options.label,
      bytesRead,
      totalBytes: options.totalBytes,
      lineCount: report.lineCount,
      totalMatches: report.totalMatches,
    });

  const paint = (text: string, newline: boolean): void => {
    lastText = text;
    if (options.tty) {
      const padded = text.length < lastLen ? `${text}${' '.repeat(lastLen - text.length)}` : text;
      stderr.write(`\r${padded}`);
      lastLen = text.length;
      if (newline) {
        stderr.write('\n');
      }
    } else {
      stderr.write(`${text}\n`);
    }
  };

  return {
    update(bytesRead, report) {
      const now = Date.now();
      if (now - lastAt < minIntervalMs) {
        return;
      }
      lastAt = now;
      paint(lineFor(bytesRead, report), false);
    },
    finish(bytesRead, report) {
      const text = lineFor(bytesRead, report);
      if (!options.tty && text === lastText) {
        return;
      }
      paint(text, true);
    },
  };
}

export async function runCli(
  argv: string[],
  io: {
    stdin: Readable;
    stdout: Writable;
    stderr: Writable;
  } = {
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
  },
): Promise<number> {
  let flags: CliFlags;
  try {
    flags = parseCli(argv);
  } catch (error) {
    io.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    return EXIT_USAGE;
  }

  if (flags.help) {
    io.stdout.write(HELP);
    return EXIT_OK;
  }

  if (flags.version) {
    const pkgUrl = new URL('../package.json', import.meta.url);
    const pkg = JSON.parse(await readFile(pkgUrl, 'utf8')) as { version: string };
    io.stdout.write(`${pkg.version}\n`);
    return EXIT_OK;
  }

  if (!flags.input) {
    io.stderr.write('Missing input path. Use "-" for stdin.\n');
    io.stderr.write(HELP);
    return EXIT_USAGE;
  }

  const extraRules = flags.rulesFile ? await loadRulesFile(flags.rulesFile) : [];
  let ruleIds: BuiltinRuleId[] = [...builtinRuleIds];
  if (flags.rules) {
    ruleIds = flags.rules.split(',').map((id) => id.trim()) as BuiltinRuleId[];
  }
  if (flags.excludeRules) {
    const skip = new Set(flags.excludeRules.split(',').map((id) => id.trim()));
    ruleIds = ruleIds.filter((id) => !skip.has(id));
  }

  const neverValues = [...flags.exclude];
  if (flags.excludeFile) {
    neverValues.push(...(await readLines(flags.excludeFile)));
  }
  const alwaysValues = [...flags.redact];
  if (flags.redactFile) {
    alwaysValues.push(...(await readLines(flags.redactFile)));
  }

  const suppliedKey = Boolean(flags.key || flags.keyFile);
  let key = flags.key;
  if (flags.keyFile) {
    key = (await readFile(flags.keyFile, 'utf8')).trim();
  }
  if (!key) {
    key = generateKey();
  }
  if (flags.printKey) {
    io.stderr.write(`${key}\n`);
  }

  const options: SanitizerOptions = {
    rules: ruleIds,
    extraRules: extraRules.length > 0 ? extraRules : undefined,
    aggressive: flags.aggressive,
    key,
    keyEncoding: flags.keyEncoding ?? (suppliedKey ? 'utf8' : 'hex'),
    alwaysRedact: alwaysValues.length > 0 ? { values: alwaysValues } : undefined,
    neverRedact: neverValues.length > 0 ? { values: neverValues } : undefined,
    // Normal output, progress, and text reports only consume aggregate counts. Preserve the
    // detailed replacement list and preview for the explicit JSON report surface.
    report:
      flags.report && flags.reportFormat === 'json'
        ? undefined
        : { previewBytes: 0, replacements: false },
  };

  const sanitizer = createSanitizer(options);
  const useStdin = flags.input === '-';
  const source = useStdin ? fromNodeStream(io.stdin) : fromFile(flags.input);
  const tty = streamIsTty(io.stderr);
  const showProgress = flags.noProgress ? false : flags.progress || (tty && !flags.quiet);
  const totalBytes = showProgress && !useStdin ? (await stat(flags.input)).size : undefined;
  const tracked = { bytes: 0 };
  const trackedSource = showProgress ? withByteTracking(source, tracked) : source;
  const progress = showProgress
    ? createProgressPrinter(io.stderr, {
        tty,
        label: progressLabel(flags.input, useStdin),
        totalBytes,
      })
    : undefined;

  const writeStdout = flags.stdout || (useStdin && !flags.out);
  let outputPath = flags.out;
  if (!writeStdout && !flags.dryRun && !outputPath && !useStdin) {
    outputPath = join(dirname(flags.input), `${basename(flags.input)}.sanitized`);
  }

  const sink: TextSink = flags.dryRun
    ? toNullSink()
    : writeStdout
      ? toNodeStream(io.stdout)
      : toFile(outputPath!);

  const report = await sanitizer.sanitizeStream(trackedSource, sink, {
    onProgress: progress
      ? (snapshot) => {
          progress.update(tracked.bytes, snapshot.report);
        }
      : undefined,
  });

  progress?.finish(tracked.bytes, report);

  if (flags.report) {
    const body =
      flags.reportFormat === 'text'
        ? formatReportText(report)
        : `${JSON.stringify(report, null, 2)}\n`;
    await writeFile(flags.report, body, 'utf8');
  }

  if (!flags.quiet && !writeStdout) {
    io.stderr.write(formatReportText(report));
  }

  if (flags.failOnMatch && report.totalMatches > 0) {
    return EXIT_ERROR;
  }

  return EXIT_OK;
}

async function main(): Promise<void> {
  try {
    process.exitCode = await runCli(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = EXIT_ERROR;
  }
}

/** True when this module is the Node process entry (including npm/npx bin shims). */
export function isCliEntryPoint(entryPath: string | undefined = process.argv[1]): boolean {
  if (!entryPath) {
    return false;
  }

  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(entryPath);
  } catch {
    return false;
  }
}

if (isCliEntryPoint()) {
  void main();
}
