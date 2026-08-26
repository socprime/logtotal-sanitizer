import { spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as esbuild from 'esbuild';

const root = fileURLToPath(new URL('..', import.meta.url));

const JSC_CANDIDATES = [
  '/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc',
  'jsc',
];

const textEncoderPolyfill = `
if (typeof TextEncoder === 'undefined') {
  var TextEncoder = function TextEncoder() {};
  TextEncoder.prototype.encode = function encode(input) {
    var str = String(input);
    var bytes = [];
    for (var i = 0; i < str.length; i++) {
      var code = str.charCodeAt(i);
      if (code < 0x80) bytes.push(code);
      else if (code < 0x800) {
        bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
      } else if (code >= 0xd800 && code <= 0xdbff) {
        var next = str.charCodeAt(++i);
        code = 0x10000 + ((code & 0x3ff) << 10) + (next & 0x3ff);
        bytes.push(
          0xf0 | (code >> 18),
          0x80 | ((code >> 12) & 0x3f),
          0x80 | ((code >> 6) & 0x3f),
          0x80 | (code & 0x3f),
        );
      } else {
        bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
      }
    }
    return new Uint8Array(bytes);
  };
}
`;

const entry = `
import { createSanitizer } from './src/index.ts';

var log = typeof print === 'function' ? print : console.log;
var KEY = '0123456789abcdef'.repeat(4);
var WIDTH = 994;
var LINE_COUNT = 80;
var chunk = 'Nov 15 09:19:41 kernel: Completed invocation of ScriptBlock ID: ed4c24c2-4b19-411e-bcaa-e16849bb0a74 user=jdoe path=/home/bob/app ';
var lines = [];
for (var n = 0; n < LINE_COUNT; n++) {
  var line = '';
  while (line.length < WIDTH) line += chunk;
  lines.push(line.slice(0, WIDTH));
}
var text = lines.join('\\n');
var sanitizer = createSanitizer({ key: KEY, keyEncoding: 'hex', json: false, report: { previewBytes: 0, replacements: false } });
sanitizer.sanitizeText(text.slice(0, WIDTH));
var t0 = Date.now();
var result = sanitizer.sanitizeText(text);
var t1 = Date.now();
var ms = t1 - t0;
var chars = text.length;
var msPerLine = ms / LINE_COUNT;
var mbps = chars / 1048576 / (ms / 1000);
log('lines=' + LINE_COUNT + ' width=' + WIDTH + ' matches=' + result.report.totalMatches);
log('time=' + ms + 'ms  ' + msPerLine.toFixed(3) + ' ms/line  ' + mbps.toFixed(2) + ' MB/s');
`;

const outDir = mkdtempSync(join(tmpdir(), 'logtotal-bench-'));
const outfile = join(outDir, 'bench.js');

await esbuild.build({
  stdin: {
    contents: entry,
    resolveDir: root,
    sourcefile: 'bench-entry.ts',
    loader: 'ts',
  },
  bundle: true,
  format: 'iife',
  platform: 'neutral',
  banner: { js: textEncoderPolyfill },
  outfile,
  logLevel: 'silent',
});

function run(label, command, args) {
  process.stdout.write(`===== ${label} =====\n`);
  const result = spawnSync(command, args, { encoding: 'utf8' });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.status !== 0) {
    process.exitCode = result.status ?? 1;
  }
}

run('V8 (node)', process.execPath, [outfile]);

let jsc = null;
for (const candidate of JSC_CANDIDATES) {
  const probe = spawnSync(candidate, ['-e', 'print(1)'], { encoding: 'utf8' });
  if (probe.error) {
    continue;
  }
  if (probe.status === 0) {
    jsc = candidate;
    break;
  }
}

if (jsc) {
  process.stdout.write('\n');
  run('JSC (Safari engine)', jsc, [outfile]);
} else {
  process.stdout.write('\n(jsc not found; Safari engine bench skipped)\n');
}
