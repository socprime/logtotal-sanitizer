# @socprime/logtotal-sanitizer

Framework-agnostic log sanitizer for browsers and Node.js. It's designed to sanitize log files before they are sent to third-party platforms for processing, analysis, or troubleshooting. The sanitizer redacts secrets, identifiers, and PII and replaces each value with a stable HMAC token to reduce the risk of accidentally exposing sensitive or confidential information contained in logs.

This library is already integrated into [LogTotal](https://logtotal.com) and runs directly in the browser, allowing logs to be sanitized locally before they leave the user's environment.

If you require a fully controlled and isolated data sanitization environment, you can deploy and run this library within your own infrastructure. The sanitizer can also be installed and used in air-gapped environments, ensuring that sensitive log data remains within an environment you fully control.

The library has no runtime dependencies. The same compiled rules run in a browser tab and in a Node.js CLI.

## Install

```bash
npm install @socprime/logtotal-sanitizer
```

Requires Node.js 20 or newer when used from Node. Browsers need `globalThis.crypto.getRandomValues`.

## Quick start

```ts
import { createSanitizer, generateKey } from '@socprime/logtotal-sanitizer';

const key = generateKey();
const sanitizer = createSanitizer({
  key,
  rules: ['secrets', 'ips', 'hosts', 'users'],
});

const { output, report } = sanitizer.sanitizeText(
  'user alice@example.test logged in from 10.0.0.1 with Bearer abcdefghijklmnop',
);

console.log(output);
console.log(report.counts);
```

Reuse `key` across files when the same original value must map to the same token. Persistence is your responsibility; the library never writes the key to disk or `sessionStorage`.

## Options

`createSanitizer(options)` compiles rules once. `sanitizeText(text, options)` is a one-shot wrapper.

| Option                | Default            | Meaning                                                                                |
| --------------------- | ------------------ | -------------------------------------------------------------------------------------- |
| `rules`               | all built-in rules | Built-in ids, custom rules from `defineRule`, or a mix. Array order is match priority. |
| `aggressive`          | `false`            | Also apply each rule's broader `aggressivePatterns`.                                   |
| `key`                 | `generateKey()`    | HMAC key. Generated keys are 64 hex chars.                                             |
| `keyEncoding`         | `hex`              | How to decode `key`. Generated keys are hex; pass `utf8` for a passphrase.             |
| `alwaysRedact`        | —                  | Extra literals and regexes, highest match priority.                                    |
| `neverRedact`         | —                  | Allowlist. Highest overall priority: matching values are left unchanged.               |
| `report.contextChars` | `0`                | Characters of surrounding text on each unique replacement.                             |
| `report.maxReplacementsPerRule` | —        | Cap on distinct originals stored per rule. Counts stay complete.                       |

### Priority

1. `neverRedact` (global values, global patterns, then `byRule`)
2. `alwaysRedact`
3. Selected rules, in the order you passed them (built-in registry order when you omit `rules`)

A rejected `validate()` result also skips the span. The engine does not retry a later overlapping rule from the same start offset.

### alwaysRedact / neverRedact

```ts
const sanitizer = createSanitizer({
  key,
  alwaysRedact: {
    values: ['acme-internal-host'],
    patterns: [/CASE-\d{6}/],
  },
  neverRedact: {
    values: ['127.0.0.1'],
    byRule: [{ ruleId: 'hosts', values: ['localhost'] }],
  },
});
```

`alwaysRedact` matches appear in the report under rule id `custom` with token prefix `CUSTOM`.

## Built-in rules

Enabled in this order when you omit `rules`:

| id               | Token       | What it redacts                                                                                                                                                 |
| ---------------- | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `secrets`        | `<R:…>`     | Bearer/JWT/API keys, PEM blocks, cloud tokens. Aggressive: high-entropy hex/base64 blobs.                                                                       |
| `sessionCookies` | `<R:…>`     | Session cookie names and values.                                                                                                                                |
| `paymentInfo`    | `<R:…>`     | PAN, IBAN, and related payment identifiers (Luhn / mod-97).                                                                                                     |
| `govIds`         | `<R:…>`     | Government identifiers (SSN-like, national IDs).                                                                                                                |
| `healthInfo`     | `<R:…>`     | Health-record shaped identifiers and ICD-like codes.                                                                                                            |
| `phoneNumbers`   | `<PHONE:…>` | International and national phone numbers.                                                                                                                       |
| `ips`            | `<IP:…>`    | IPv4, IPv6, MAC, reverse-DNS.                                                                                                                                   |
| `hosts`          | `<HOST:…>`  | Hostnames and FQDNs, including the host field in syslog lines. Aggressive: `WIN-` / `DESKTOP-` NetBIOS names and `srv-` / `web-` / `db-` style inventory names. |
| `users`          | `<USER:…>`  | Usernames and emails.                                                                                                                                           |
| `geoLocation`    | `<GEO:…>`   | Coordinates and postal-style locations.                                                                                                                         |
| `paths`          | `<R:…>`     | Home-directory user segments (`/home/…`, `\Users\…`).                                                                                                           |

`mask` mode (`<R:…>`) hides the kind of secret. `pseudo` mode keeps a type prefix so you can still read the timeline.

JSON lines: if a line parses as a JSON object or array, fields listed in a rule's `jsonKeys` are redacted by name (case- and `-`/`_`-insensitive). Other string values still go through the regex pass.

## Custom rules

```ts
import { createSanitizer, defineRule } from '@socprime/logtotal-sanitizer';

const ticket = defineRule({
  id: 'ticket',
  label: 'Ticket ids',
  description: 'Internal ticket numbers',
  mode: 'pseudo',
  token: 'TICKET',
  patterns: ['(?:CASE-\\d{6})'],
});

const sanitizer = createSanitizer({ rules: ['secrets', ticket] });
```

`id` must be a JavaScript identifier. At most one capturing group per fragment; it marks the value to replace (the rest of the match is kept). Put expensive checks in `validate`, not in the regex.

## Streaming and I/O

```ts
import { createSanitizer, fromString, toString } from '@socprime/logtotal-sanitizer';

const sink = toString();
const report = await createSanitizer({ key }).sanitizeStream(fromString(text), sink);
const output = sink.result();
```

Browser helpers: `fromBlob`, `fromWebStream`, `toWebStream`.
`planLineAlignedRanges(blob, partCount)` returns newline-aligned byte ranges for concurrent
sanitization; `mergeReports(reports)` folds the resulting reports back together.

Node helpers (subpath `@socprime/logtotal-sanitizer/node`):

```ts
import { sanitizeFile } from '@socprime/logtotal-sanitizer/node';

await sanitizeFile('./app.log', './app.sanitized.log', { rules: ['secrets', 'ips'] });
```

Also: `fromFile`, `toFile`, `fromNodeStream`, `toNodeStream`.

The root entry does not import `node:*`.

## Report

```ts
{
  counts: { ips: 2, secrets: 1 },
  totalMatches: 3,
  lineCount: 40,
  replacements: [{ ruleId, original, replacement, count, contextBefore?, contextAfter? }],
  preview: { before: [{ text, changed }], after: [{ text, changed }] },
  replacementsTruncated?: true
}
```

`preview` covers the first 256 KiB of output.

## CLI

```bash
npx @socprime/logtotal-sanitizer --help

# local
npx logtotal-sanitize ./app.log -o ./app.sanitized.log --report ./report.json

# stdin / stdout
cat app.log | npx logtotal-sanitize - --stdout > app.sanitized.log

# correlate tokens across files
npx logtotal-sanitize a.log -o a.out --print-key
npx logtotal-sanitize b.log -o b.out --key "$KEY"
```

Global install:

```bash
npm install -g @socprime/logtotal-sanitizer
logtotal-sanitize ./app.log -o ./app.sanitized.log
```

| Flag                                      | Meaning                                                                            |
| ----------------------------------------- | ---------------------------------------------------------------------------------- |
| `-o, --out`                               | Output path (default: `<input>.sanitized`)                                         |
| `--stdout`                                | Write sanitized text to stdout                                                     |
| `--report` / `--report-format`            | JSON or text summary                                                               |
| `--rules` / `--exclude-rules`             | Built-in id lists                                                                  |
| `--rules-file`                            | Extra rules from JS (default export) or JSON                                       |
| `--exclude` / `--exclude-file`            | `neverRedact` values                                                               |
| `--redact` / `--redact-file`              | `alwaysRedact` values                                                              |
| `--aggressive`                            | Broader patterns                                                                   |
| `--key` / `--key-file` / `--key-encoding` | HMAC key                                                                           |
| `--print-key`                             | Print the key to stderr                                                            |
| `--dry-run`                               | Report only                                                                        |
| `--fail-on-match`                         | Exit `1` if anything was redacted                                                  |
| `--progress` / `--no-progress`            | Live progress bar on stderr (on by default when stderr is a TTY and not `--quiet`) |
| `-q, --quiet`                             | No text summary                                                                    |

Exit codes: `0` ok, `1` runtime error or `--fail-on-match`, `2` usage error.

## Token correlation

Tokens are HMAC-SHA-256 of `ruleId || 0x00 || original`, truncated to 16 hex chars. Same key + same value + same rule ⇒ same token. A different key produces different tokens. Generated keys use encoding `hex`; pasted keys default to `utf8`.

## Integrations

The sanitizer is a library first, so most real deployments wrap it in something else: a pipeline function, a stream processor, a sidecar. This index tracks integrations that exist today and ones we (or partners) intend to build. Entries maintained outside SOC Prime are marked as such and are not endorsed or supported by SOC Prime.

Status values: **Available** — released and usable. **Planned** — committed, in design or development. **Wanted** — no owner yet; open an issue to claim one.

| Integration | Maintainer | Status | Description |
| --- | --- | --- | --- |
| [Cribl Stream Pack](https://github.com/M3NIX/cribl-logtotal-sanitizer) | [@M3NIX](https://github.com/M3NIX) (community) | Available | Cribl Stream Pack that sanitizes `_raw` in-pipeline using a Worker Group Secret as the HMAC key. Ships a Function, a passthrough fallback route, and 100 synthetic preview events. Also on [packs.cribl.io](https://packs.cribl.io/packs/cc-stream-logtotal-sanitizer). |
| Kafka — sanitize on produce | SOC Prime | Planned | Sanitizes events at the ingestion edge, before they are written to the topic, so raw secrets and identifiers never land in Kafka storage or replicas. |
| Kafka — sanitize on consume | SOC Prime | Planned | Leaves the topic intact and sanitizes on read, for cases where the cluster is trusted but a specific downstream consumer or third party is not. |
| [Tenzir](https://tenzir.com) | Open — contributors welcome | Planned | Sanitizer operator for TQL pipelines, applied to selected fields. Likely via the Python or shell operator until a native operator exists. |
| [Onum](https://onum.com) (CrowdStrike) | Open — contributors welcome | Planned | Sanitizer action in an Onum pipeline, ahead of delivery to Falcon Next-Gen SIEM or any other destination. |
| [Vector](https://vector.dev) (Datadog) | Open — contributors welcome | Wanted | Sanitization stage in a Vector topology, via an `exec` transform or an HTTP round trip to a sanitizer sidecar. |
| [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/) | Open — contributors welcome | Wanted | Log record processor. The Collector is Go, so this is an external-processor or sidecar pattern rather than an in-process extension. |
| [Logstash](https://www.elastic.co/logstash) | Open — contributors welcome | Wanted | Filter stage. JRuby runtime means calling the Node CLI or a sanitizer service rather than embedding the library. |
| [Fluent Bit](https://fluentbit.io) | Open — contributors welcome | Wanted | Filter plugin. Needs either a WASM port of the rule engine or a sidecar; the Lua filter cannot host the library directly. |
| [Redpanda Connect](https://www.redpanda.com/connect) (Benthos) | Open — contributors welcome | Wanted | Processor in a Connect pipeline, using the `subprocess` or `http` processor against the CLI or a sanitizer service. |
| [Apache NiFi](https://nifi.apache.org) | Open — contributors welcome | Wanted | Custom processor or `ExecuteStreamCommand` wrapping the CLI, for flow-file content sanitization. |
| [Splunk Edge Processor / Ingest Processor](https://www.splunk.com/en_us/products/ingest-processor.html) | Open — contributors welcome | Wanted | Sanitization before data reaches the indexer. SPL2 pipelines do not currently accept custom code, so feasibility needs evaluation. |
| [Elastic ingest pipeline](https://www.elastic.co/guide/en/elasticsearch/reference/current/ingest.html) | Open — contributors welcome | Wanted | Index-time sanitization. Painless cannot host the library, so realistically this means sanitizing upstream in Logstash or a sidecar and documenting the pattern. |
| [Microsoft Sentinel DCR transformation](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-transformations) | Open — contributors welcome | Wanted | Sanitization before ingestion into Log Analytics. DCR transformations are KQL-only, so this needs an upstream agent or Azure Function approach. |
| [DataBahn](https://databahn.ai) | Open — contributors welcome | Wanted | Sanitizer stage in a DataBahn pipeline, ahead of any downstream destination. |
| [Observo AI](https://observo.ai) | Open — contributors welcome | Wanted | Sanitizer stage in an Observo pipeline, complementing its own reduction and routing. |
| [Axoflow / AxoSyslog](https://axoflow.com) | Open — contributors welcome | Wanted | Sanitization in an AxoSyslog / Axoflow pipeline before forwarding to a SIEM or object storage. |
| [Abstract Security](https://www.abstract.security) | Open — contributors welcome | Wanted | Sanitizer stage in an Abstract streaming pipeline ahead of routing to a lake or SIEM. |
| [VirtualMetric DataStream](https://virtualmetric.com) | Open — contributors welcome | Wanted | Sanitization stage in a DataStream pipeline before delivery to downstream destinations. |
| [Beacon](https://beacon.security/) | Open — contributors welcome | Wanted | Sanitization stage in a Beacon pipeline before delivery to downstream destinations. |

### Contributing an integration

Integrations live in their own repositories under their own maintainers; this table is just an index. To be listed, open a PR adding a row with a working link, and make sure the project:

- pins a released `@socprime/logtotal-sanitizer` version and states the minimum supported one
- reads the HMAC key from the host platform's secret store, never from a config file or
  a hardcoded default
- documents that token stability requires the same key, library version, and rule set
  across every node
- ships a synthetic sample for testing, with no real log data
