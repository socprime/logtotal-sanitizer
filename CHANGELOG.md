# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2-beta.0] - 2026-11-16

### Added

- CSV path via `csv: true` or `{ delimiter?, header?, hasHeader? }`. The header row is copied
  unchanged. Columns are classified with the ECS-aware JSON key matcher (a trailing `.keyword`,
  `.text`, or `.raw` is ignored). `ips` columns are regex-scanned inside the cell; other typed
  columns replace the whole cell; remaining columns are regex-scanned, and JSON cells use the JSON
  path. `-` and empty cells are kept. Rows whose field count differs from the header are
  regex-scanned and counted in `report.csv.misalignedRows`. `report.csv.columns` lists
  `{ name, action, ruleId }`. User and host values from typed columns are remembered for the rest
  of the run and replaced in later free-text cells.
- `keepPrivateIps` and CLI `--keep-private-ips`. RFC 1918 IPv4 addresses (`10/8`, `172.16/12`,
  `192.168/16`), including IPv4-mapped IPv6, reverse-DNS PTR names, and `ip:port`, stay unchanged
  on every path.
- CLI `--format auto|lines|csv` (default `auto`). `auto` selects the CSV path for `.csv` and `.tsv`
  inputs; a `.tsv` path uses a tab delimiter. Stdin stays in line mode unless `--format csv` is set.
- `readCsvHeader(blob, { delimiter?, maxBytes? })` returns the header names so parallel workers
  can run shard 0 with `csv: true` and later shards with `csv: { header }`. The blob is read in
  64 KiB steps (default cap 4 MiB). A leading UTF-8 BOM is removed.
- ECS field hints for JSON keys and CSV columns (`user.effective.name`, `dns.question.name`,
  `agent.name`, `related.*`, `winlog.event_data` Target/Subject fields, `*.nat.ip`, and similar).
- `hosts` rule: internal suffixes `lab`, `priv`, `private`, `dmz`, and `intra`, case-insensitive.

### Changed

- Well-known Windows principals (`SYSTEM`, `NT AUTHORITY`, `LOCAL SERVICE`, `NETWORK SERVICE`,
  `S-1-5-18`, and similar) are never key-redacted.
- Machine accounts keep the trailing `$`. `WKS-0042$` becomes `<USER:…>$`, the same token as
  `WKS-0042`.
- ECS field paths such as `host.name`, `user.id`, and `agent.id` are no longer detected as FQDNs.
- Explicitly non-sensitive ECS fields are not key-redacted: `event.*`, `*.version`, `host.os.name`,
  `process.name`, and leaves ending in `_count`, `_age`, `_time`, `_bytes`, `_ms`, or `_ns`.

### Fixed

- CSV export header names were sanitized as if they were log text. The header row is now preserved.
- Domains under the internal `.lab` suffix were missed by the `hosts` rule.
- `relative_password_age` was key-redacted as a secret because the name contains `password`. Leaves
  that end in `_age` (and the other non-sensitive suffixes) are left unchanged.

## [0.2.1-beta.0] - 2026-10-14

### Fixed

- JSON field redaction now applies to lines that are not a whole JSON document: pretty-printed
  records, JSON embedded in a text line (`body="{\"password\":\"…\"}"`) and Python dict reprs.
  Values of `"key": value` pairs whose key belongs to a rule are replaced by name, as in
  single-line JSON. Previously, a pretty-printed record leaked `ssn`, `passport_number`, `iban`,
  `cvv`, `diagnosis` and similar fields whose values fail the plain-text checksums.
- Numeric values of sensitive keys (`"latitude": 48.1486`, `"pan": 4111111111111111`) are replaced
  with a string token instead of being left as is.
- Array items inherit the key of their array, so `"emails": [...]` and GeoJSON
  `"coordinates": [...]` are redacted.
- `hosts` rule: the reserved `.test`, `.invalid` and `.localhost` TLDs are recognized.

### Changed

- JSON key matching also ignores `.` and spaces, and tries a nested field together with its
  parent's name (`user` + `name`, `client` + `ip`, `source` + `address`) before the field's own
  name. Dotted flat keys (`"source.ip"`) resolve the same way.
- In a pretty-printed record, a field named in `jsonKeys` is now replaced as a whole, the same
  way the single-line form already was. For example, `"User": "CORP\\jdoe"` becomes one `USER`
  token instead of a `HOST` and a `USER` token.
- Key resolution is memoized per rule set, with a bounded cache.
- Expanded `jsonKeys` and `jsonKeyContains` for every built-in rule with field names used by ECS,
  AWS CloudTrail, Azure sign-in logs, Windows events, CEF, Datadog and common application logs:
  cloud and API credentials, session and CSRF cookies, card, bank and wallet fields, national
  identifiers (PESEL, rodné číslo, CPF, Aadhaar, РНОКПП and others), clinical fields, phone and
  telephony fields, source, destination and forwarded IPs, workstation, SNI and DNS query hosts,
  mail and actor identities, and street addresses.

## [0.2.0-beta.3] - 2026-09-23

### Fixed

- JSON replacement context: `report.contextChars` for values redacted by `jsonKeys` or
  `jsonKeyContains` now locates the quoted JSON value instead of the first bare
  substring.

## [0.2.0-beta.2] - 2026-09-21

### Fixed

- JSON field redaction: Windows placeholder values (`""` and `"-"`) are left unchanged instead
  of being replaced with a token.
- `users` rule: `DOMAIN\user` is now also matched when the separator is JSON-escaped
  (`"User": "CORP\\jdoe"`), so accounts in pretty-printed JSON that never parses line by line are
  redacted. The account segment gets the same token as the plain-text form.
- `hosts` rule: quoted JSON host fields (`"Computer": "box1"`, `"SubjectDomainName": "CORP"`) are
  matched by key name, case- and `-`/`_`-insensitive. The plain-text `computer=` pattern only
  matched lowercase keys with no quote between the key and the separator.
- `hosts` rule: the domain half of a quoted `"DOMAIN\account"` value becomes a `HOST` token, so a
  workstation name correlates with the same name in a `Computer` field. Anchored on both quotes,
  and guarded by the well-known-domain and filename exclusions the `users` rule already uses, so
  path segments such as `"System32\cmd.exe"` are left alone.
- `hosts` rule: UNC computer names are also matched when the separators are JSON-escaped
  (`"\\\\FILESRV01\\share"`).

## [0.2.0-beta.1] - 2026-09-15

### Added

- `jsonKeyContains` on `SanitizeRule`: JSON field names are matched when the normalized key
  contains a fragment, after an exact `jsonKeys` miss. The first active rule wins.
- `hosts` rule: `computer` in `jsonKeys`, plus `jsonKeyContains` for `computer` and `domainname`
  (covers Windows Event fields such as `Computer`, `SubjectDomainName`, `TargetDomainName`).
- `users` rule: `jsonKeyContains` for `owner` and `username` (covers `jobOwner`,
  `SubjectUserName`, `TargetUserName`, and similar).

## [0.2.0-beta.0] - 2026-09-07

### Added

- `mergeReports` combines reports from disjoint, ordered ranges of the same input: counts and
  line totals are summed, distinct replacements are merged by `(ruleId, original)`, and preview
  segments are concatenated until `previewBytes`.
- `planLineAlignedRanges` splits a `Blob` / `File` into newline-aligned byte ranges so callers can
  sanitize parts concurrently and concatenate the outputs.
- `report.maxReplacementsPerRule` caps distinct original values stored per rule. Counts stay
  complete; `replacementsTruncated` is set when the cap drops at least one value. Unset by
  default, so CLI `--report json` still dumps the full list.
- `sanitizeStream` accepts a per-run `previewBytes` override so one sanitizer can collect a
  preview from only the first range.

### Changed

- Most positive lookbehind fragments now consume their prefix and capture only the value to redact.
  JavaScriptCore (Safari) evaluates lookbehind-led alternatives about 15× slower than V8; this
  rewrite is equivalent on value spans and is faster in both engines. Two fragments keep their
  lookbehind because consumption would not be equivalent there.
- Patterns are compiled one regex per fragment, behind a cheap per-rule prefilter, instead of a
  single combined pattern. Match selection is unchanged: the leftmost value wins, and ties go to
  the earlier rule and then the earlier fragment.
- Sanitizing 1 MB of Windows PowerShell logs is about 4.9× faster under JavaScriptCore and about
  1.6× faster under V8. Output is byte-identical: verified against the previous implementation on
  318k real log lines and 1.8M generated adversarial lines across every rule, both modes, JSON
  mode, allowlists and segment reporting.
- The CLI skips collecting the replacement list and preview unless `--report` is JSON, so a
  normal run no longer pays for detail it never prints.

## [0.0.1-beta.3] - 2026-08-26

### Fixed

- JSON preview `before` segments now highlight values redacted via `jsonKeys`, not only regex
  matches. Fields such as `UserName` were replaced in the output (and highlighted in `after`) but
  left unmarked on the left-hand preview.

## [0.0.1-beta.2] - 2026-08-25

### Changed

- README now describes the intended use: sanitize logs locally before they leave the environment,
  including LogTotal in-browser integration and self-hosted or air-gapped deployments.

## [0.0.1-beta.1] - 2026-08-25

### Added

- The `hosts` rule redacts the host field in BSD syslog and ISO-8601 syslog lines, so short names
  such as `srv-app-01` become the same token as FQDNs.
- Aggressive mode for `hosts` also matches inventory-style short names (`srv-`, `web-`, `db-`,
  `app-`, `host-`, `node-`, `pod-` prefixes with a numeric suffix).

## [0.0.1-beta.0]

### Added

- Initial beta release.
- Isomorphic sanitization engine: single combined pattern per run, line-by-line processing,
  HMAC-SHA-256 pseudonymization with stable tokens.
- Eleven built-in rules: `secrets`, `sessionCookies`, `paymentInfo`, `govIds`, `healthInfo`,
  `phoneNumbers`, `ips`, `hosts`, `users`, `geoLocation`, `paths`.
- Custom rule support through `defineRule` and the `rules` / `extraRules` options.
- `alwaysRedact` for values and patterns that must be redacted regardless of the active rules,
  and `neverRedact` for allowlisting values globally, by pattern, or per rule.
- JSON Lines awareness: field names listed in a rule's `jsonKeys` are redacted by name.
- Streaming API with injectable sources and sinks, plus `AbortSignal` support.
- Node entry point (`@socprime/logtotal-sanitizer/node`) with file and stream helpers.
- Dual ESM/CJS build with type declarations for both module systems.
