# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
