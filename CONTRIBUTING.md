# Contributing

This package is a regex + HMAC redaction engine. Public behaviour lives in `README.md`. This document is for people changing the engine or adding a rule.

## Layout

| Path                    | Role                                                                                       |
| ----------------------- | ------------------------------------------------------------------------------------------ |
| `src/core`              | Compile one `RegExp` per pattern fragment, walk each line, HMAC tokens, reports, streaming |
| `src/rules/definitions` | Built-in rules (data + `validate`)                                                         |
| `src/rules/shared`      | Shared validators (Luhn, Shannon entropy)                                                  |
| `src/io`                | Web-standard sources/sinks                                                                 |
| `src/node`              | `node:fs` / `node:stream` adapters                                                         |
| `src/cli.ts`            | `logtotal-sanitize`                                                                        |

The root export must not import `node:*`.

## How a line is redacted

1. `compileRules` compiles every fragment of each selected rule's `patterns` (and `aggressivePatterns` when `aggressive` is true) into its own regex, plus one cheaper per-rule gate that is a language-superset of the rule's precise patterns. A capturing group in a fragment marks the value to replace; without one, the whole match is the value.
2. Rule order, then fragment order, is priority. If two fragments match at the same _value_ offset, the earlier one wins.
3. `redactLine` keeps one live match per fragment of every rule that passes its gate, and repeatedly takes the leftmost. Fragments are never merged into one alternation: a fragment whose consumed prefix starts earlier would otherwise pre-empt a higher-priority fragment at the same value offset.
4. `validate` returning `false`, or a `neverRedact` hit, leaves the text unchanged and still occupies that value span. A later match that would have started _inside_ the skipped span is not retried. That is intentional (shadowing). Fragments that overshot the span rewind to its end, so a shorter match hidden inside a longer one is still reachable.
5. Lines that look like JSON (`{` / `[` after trim) go through `redactJsonLine`: `jsonKeys` redact by field name, other strings still use `redactLine`.
6. Replacement is HMAC-SHA-256(`ruleId || NUL || original`) truncated to 16 hex chars. `mask` uses prefix `R`; `pseudo` uses `rule.token`.

`alwaysRedact` is injected as rule id `custom` in front of the selected list. `neverRedact` is checked before replacement and beats every rule.

## Adding a built-in rule

1. `id` must match `/^[A-Za-z_$][A-Za-z0-9_$]*$/`.
2. At most one capturing group per fragment; it marks the value to replace (so a consumed prefix such as `/home/(user)` is kept). Named groups are not allowed. Prefer a consumed prefix over a positive lookbehind — JavaScriptCore evaluates lookbehind-led patterns far slower. Keep the lookbehind when the two are not equivalent: when the prefix asserts a nearby keyword rather than adjacent text (`(?<=Twilio.{0,60})`), so one keyword can serve several values, or when the value's character class overlaps the prefix's trailing quantifier, which makes the split ambiguous.
3. Prefer a tight regex plus `validate` (Luhn, allowlists, entropy) over a greedy pattern.
4. Put the file in `src/rules/definitions/` and append it to `builtinRules` in `src/rules/registry.ts` at the right priority: specific credential-shaped rules before broad identifiers.
5. Add `jsonKeys` when JSON field names should redact regardless of value shape.
6. Add cases in `tests/` that the rule _must_ redact and cases it _must not_ (false positives: versions, UUIDs used as ids, loopback, `uid=0(root)`).
7. Do not add comments in implementation files. Public TSDoc belongs only on symbols re-exported from `src/index.ts`, `src/node/index.ts`, and `src/rules/index.ts`.

## Development

```bash
npm install
npm test
npm run typecheck
npm run bench
npm run build
npm run verify:pack
```
