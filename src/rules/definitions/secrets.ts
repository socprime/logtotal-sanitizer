import type { SanitizeRule } from '../../types';

const ENTROPY_THRESHOLD = 3.5;

function shannonEntropy(value: string): number {
  const { length } = value;

  if (length === 0) {
    return 0;
  }

  const freq: Record<string, number> = {};

  for (let i = 0; i < length; i += 1) {
    const char = value[i];
    freq[char] = (freq[char] ?? 0) + 1;
  }

  return Object.values(freq).reduce((entropy, count) => {
    const p = count / length;

    return entropy - p * Math.log2(p);
  }, 0);
}

function isHexBlob(match: string): boolean {
  return match.length >= 32 && /^[A-Fa-f0-9]+$/.test(match);
}

function isBase64Blob(match: string): boolean {
  return match.length >= 40 && /^[A-Za-z0-9+/]+=*$/.test(match);
}

function validateSecret(match: string): boolean {
  if (isHexBlob(match)) {
    return shannonEntropy(match) > ENTROPY_THRESHOLD;
  }

  if (isBase64Blob(match)) {
    return (
      shannonEntropy(match) > ENTROPY_THRESHOLD && /[A-Za-z]/.test(match) && /[0-9+/]/.test(match)
    );
  }

  return true;
}

const CONTEXT_KEYS =
  '(?:api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|secret[_-]?key|private[_-]?key|password|passwd|pwd|pass|auth[_-]?token|signing[_-]?key)';

const CONTEXT_VALUE = '[^\\s,;}"\']{4,}';

const CLI_FLAGS = '(?:password|secret|token|api-key|apikey|access-token|client-secret)';

export const secretsRule: SanitizeRule = {
  id: 'secrets',
  label: 'Tokens & credentials',
  description:
    'Bearer tokens, JWTs and API keys are redacted outright — they are not meant to be traced.',
  mode: 'mask',
  token: 'SECRET',
  patterns: [
    '(?:(?:Bearer|bearer|BEARER)\\s+)([A-Za-z0-9._\\-+/=]{8,})',
    '(?:(?:Basic|basic|BASIC)\\s+)([A-Za-z0-9+/]{8,}={0,2})',
    '(?:(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}(?:\\.[A-Za-z0-9_-]{8,})?)',
    '(?:-----BEGIN (?:(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY|CERTIFICATE)-----[A-Za-z0-9+/=\\s\\\\]+?-----END (?:(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY|CERTIFICATE)-----)',
    '(?:\\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\\b)',
    '(?:(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\\s*[=:]\\s*)([A-Za-z0-9/+=]{30,})',
    '(?:github_pat_[A-Za-z0-9_]{22,})',
    '(?:gh[pousr]_[A-Za-z0-9]{36,})',
    '(?:xox[abprs]-[A-Za-z0-9-]{10,})',
    '(?:hooks\\.slack\\.com/services/[A-Za-z0-9/_-]{16,})',
    '(?:AIza[A-Za-z0-9_-]{35})',
    '(?:(?:sk_live_|sk_test_|rk_live_|rk_test_)[A-Za-z0-9]{16,})',
    '(?:sk-proj-[A-Za-z0-9_-]{16,})',
    '(?:sk-[A-Za-z0-9]{20,})',
    // Kept as a lookbehind: `.{0,60}` asserts a nearby keyword rather than an adjacent prefix, so
    // one `Twilio` has to stay reusable by every identifier that follows it.
    '(?:(?<=(?:[Tt]wilio.{0,60}|\\b(?:[Aa]ccount[Ss]id|[Aa]uth[Tt]oken|[Ss]id)\\s*[=:]\\s*))(?:AC|SK)[0-9A-Fa-f]{32})',
    '(?:SG\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,})',
    '(?:npm_[A-Za-z0-9]{36,})',
    '(?:[?&][Ss]ig=)([^&\\s"\']{16,})',
    '(?:[a-zA-Z][a-zA-Z0-9+.-]*://)([^/@\\s:]+:[^/@\\s]+@)',
    `(?:--${CLI_FLAGS}(?:\\s+|=)"?)([^\\s"']{4,})`,
    `(?:\\b${CONTEXT_KEYS}"?\\s*[=:]\\s*"?)(${CONTEXT_VALUE})`,
  ],
  aggressivePatterns: [
    '(?:(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=]))',
    '(?:\\b[A-Fa-f0-9]{32,}\\b)',
  ],
  validate: validateSecret,
  jsonKeys: [
    'password',
    'token',
    'authorization',
    'apiKey',
    'secret',
    'accessToken',
    'refreshToken',
    'passwd',
    'pwd',
    'pass',
    'clientSecret',
    'privateKey',
    'secretKey',
    'apiSecret',
    'credentials',
    'auth',
    'xApiKey',
    'idToken',
    'awsSecretAccessKey',
    'signature',
  ],
};
