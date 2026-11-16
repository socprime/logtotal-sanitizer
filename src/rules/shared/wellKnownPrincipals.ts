const PRINCIPAL_NAMES = new Set([
  'SYSTEM',
  'LOCAL SERVICE',
  'NETWORK SERVICE',
  'NT AUTHORITY',
  'NT AUTHORITY\\SYSTEM',
  'NT AUTHORITY\\LOCAL SERVICE',
  'NT AUTHORITY\\NETWORK SERVICE',
  '\\LOCAL SERVICE',
  '\\NETWORK SERVICE',
  'ANONYMOUS LOGON',
  'LOCAL SYSTEM',
  'WINDOW MANAGER',
  'FONT DRIVER HOST',
]);

const PRINCIPAL_SIDS = new Set(['S-1-5-18', 'S-1-5-19', 'S-1-5-20', 'S-1-1-0', 'S-1-5-7']);

const DWM_RE = /^DWM-\d+$/i;
const UMFD_RE = /^UMFD-\d+$/i;

export function isWellKnownPrincipal(value: string): boolean {
  const trimmed = value.trim();

  if (trimmed.length === 0) {
    return false;
  }

  const upper = trimmed.toUpperCase();

  if (PRINCIPAL_NAMES.has(upper)) {
    return true;
  }

  if (PRINCIPAL_SIDS.has(trimmed.toUpperCase())) {
    return true;
  }

  if (DWM_RE.test(trimmed) || UMFD_RE.test(trimmed)) {
    return true;
  }

  return false;
}
