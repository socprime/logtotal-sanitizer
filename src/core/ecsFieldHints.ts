export function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[-_.\s]/g, '');
}

export const ECS_EXPLICIT_NONE = 'none' as const;

export type EcsHint = string | typeof ECS_EXPLICIT_NONE | undefined;

const MULTI_FIELD_LEAVES = new Set(['keyword', 'text', 'raw']);

const HOST_DOMAIN_SOURCES = new Set([
  'source',
  'destination',
  'client',
  'server',
  'url',
  'host',
  'observer',
]);

const NON_SENSITIVE_PATHS = new Set(
  ['host.os.name', 'os.name', 'process.name', 'process.parent.name', 'dll.name', 'file.name'].map(
    (path) => normalizeKey(path),
  ),
);

const NON_SENSITIVE_LEAF_SUFFIXES = ['_age', '_count', '_time', '_bytes', '_ms', '_ns'] as const;

const WINLOG_USER_LEAVES = new Set(['targetusername', 'subjectusername']);
const WINLOG_HOST_LEAVES = new Set(['targetdomainname', 'subjectdomainname', 'workstationname']);
const WINLOG_IP_LEAVES = new Set(['ipaddress']);

const USER_IDENTITY_LEAVES = new Set(['name', 'id', 'fullname']);

function leafNorm(leaf: string): string {
  return normalizeKey(leaf);
}

function pathNorm(segments: readonly string[]): string {
  return segments.map((segment) => normalizeKey(segment)).join('');
}

function hasUserSegment(segments: readonly string[]): boolean {
  return segments.some((segment) => {
    const lower = segment.toLowerCase();
    return lower === 'user' || lower.endsWith('user');
  });
}

export function splitFieldPath(
  key: string,
  parent?: string,
): { segments: string[]; leaf: string; dotted: string } {
  let dotted: string;
  let segments: string[];

  if (key.includes('.')) {
    dotted = key;
    segments = key.split('.');
  } else if (parent !== undefined && parent.length > 0) {
    dotted = `${parent}.${key}`;
    segments = dotted.split('.');
  } else {
    dotted = key;
    segments = [key];
  }

  const multi = segments.at(-1)?.toLowerCase();

  if (multi !== undefined && MULTI_FIELD_LEAVES.has(multi)) {
    segments = segments.slice(0, -1);
    dotted = segments.join('.');
  }

  const leaf = segments.at(-1) ?? '';

  return { segments, leaf, dotted };
}

function isExplicitNonSensitive(segments: readonly string[], leaf: string): boolean {
  const dottedNorm = pathNorm(segments);

  if (NON_SENSITIVE_PATHS.has(dottedNorm)) {
    return true;
  }

  if (segments[0] === 'event') {
    return true;
  }

  if (leafNorm(leaf) === 'version') {
    return true;
  }

  const leafLower = leaf.toLowerCase();

  return NON_SENSITIVE_LEAF_SUFFIXES.some((suffix) => leafLower.endsWith(suffix));
}

function winlogHint(segments: readonly string[], leaf: string): EcsHint {
  const winlogIdx = segments.findIndex((segment) => segment.toLowerCase() === 'winlog');

  if (winlogIdx === -1) {
    return undefined;
  }

  const rest = segments.slice(winlogIdx + 1).map((segment) => segment.toLowerCase());
  const inEventData =
    rest[0] === 'event_data' || rest.join('.').includes('event_data') || rest.includes('eventdata');

  if (!inEventData) {
    return undefined;
  }

  const leafKey = leafNorm(leaf);

  if (WINLOG_USER_LEAVES.has(leafKey)) {
    return 'users';
  }

  if (WINLOG_HOST_LEAVES.has(leafKey)) {
    return 'hosts';
  }

  if (WINLOG_IP_LEAVES.has(leafKey)) {
    return 'ips';
  }

  return undefined;
}

function relatedHint(segments: readonly string[], leaf: string): EcsHint {
  if (segments.length < 2 || segments[0]?.toLowerCase() !== 'related') {
    return undefined;
  }

  const leafKey = leafNorm(leaf);

  if (leafKey === 'user') {
    return 'users';
  }

  if (leafKey === 'hosts') {
    return 'hosts';
  }

  if (leafKey === 'ip') {
    return 'ips';
  }

  return undefined;
}

function dnsHint(segments: readonly string[], leaf: string): EcsHint {
  const leafKey = leafNorm(leaf);

  if (leafKey === 'resolvedip') {
    return 'ips';
  }

  const dnsIdx = segments.findIndex((segment) => segment.toLowerCase() === 'dns');

  if (dnsIdx === -1) {
    return undefined;
  }

  const afterDns = segments.slice(dnsIdx + 1).map((segment) => segment.toLowerCase());

  if (afterDns[0] === 'question' && (leafKey === 'name' || leafKey === 'registereddomain')) {
    return 'hosts';
  }

  if (leafKey === 'resolvedip' && afterDns.length > 0) {
    return 'ips';
  }

  return undefined;
}

function staticHostPaths(segments: readonly string[], leaf: string): EcsHint {
  const leafKey = leafNorm(leaf);

  if (leafKey !== 'name' && leafKey !== 'hostname') {
    return undefined;
  }

  const head = segments[0]?.toLowerCase();

  if (head === 'agent' || head === 'observer') {
    return 'hosts';
  }

  return undefined;
}

function prefixSuffixRules(segments: readonly string[], leaf: string): EcsHint {
  const leafKey = leafNorm(leaf);
  const head = segments[0]?.toLowerCase();
  const last = segments.at(-1)?.toLowerCase() ?? '';

  if (head !== undefined && HOST_DOMAIN_SOURCES.has(head)) {
    if (leafKey === 'domain' || leafKey === 'registereddomain') {
      return 'hosts';
    }

    if (leafKey === 'ip') {
      return 'ips';
    }

    if (leafKey === 'mac') {
      return 'ips';
    }
  }

  if (
    leafKey === 'ip' &&
    last === 'ip' &&
    segments.some((segment) => segment.toLowerCase() === 'nat')
  ) {
    return 'ips';
  }

  if (leafKey === 'forwardedip' && segments[0]?.toLowerCase() === 'network') {
    return 'ips';
  }

  return undefined;
}

function userContextHint(segments: readonly string[], leaf: string): EcsHint {
  if (!hasUserSegment(segments)) {
    return undefined;
  }

  const leafKey = leafNorm(leaf);

  if (USER_IDENTITY_LEAVES.has(leafKey)) {
    return 'users';
  }

  if (leafKey === 'domain') {
    return 'hosts';
  }

  return undefined;
}

export function resolveEcsFieldHint(
  key: string,
  parent: string | undefined,
  activeRuleIds: ReadonlySet<string>,
): EcsHint {
  const { segments, leaf } = splitFieldPath(key, parent);

  if (segments.length === 0 || leaf.length === 0) {
    return undefined;
  }

  if (isExplicitNonSensitive(segments, leaf)) {
    return ECS_EXPLICIT_NONE;
  }

  const candidates: Array<EcsHint | undefined> = [
    relatedHint(segments, leaf),
    dnsHint(segments, leaf),
    staticHostPaths(segments, leaf),
    winlogHint(segments, leaf),
    prefixSuffixRules(segments, leaf),
    userContextHint(segments, leaf),
  ];

  for (const candidate of candidates) {
    if (candidate === undefined) {
      continue;
    }

    if (candidate === ECS_EXPLICIT_NONE) {
      return ECS_EXPLICIT_NONE;
    }

    if (activeRuleIds.has(candidate)) {
      return candidate;
    }
  }

  return undefined;
}
