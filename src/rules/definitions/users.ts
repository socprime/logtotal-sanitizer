import type { SanitizeRule } from '../../types';

const EMAIL_LOCAL = '[A-Za-z0-9._%+-]+';
const EMAIL_DOMAIN = '[A-Za-z0-9.-]+\\.[A-Za-z]{2,}';
const EMAIL = `(?:\\b${EMAIL_LOCAL}@${EMAIL_DOMAIN})`;
const EMAIL_IP_LITERAL = `(?:\\b${EMAIL_LOCAL}@\\[[0-9a-fA-F.:]+\\])`;

const WIN_DOMAIN_EXCLUDE = '(?:BUILTIN|NT SERVICE|NT AUTHORITY|Users|Settings|Files)\\\\';
const USER_SEG_SIMPLE = '[A-Za-z0-9_](?:[A-Za-z0-9_.$-]*[A-Za-z0-9$])';

const FILE_EXT = 'exe|dll|sys|bat|cmd|ps1|vbs|msi|tmp|hiv|log|dat|txt|ini|xml|json|lnk|cpl|ocx|drv';
const NOT_FILENAME = `(?![A-Za-z0-9_$.-]*\\.(?:${FILE_EXT})(?![A-Za-z0-9]))`;
const NOT_GUID = '(?![0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-)';
const ACCOUNT_END = '(?![A-Za-z0-9_$\\\\/-])';

const PATH_ROOT = '(?:\\b(?:HKLM|HKCU|HKU|HKCR|HKEY_[A-Z_]+)|\\b[A-Za-z]:)\\\\';
const NOT_UNDER_PATH_ROOT = `(?<!${PATH_ROOT}(?:(?! [-/])[^<>'"\\n])*)`;
const DOMAIN_USER = `(?:(?:(?:^|[^\\\\.-])\\b[A-Za-z0-9](?:[A-Za-z0-9.-]{0,13}[A-Za-z0-9])?\\\\)(?<!${WIN_DOMAIN_EXCLUDE})${NOT_FILENAME}${NOT_GUID}(${USER_SEG_SIMPLE})${ACCOUNT_END}${NOT_UNDER_PATH_ROOT})`;

const SID = '(?:\\bS-1-(?:\\d+-){1,14}\\d+\\b)';

const VALUE_WITH_LETTER = '[\\w.@+-]*[A-Za-z][\\w.@+-]*';
const LDAP_DN_SINGLE = `(?:\\b(?:uid|sAMAccountName)=)(${VALUE_WITH_LETTER})`;
const CN_VALUE = "(?:[A-Za-z0-9.'-]+(?: [A-Za-z0-9.'-]+){0,3})";
const LDAP_DN_CN = `(?:\\bcn=)(${CN_VALUE})`;

const ARN_USER = '(?::user/)([\\w.@+=,-]+)';
const ARN_ASSUMED_ROLE_SESSION = '(?::assumed-role/[\\w+=,.@-]+/)([\\w.@+=,-]+)';

const K8S_SERVICE_ACCOUNT = '(?:\\bsystem:serviceaccount:[A-Za-z0-9-]+:)([A-Za-z0-9-]+)';

const SSHD_FOR_USER = '(?:(?:\\bfor (?:invalid )?user|\\b[Ii]nvalid user)\\s+)([A-Za-z0-9._-]+)';
const SSHD_RUSER = '(?:\\bruser=)([A-Za-z0-9._-]+)';
const SSHD_LOGNAME = '(?:\\blogname=)([A-Za-z0-9._-]+)';
const SUDO_USER = '(?:\\bsudo:\\s+)([A-Za-z0-9._-]+)(?=\\s+:)';

const GENERIC_KEY =
  '(?:user|username|login|account|owner|actor|principal|requester|createdBy|modifiedBy|assignee|operator)';
const GENERIC_CTX = `(?:\\b${GENERIC_KEY}\\s*[=:]\\s*)(${VALUE_WITH_LETTER})`;

const SLACK_USER_ID_AGGRESSIVE = '(?:\\bU[A-Z0-9]{8,10}\\b)';

const SYSTEM_ACCOUNTS = new Set([
  'root',
  'system',
  'daemon',
  'nobody',
  'www-data',
  'nginx',
  'sshd',
  'syslog',
]);

function isWellKnownWindowsAccount(match: string): boolean {
  const upper = match.toUpperCase();

  if (upper === 'SYSTEM' || upper === 'LOCAL' || upper === 'NETWORK' || upper === 'ANONYMOUS') {
    return true;
  }

  return match.endsWith('$');
}

function isWellKnownSid(match: string): boolean {
  if (match === 'S-1-1-0') {
    return true;
  }

  if (/^S-1-5-(?:18|19|20)$/.test(match)) {
    return true;
  }

  return /^S-1-5-32-\d+$/.test(match);
}

function validateUser(match: string): boolean {
  if (isWellKnownWindowsAccount(match)) {
    return false;
  }

  if (isWellKnownSid(match)) {
    return false;
  }

  return !SYSTEM_ACCOUNTS.has(match.toLowerCase());
}

export const usersRule: SanitizeRule = {
  id: 'users',
  label: 'Usernames & emails',
  description:
    'Email addresses and account identifiers (DOMAIN\\user, SIDs, ARNs, LDAP DNs, sshd/PAM context) become the same token everywhere within a session.',
  mode: 'pseudo',
  token: 'USER',
  patterns: [
    EMAIL_IP_LITERAL,
    EMAIL,
    DOMAIN_USER,
    SID,
    LDAP_DN_SINGLE,
    LDAP_DN_CN,
    ARN_USER,
    ARN_ASSUMED_ROLE_SESSION,
    K8S_SERVICE_ACCOUNT,
    SSHD_FOR_USER,
    SSHD_RUSER,
    SSHD_LOGNAME,
    SUDO_USER,
    GENERIC_CTX,
  ],
  aggressivePatterns: [SLACK_USER_ID_AGGRESSIVE],
  validate: validateUser,
  jsonKeys: [
    'email',
    'username',
    'user',
    'emailAddress',
    'mail',
    'userEmail',
    'user_name',
    'login',
    'account',
    'samAccountName',
    'userPrincipalName',
    'upn',
    'actor',
    'principal',
    'owner',
    'createdBy',
    'modifiedBy',
    'firstName',
    'lastName',
    'fullName',
    'displayName',
    'givenName',
    'surname',
    'userId',
    'uid',
  ],
};
