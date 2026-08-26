import type { SanitizeRule } from '../../types';

const COOKIE_VALUE = '[^;\\s]{8,}';

export const sessionCookiesRule: SanitizeRule = {
  id: 'sessionCookies',
  label: 'Session cookies',
  description: 'Session identifiers (sessionid, sid, JSESSIONID, PHPSESSID) are redacted outright.',
  mode: 'mask',
  token: 'SESSION',
  patterns: [
    `(?:(?<![\\w-])(?:[Ss]essionid|[Ss]ession_id|sessionId|SESSIONID)=${COOKIE_VALUE})`,
    `(?:(?<![\\w-])sid=${COOKIE_VALUE})`,
    `(?:PHPSESSID=${COOKIE_VALUE})`,
    `(?:JSESSIONID=${COOKIE_VALUE})`,
    `(?:ASP\\.NET_SessionId=${COOKIE_VALUE})`,
    `(?:ASPSESSIONID[A-Za-z0-9]*=${COOKIE_VALUE})`,
    `(?:connect\\.sid=${COOKIE_VALUE})`,
    `(?:laravel_session=${COOKIE_VALUE})`,
    `(?:_session_id=${COOKIE_VALUE})`,
    `(?:(?:csrftoken|csrf_token|XSRF-TOKEN|xsrf-token)=${COOKIE_VALUE})`,
    `(?:remember_token=${COOKIE_VALUE})`,
    `(?:(?:SSESS|SESS)[A-Fa-f0-9]{32}=${COOKIE_VALUE})`,
    `(?:[Ss]et-[Cc]ookie:\\s*)([^;=\\s]+=${COOKIE_VALUE})`,
  ],
  aggressivePatterns: [
    `(?:(?<![\\w-])[\\w-]*session[\\w-]*=${COOKIE_VALUE})`,
    `(?:(?<![\\w-])[\\w-]*token=${COOKIE_VALUE})`,
  ],
  jsonKeys: ['sessionId', 'sid', 'cookie', 'cookies', 'setCookie', 'jsessionid', 'csrfToken'],
};
