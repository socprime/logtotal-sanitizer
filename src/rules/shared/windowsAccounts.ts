export const BACKSLASH = '\\\\';

export const JSON_BACKSLASH = '\\\\\\\\';

export const WINDOWS_FILE_EXT =
  'exe|dll|sys|bat|cmd|ps1|vbs|msi|tmp|hiv|log|dat|txt|ini|xml|json|lnk|cpl|ocx|drv';

export const NOT_WINDOWS_FILENAME = `(?![A-Za-z0-9_$.-]*\\.(?:${WINDOWS_FILE_EXT})(?![A-Za-z0-9]))`;

export const WELL_KNOWN_DOMAIN = '(?:BUILTIN|NT SERVICE|NT AUTHORITY|Users|Settings|Files)';

export const NETBIOS_DOMAIN = '[A-Za-z0-9](?:[A-Za-z0-9.-]{0,13}[A-Za-z0-9])?';

export const ACCOUNT_SEGMENT = '[A-Za-z0-9_](?:[A-Za-z0-9_.$-]*[A-Za-z0-9$])';
