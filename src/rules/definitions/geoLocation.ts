import type { SanitizeRule } from '../../types';

function parseLatLonPair(match: string): { lat: number; lon: number } | null {
  const stripped = match.replace(/[()\s]/g, '');

  if (!/^-?\d+\.\d+[,;]-?\d+\.\d+$/.test(stripped)) {
    return null;
  }

  const [latStr, lonStr] = stripped.split(/[,;]/);
  const lat = Number(latStr);
  const lon = Number(lonStr);

  if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
    return null;
  }

  return { lat, lon };
}

function isPlausibleLatLon(lat: number, lon: number): boolean {
  if (lat === 0 && lon === 0) {
    return false;
  }

  return lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
}

function validateGeo(match: string): boolean {
  const pair = parseLatLonPair(match);

  if (pair) {
    return isPlausibleLatLon(pair.lat, pair.lon);
  }

  return true;
}

const LAT_KEY = '(?:latitude|lat)';
const LON_KEY = '(?:longitude|long|lon|lng)';
const ZIP_KEY = '(?:zipCode|postalCode|postcode|zip)';
const ADDR_KEY = '(?:addressLine1|address|street)';
const OLC = '[23456789CFGHJMPQRVWXcfghjmpqrvwx]';
const GEOHASH = '[0-9b-hjkmnp-zB-HJKMNP-Z]';

export const geoLocationRule: SanitizeRule = {
  id: 'geoLocation',
  label: 'Geo location',
  description:
    'Coordinates, geohashes, plus codes, postcodes and context-anchored addresses become a stable <GEO:…> token — the same value maps to the same token everywhere within a session.',
  mode: 'pseudo',
  token: 'GEO',
  patterns: [
    '(?:\\(\\s*-?\\d{1,3}\\.\\d{3,}\\s*[,;]\\s*-?\\d{1,3}\\.\\d{3,}\\s*\\))',
    '(?:(?<![\\d.])-?\\d{1,3}\\.\\d{3,}\\s*[,;]\\s*-?\\d{1,3}\\.\\d{3,}(?!\\d))',
    `(?:\\b${LAT_KEY}\\s*[=:]\\s*)(-?\\d{1,3}\\.\\d+)`,
    `(?:\\b${LON_KEY}\\s*[=:]\\s*)(-?\\d{1,3}\\.\\d+)`,
    `(?:\\bgeohash\\s*[=:]\\s*)(${GEOHASH}{5,12}\\b)`,
    `(?:(?<![\\w+])${OLC}{4,8}\\+${OLC}{2,3}(?![\\w+]))`,
    '(?:\\b\\d{1,3}°\\d{1,2}\'\\d{1,2}(?:\\.\\d+)?"[NSEW]\\b)',
    '(?:\\b[A-Za-z]{1,2}\\d{1,2}[A-Za-z]?\\s\\d[A-Za-z]{2}\\b)',
    `(?:\\b${ZIP_KEY}\\s*[=:]\\s*)(\\d{5}(?:-\\d{4})?\\b)`,
  ],
  aggressivePatterns: [
    '(?:\\(\\s*-?\\d{1,3}\\.\\d{2,}\\s*[,;]\\s*-?\\d{1,3}\\.\\d{2,}\\s*\\))',
    '(?:(?<![\\d.])-?\\d{1,3}\\.\\d{2,}\\s*[,;]\\s*-?\\d{1,3}\\.\\d{2,}(?!\\d))',
    `(?:(?<=\\b${ADDR_KEY}\\s*[=:]\\s*)[^\\n"'<>]{5,80})`,
  ],
  validate: validateGeo,
  jsonKeys: [
    'latitude',
    'longitude',
    'lat',
    'lon',
    'lng',
    'long',
    'coordinates',
    'coords',
    'geo',
    'streetAddress',
    'addressLine1',
    'addressLine2',
    'postalCode',
    'postcode',
    'zip',
    'zipCode',
    'geohash',
  ],
};
