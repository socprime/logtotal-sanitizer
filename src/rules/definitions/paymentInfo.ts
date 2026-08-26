import { sha256 } from '../shared/hmacSha256';
import type { SanitizeRule } from '../../types';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function luhnCheck(digits: string): boolean {
  if (!/^\d{13,19}$/.test(digits) || /^0+$/.test(digits)) {
    return false;
  }

  let sum = 0;
  let doubleIt = false;

  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let digit = Number(digits[i]);

    if (doubleIt) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    doubleIt = !doubleIt;
  }

  return sum % 10 === 0;
}

function ibanMod97(iban: string): boolean {
  const compact = iban.replace(/\s/g, '').toUpperCase();

  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(compact)) {
    return false;
  }

  const rearranged = compact.slice(4) + compact.slice(0, 4);
  const numeric = rearranged.replace(/[A-Z]/g, (char) => String(char.charCodeAt(0) - 55));
  let remainder = 0;

  for (let i = 0; i < numeric.length; i += 1) {
    remainder = (remainder * 10 + Number(numeric[i])) % 97;
  }

  return remainder === 1;
}

const IBAN_COUNTRY_CODES = new Set([
  'AD',
  'AE',
  'AL',
  'AO',
  'AT',
  'AZ',
  'BA',
  'BE',
  'BF',
  'BG',
  'BH',
  'BI',
  'BJ',
  'BR',
  'BY',
  'CF',
  'CG',
  'CH',
  'CI',
  'CM',
  'CR',
  'CV',
  'CY',
  'CZ',
  'DE',
  'DJ',
  'DK',
  'DO',
  'DZ',
  'EE',
  'EG',
  'ES',
  'FI',
  'FO',
  'FR',
  'GA',
  'GB',
  'GE',
  'GI',
  'GL',
  'GQ',
  'GR',
  'GT',
  'GW',
  'HN',
  'HR',
  'HU',
  'IE',
  'IL',
  'IQ',
  'IR',
  'IS',
  'IT',
  'JO',
  'KM',
  'KW',
  'KZ',
  'LB',
  'LC',
  'LI',
  'LT',
  'LU',
  'LV',
  'LY',
  'MA',
  'MC',
  'MD',
  'ME',
  'MG',
  'MK',
  'ML',
  'MR',
  'MT',
  'MU',
  'MZ',
  'NE',
  'NI',
  'NL',
  'NO',
  'PK',
  'PL',
  'PS',
  'PT',
  'QA',
  'RO',
  'RS',
  'RU',
  'SA',
  'SC',
  'SD',
  'SE',
  'SI',
  'SK',
  'SM',
  'SN',
  'ST',
  'SV',
  'TD',
  'TG',
  'TL',
  'TN',
  'TR',
  'UA',
  'VA',
  'VG',
  'XK',
]);

function isIbanCountry(compact: string): boolean {
  return IBAN_COUNTRY_CODES.has(compact.slice(0, 2).toUpperCase());
}

function isHexHashLength(value: string): boolean {
  return /^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$/.test(value);
}

function isCardSeparatorLayout(match: string): boolean {
  if (!/[ -]/.test(match)) {
    return true;
  }

  const groups = match.split(/[ -]/).map((group) => group.length);

  if (groups.some((length) => length === 0)) {
    return false;
  }

  if (
    groups.length === 3 &&
    groups[0] === 4 &&
    groups[1] === 6 &&
    (groups[2] === 4 || groups[2] === 5)
  ) {
    return true;
  }

  const last = groups[groups.length - 1];

  return (
    groups.length >= 2 &&
    groups.slice(0, -1).every((length) => length === 4) &&
    last >= 1 &&
    last <= 7
  );
}

function bitcoinBase58Check(address: string): boolean {
  const decoded = decodeBase58(address);

  if (!decoded || decoded.length < 5) {
    return false;
  }

  const payload = decoded.subarray(0, decoded.length - 4);
  const checksum = decoded.subarray(decoded.length - 4);
  const digest = sha256(sha256(payload));

  return (
    digest[0] === checksum[0] &&
    digest[1] === checksum[1] &&
    digest[2] === checksum[2] &&
    digest[3] === checksum[3]
  );
}

function decodeBase58(input: string): Uint8Array | null {
  const bytes: number[] = [0];

  for (let i = 0; i < input.length; i += 1) {
    let carry = BASE58_ALPHABET.indexOf(input[i]);

    if (carry === -1) {
      return null;
    }

    for (let j = 0; j < bytes.length; j += 1) {
      carry += bytes[j] * 58;
      bytes[j] = carry % 256;
      carry = Math.floor(carry / 256);
    }

    while (carry > 0) {
      bytes.push(carry % 256);
      carry = Math.floor(carry / 256);
    }
  }

  let leadingOnes = 0;

  while (leadingOnes < input.length && input[leadingOnes] === '1') {
    leadingOnes += 1;
  }

  let end = bytes.length;

  while (end > 0 && bytes[end - 1] === 0) {
    end -= 1;
  }

  const out = new Uint8Array(leadingOnes + end);

  for (let i = 0; i < end; i += 1) {
    out[leadingOnes + end - 1 - i] = bytes[i];
  }

  return out;
}

function isKnownCardIin(digits: string): boolean {
  const { length } = digits;
  const d2 = Number(digits.slice(0, 2));
  const d4 = Number(digits.slice(0, 4));

  switch (digits[0]) {
    case '4':
      return length === 13 || length === 16 || length === 19;
    case '5':
      return length === 16 && d2 >= 51 && d2 <= 55;
    case '2':
      return length === 16 && d4 >= 2221 && d4 <= 2720;
    case '3':
      if (length === 15) {
        return d2 === 34 || d2 === 37;
      }

      if (length === 14) {
        return d2 === 36 || d2 === 38 || d2 === 39 || (d4 >= 3000 && d4 <= 3059) || d4 === 3095;
      }

      return length >= 16 && length <= 19 && d4 >= 3528 && d4 <= 3589;
    case '6':
      return (
        length >= 16 &&
        length <= 19 &&
        (digits.startsWith('6011') ||
          digits.startsWith('62') ||
          digits.startsWith('64') ||
          digits.startsWith('65'))
      );
    default:
      return false;
  }
}

function validatePayment(match: string): boolean {
  const compactIban = match.replace(/\s/g, '');

  if (/^[A-Za-z]{2}\d{2}[A-Za-z0-9]+$/.test(compactIban)) {
    return !isHexHashLength(compactIban) && isIbanCountry(compactIban) && ibanMod97(match);
  }

  const compactPan = match.replace(/[ -]/g, '');

  if (/^[\d -]+$/.test(match) && /^\d{13,19}$/.test(compactPan)) {
    const grouped = /[ -]/.test(match);

    if (!grouped && compactPan.length > 16) {
      return false;
    }

    return isCardSeparatorLayout(match) && isKnownCardIin(compactPan) && luhnCheck(compactPan);
  }

  if (/^[13][A-HJ-NP-Za-km-z1-9]{25,34}$/.test(match)) {
    return bitcoinBase58Check(match);
  }

  return true;
}

const CVV_KEY = '(?:[Cc][Vv][Vv]2?|[Cc][Vv][Cc]2?|[Cc][Ii][Dd])';
const EXP_KEY = '(?:[Ee]xp(?:iry|iration)?|[Ee]xp[_-]?[Dd]ate)';
const ROUTING_KEY = '(?:[Rr]outing(?:[_-]?[Nn]umber)?|[Aa][Bb][Aa])';
const ACCOUNT_KEY = '(?:[Aa]ccount[_-]?[Nn]umber|[Aa]cct)';

export const paymentInfoRule: SanitizeRule = {
  id: 'paymentInfo',
  label: 'Payment info',
  description:
    'IBANs, card numbers (PAN, Luhn-checked), CVV/CVC, expiry dates and crypto addresses are redacted outright.',
  mode: 'mask',
  token: 'PAYMENT',
  patterns: [
    '(?:(?<![.\\d])\\b\\d(?:[ -]?\\d){12,18}\\b)',
    '(?:\\b[A-Z]{2}\\d{2}[A-Z0-9]{10,30}\\b)',
    '(?:\\b[A-Z]{2}\\d{2}(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?\\b)',
    `(?:\\b${CVV_KEY}\\s*[=:]\\s*)(\\d{3,4}\\b)`,
    `(?:\\b${EXP_KEY}\\s*[=:]\\s*)((?:0[1-9]|1[0-2])[/-](?:\\d{2}|\\d{4})\\b)`,
    '(?:\\bbc1[a-z0-9]{25,39}\\b)',
    '(?:(?<![A-Za-z0-9])[13][A-HJ-NP-Za-km-z1-9]{25,34}(?![A-Za-z0-9]))',
    '(?:\\b0x[A-Fa-f0-9]{40}\\b)',
  ],
  aggressivePatterns: [
    '(?:(?<![\\\\/])\\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\\b(?![\\\\/]))',
    `(?:\\b${ROUTING_KEY}\\s*[=:]\\s*)(\\d{9}\\b)`,
    `(?:\\b${ACCOUNT_KEY}\\s*[=:]\\s*)(\\d{8,12}\\b)`,
  ],
  validate: validatePayment,
  jsonKeys: [
    'iban',
    'cardNumber',
    'pan',
    'cvv',
    'cvc',
    'card_number',
    'creditCard',
    'cvv2',
    'accountNumber',
    'routingNumber',
    'bic',
    'swift',
    'expiryDate',
  ],
};
