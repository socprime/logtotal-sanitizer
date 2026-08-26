import type { SanitizeRule } from '../../types';

function luhnCheck(digits: string): boolean {
  if (!/^\d+$/.test(digits) || /^0+$/.test(digits)) {
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

function isValidSsn(area: string, group: string, serial: string): boolean {
  if (area === '000' || area === '666' || area.startsWith('9')) {
    return false;
  }

  return group !== '00' && serial !== '0000';
}

function isValidItin(area: string, group: string, serial: string): boolean {
  if (!area.startsWith('9') || serial === '0000') {
    return false;
  }

  const groupNum = Number(group);

  return (
    (groupNum >= 70 && groupNum <= 88) ||
    (groupNum >= 90 && groupNum <= 92) ||
    (groupNum >= 94 && groupNum <= 99)
  );
}

function isValidNhs(digits: string): boolean {
  if (!/^\d{10}$/.test(digits) || /^0+$/.test(digits)) {
    return false;
  }

  let sum = 0;

  for (let i = 0; i < 9; i += 1) {
    sum += Number(digits[i]) * (10 - i);
  }

  const remainder = sum % 11;
  let check = 11 - remainder;

  if (check === 11) {
    check = 0;
  }

  if (check === 10) {
    return false;
  }

  return check === Number(digits[9]);
}

function validateGovId(match: string): boolean {
  const dashed = /^(\d{3})-(\d{2})-(\d{4})$/.exec(match);

  if (dashed?.[1] && dashed[2] && dashed[3]) {
    return (
      isValidSsn(dashed[1], dashed[2], dashed[3]) || isValidItin(dashed[1], dashed[2], dashed[3])
    );
  }

  if (/^\d{3}-\d{3}-\d{3}$/.test(match)) {
    return luhnCheck(match.replace(/-/g, ''));
  }

  if (/^\d{3} \d{3} \d{4}$/.test(match)) {
    return isValidNhs(match.replace(/ /g, ''));
  }

  const nhsPrefixed = /(?:NHS|nhs)(?:[_-]?number)?\s*[=:]\s*(\d{10})$/.exec(match);
  const nhsDigits = nhsPrefixed?.[1];

  if (nhsDigits) {
    return isValidNhs(nhsDigits);
  }

  return true;
}

const SSN_CTX =
  '(?:[Ss][Ss][Nn]|[Ee][Ii][Nn]|[Ss][Ii][Nn]|tax[_-]?id|social[_ -]?security(?:[_ -]?number)?)';
const ID_CTX = '(?:passport(?:_no|_number)?|driver[_-]?license|national[_-]?id|tax[_-]?id)';

export const govIdentifiersRule: SanitizeRule = {
  id: 'govIds',
  label: 'Government identifiers',
  description: 'Passport numbers, tax numbers, SSNs and similar IDs are redacted outright.',
  mode: 'mask',
  token: 'GOV_ID',
  patterns: [
    '(?:(?<![A-Z0-9<])P<[A-Z0-9<]{42}(?![A-Z0-9<]))',
    '(?:\\b\\d{3}-\\d{2}-\\d{4}\\b)',
    '(?:\\b\\d{3}-\\d{3}-\\d{3}\\b)',
    '(?:\\b\\d{3} \\d{3} \\d{4}\\b)',
    '(?:\\b(?:NHS|nhs)(?:[_-]?number)?\\s*[=:]\\s*\\d{10}\\b)',
    '(?:\\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\\d{6}\\s?[A-D]\\b)',
    '(?:(?<![A-Za-z0-9А-ЯІЇЄҐа-яіїєґ])[А-ЯІЇЄҐ]{2}\\d{6}\\b)',
    `(?:\\b${SSN_CTX}\\s*[=:]?\\s*)(\\d{9})\\b`,
    '(?:(?:ІПН|РНОКПП|tax[_-]?id)\\s*[=:]?\\s*)(\\d{10})\\b',
    `(?:\\b${ID_CTX}\\s*[=:]\\s*)([A-Za-z0-9<]{5,32})`,
  ],
  aggressivePatterns: ['(?:\\b[A-Z]{1,2}\\d{6,9}\\b)', '(?:\\b\\d{9,11}\\b)'],
  validate: validateGovId,
  jsonKeys: [
    'ssn',
    'passportNumber',
    'taxId',
    'nationalId',
    'socialSecurityNumber',
    'passport',
    'nino',
    'nhsNumber',
    'driverLicense',
    'licenseNumber',
    'personalId',
    'dob',
    'dateOfBirth',
  ],
};
