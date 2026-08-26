import type { SanitizeRule } from '../../types';

function validatePhone(match: string): boolean {
  const digits = match.replace(/\D/g, '');
  const national = digits.startsWith('00') ? digits.slice(2) : digits;
  return national.length >= 7 && national.length <= 15;
}

const PHONE_KEY = '(?:telephone|phone|mobile|msisdn|cell|fax|tel)';

export const phoneNumbersRule: SanitizeRule = {
  id: 'phoneNumbers',
  label: 'Phone numbers',
  description:
    'Phone numbers become a stable <PHONE:…> token — the same number maps to the same token everywhere within a session.',
  mode: 'pseudo',
  token: 'PHONE',
  patterns: [
    '(?:(?<![A-Za-z0-9])\\+[1-9](?:[\\s().-]*\\d){6,14}(?!\\d))',
    '(?:\\(\\d{3}\\)\\s?\\d{3}-\\d{4}(?!\\d))',
    '(?:\\b\\d{3}-\\d{3}-\\d{4}\\b)',
    '(?:\\b1-\\d{3}-\\d{3}-\\d{4}\\b)',
    '(?:\\b0\\d{2}-\\d{3}-\\d{2}-\\d{2}\\b)',
    '(?:\\b0\\d{2}\\s\\d{3}\\s\\d{2}\\s\\d{2}\\b)',
    '(?:(?<![.\\d-])\\b00[1-9](?:[\\s().-]*\\d){7,13}(?!\\w)(?!-[\\dA-Fa-f]))',
    '(?:\\b(?:tel|sms):)(\\+?[1-9](?:[\\s().-]*\\d){6,14})(?!\\d)',
    `(?:\\b${PHONE_KEY}\\s*[=:]\\s*)(\\+?[0-9](?:[\\s().-]*\\d){6,14})(?!\\d)`,
  ],
  validate: validatePhone,
  jsonKeys: [
    'phone',
    'phoneNumber',
    'phone_number',
    'mobile',
    'mobileNumber',
    'cell',
    'telephone',
    'tel',
    'fax',
    'msisdn',
    'contactNumber',
  ],
};
