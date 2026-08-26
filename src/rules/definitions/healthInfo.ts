import type { SanitizeRule } from '../../types';

function isValidDea(match: string): boolean {
  if (!/^[ABFGMPRX][A-Z9]\d{7}$/.test(match)) {
    return false;
  }

  const digits = match.slice(2);
  const sum =
    Number(digits[0]) +
    Number(digits[2]) +
    Number(digits[4]) +
    2 * (Number(digits[1]) + Number(digits[3]) + Number(digits[5]));

  return sum % 10 === Number(digits[6]);
}

function validateHealth(match: string): boolean {
  if (/^[ABFGMPRX][A-Z9]\d{7}$/.test(match)) {
    return isValidDea(match);
  }

  return true;
}

const MRN_KEY = '(?:[Mm][Rr][Nn]|medical[_-]?record(?:[_-]?number)?)';

export const healthInfoRule: SanitizeRule = {
  id: 'healthInfo',
  label: 'Protected health information',
  description:
    'PHI in SOC logs is almost always structured: JSON field names (diagnosis, medication, MRN, …) carry most of the coverage. Freeform patterns only match context-anchored medical codes (ICD, SNOMED, LOINC, NDC, DEA, MRN).',
  mode: 'mask',
  token: 'PHI',
  patterns: [
    '(?:\\b(?:[Ii][Cc][Dd]-10|[Ii][Cc][Dd]10):?\\s*[A-Z]\\d{2}(?:\\.\\d{1,4})?\\b)',
    '(?:\\b(?:[Ii][Cc][Dd]-9|[Ii][Cc][Dd]9):?\\s*(?:[VE]\\d{2,3}|\\d{3})(?:\\.\\d{1,2})?\\b)',
    '(?:\\b(?:SNOMED(?:\\s*CT)?|[Ss]nomed(?:\\s*CT)?)[:\\s]+\\d{6,18}\\b)',
    '(?:\\b(?:LOINC|[Ll]oinc)[:\\s]+\\d{1,5}-\\d\\b)',
    '(?:\\b(?:NDC|[Nn]dc)[:\\s]+\\d{4,5}-\\d{3,4}-\\d{1,2}\\b)',
    '(?:\\b[ABFGMPRX][A-Z9]\\d{7}\\b)',
    '(?:\\b(?:[Nn][Pp][Ii])\\s*[=:]\\s*\\d{10}\\b)',
    `(?:\\b${MRN_KEY}\\s*[=:]\\s*)([A-Za-z0-9-]{4,})\\b`,
  ],
  aggressivePatterns: ['(?:(?<![A-Za-z0-9])[A-TV-Z]\\d{2}(?:\\.\\w{1,4})?(?![A-Za-z0-9:]))'],
  validate: validateHealth,
  jsonKeys: [
    'diagnosis',
    'prescription',
    'medication',
    'icd10',
    'icd9',
    'snomed',
    'condition',
    'allergy',
    'allergies',
    'bloodType',
    'patientId',
    'mrn',
    'medicalRecordNumber',
    'insuranceNumber',
    'labResult',
    'observation',
    'vitalSigns',
  ],
};
