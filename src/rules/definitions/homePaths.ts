import type { SanitizeRule } from '../../types';

const USER_SEG = '[^/\\\\\\s"\'<>]+';

function validateHomeUser(match: string): boolean {
  return match !== '.' && match !== '..';
}

export const homePathsRule: SanitizeRule = {
  id: 'paths',
  label: 'Home-directory usernames',
  description:
    'Only the username segment of a home-directory path is redacted (e.g. /home/jdoe/app → /home/<R:…>/app); the rest of the path stays visible.',
  mode: 'mask',
  token: 'PATH',
  patterns: [
    `(?:/export/home/(${USER_SEG}))`,
    `(?:/usr/home/(${USER_SEG}))`,
    `(?:/var/home/(${USER_SEG}))`,
    `(?:/home/(${USER_SEG}))`,
    `(?:/Users/(${USER_SEG}))`,
    `(?:[A-Za-z]:\\\\Users\\\\(${USER_SEG}))`,
    `(?:[A-Za-z]:/Users/(${USER_SEG}))`,
    `(?:\\\\\\\\\\?\\\\[A-Za-z]:\\\\Users\\\\(${USER_SEG}))`,
    `(?:[A-Za-z]:\\\\Documents and Settings\\\\(${USER_SEG}))`,
    `(?:[A-Za-z]:\\\\\\\\Users\\\\\\\\(${USER_SEG}))`,
    `(?:/mnt/[A-Za-z]/Users/(${USER_SEG}))`,
    `(?://wsl\\$/(?:[A-Za-z0-9_-]+)/home/(${USER_SEG}))`,
  ],
  validate: validateHomeUser,
};
