import {
  createHash,
  randomBytes,
  scryptSync,
  pbkdf2Sync,
  timingSafeEqual,
} from 'node:crypto';

function sameBytes(left, right) {
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

export function sha256(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function randomToken(bytes = 32) {
  return randomBytes(bytes).toString('base64url');
}

export function randomEnrollmentCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = randomBytes(12);
  let result = '';
  for (let index = 0; index < 12; index += 1) {
    if (index === 4 || index === 8) result += '-';
    result += alphabet[bytes[index] % alphabet.length];
  }
  return result;
}

export function hashPassword(password) {
  const salt = randomBytes(16);
  const n = 32768;
  const r = 8;
  const p = 1;
  const derived = scryptSync(password, salt, 32, { N: n, r, p, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${n}$${r}$${p}$${salt.toString('base64url')}$${derived.toString('base64url')}`;
}

export function verifyPassword(password, encoded) {
  try {
    const [kind, nText, rText, pText, saltText, hashText] = encoded.split('$');
    if (kind !== 'scrypt') return false;
    const expected = Buffer.from(hashText, 'base64url');
    const actual = scryptSync(password, Buffer.from(saltText, 'base64url'), expected.length, {
      N: Number(nText),
      r: Number(rText),
      p: Number(pText),
      maxmem: 64 * 1024 * 1024,
    });
    return sameBytes(actual, expected);
  } catch {
    return false;
  }
}

export function hashPin(pin) {
  const salt = randomBytes(16);
  const iterations = 210000;
  const derived = pbkdf2Sync(pin, salt, iterations, 32, 'sha256');
  return `pbkdf2-sha256$${iterations}$${salt.toString('base64url')}$${derived.toString('base64url')}`;
}

export function verifyPin(pin, encoded) {
  try {
    const [kind, iterationsText, saltText, hashText] = encoded.split('$');
    if (kind !== 'pbkdf2-sha256') return false;
    const expected = Buffer.from(hashText, 'base64url');
    const actual = pbkdf2Sync(
      pin,
      Buffer.from(saltText, 'base64url'),
      Number(iterationsText),
      expected.length,
      'sha256',
    );
    return sameBytes(actual, expected);
  } catch {
    return false;
  }
}

