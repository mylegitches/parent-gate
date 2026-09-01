import test from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword, verifyPassword, hashPin, verifyPin, randomEnrollmentCode } from '../src/auth.js';

test('password hashing verifies only the original password', () => {
  const encoded = hashPassword('this is a good household password');
  assert.equal(verifyPassword('this is a good household password', encoded), true);
  assert.equal(verifyPassword('wrong password', encoded), false);
});

test('PIN verifier is portable and rejects an incorrect PIN', () => {
  const encoded = hashPin('2468');
  assert.match(encoded, /^pbkdf2-sha256\$/);
  assert.equal(verifyPin('2468', encoded), true);
  assert.equal(verifyPin('1357', encoded), false);
});

test('enrollment code uses unambiguous grouped characters', () => {
  assert.match(randomEnrollmentCode(), /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);
});

