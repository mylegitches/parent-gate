import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

async function waitForServer(baseUrl, child) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (child.exitCode != null) throw new Error(`Server exited with ${child.exitCode}.`);
    try {
      const response = await fetch(`${baseUrl}/healthz`);
      if (response.ok) return;
    } catch { /* wait */ }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('Server did not become ready.');
}

async function responseJson(response) {
  const body = await response.json();
  assert.equal(response.ok, true, JSON.stringify(body));
  return body;
}

function cookieAndCsrf(response, body) {
  return {
    cookie: response.headers.get('set-cookie').split(';')[0],
    csrf: body.csrfToken,
  };
}

function parentHeaders(session) {
  return { Cookie: session.cookie, 'X-CSRF-Token': session.csrf, 'Content-Type': 'application/json' };
}

test('parents can be listed, added, edited, and removed', { timeout: 30000 }, async () => {
  const dataDirectory = mkdtempSync(join(tmpdir(), 'crackdown-parents-'));
  const port = 19180 + Math.floor(Math.random() * 800);
  const baseUrl = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: process.cwd(),
    env: { ...process.env, PORT: String(port), DATA_DIR: dataDirectory, COOKIE_SECURE: 'false', APP_BASE_URL: baseUrl },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  try {
    await waitForServer(baseUrl, child);
    const healthz = await responseJson(await fetch(`${baseUrl}/healthz`));
    assert.equal(healthz.version, '0.3.11');

    const setupResponse = await fetch(`${baseUrl}/api/setup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'parent', displayName: 'Parent', password: 'long-test-password', pin: '2468' }),
    });
    const parentSession = cookieAndCsrf(setupResponse, await responseJson(setupResponse));

    const listed = await responseJson(await fetch(`${baseUrl}/api/parents`, { headers: parentHeaders(parentSession) }));
    assert.equal(listed.parents.length, 1);
    assert.equal(listed.parents[0].username, 'parent');
    assert.equal(listed.parents[0].isSelf, true);
    assert.equal('password_hash' in listed.parents[0], false);
    assert.equal('pin_hash' in listed.parents[0], false);

    const selfDelete = await fetch(`${baseUrl}/api/parents/${listed.parents[0].id}`, {
      method: 'DELETE',
      headers: parentHeaders(parentSession),
    });
    assert.equal(selfDelete.status, 409);

    const lastDelete = await fetch(`${baseUrl}/api/parents/${listed.parents[0].id}`, {
      method: 'DELETE',
      headers: parentHeaders(parentSession),
    });
    assert.equal(lastDelete.status, 409);

    const created = await responseJson(await fetch(`${baseUrl}/api/parents`, {
      method: 'POST',
      headers: parentHeaders(parentSession),
      body: JSON.stringify({
        username: 'other',
        displayName: 'Other',
        password: 'another-long-password',
        pin: '1357',
      }),
    }));
    assert.equal(created.username, 'other');
    assert.equal(created.isSelf, false);

    const duplicate = await fetch(`${baseUrl}/api/parents`, {
      method: 'POST',
      headers: parentHeaders(parentSession),
      body: JSON.stringify({
        username: 'Other',
        displayName: 'Someone',
        password: 'another-long-password',
        pin: '2468',
      }),
    });
    assert.equal(duplicate.status, 409);

    const otherLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'other', pin: '1357' }),
    });
    const otherSession = cookieAndCsrf(otherLogin, await responseJson(otherLogin));
    const otherCode = await responseJson(await fetch(`${baseUrl}/api/enrollment-codes`, {
      method: 'POST',
      headers: parentHeaders(otherSession),
      body: '{}',
    }));

    const renamed = await responseJson(await fetch(`${baseUrl}/api/parents/${created.id}`, {
      method: 'PUT',
      headers: parentHeaders(parentSession),
      body: JSON.stringify({ displayName: 'Other Parent' }),
    }));
    assert.equal(renamed.displayName, 'Other Parent');
    assert.equal(renamed.username, 'other');

    const pinChanged = await responseJson(await fetch(`${baseUrl}/api/parents/${created.id}`, {
      method: 'PUT',
      headers: parentHeaders(parentSession),
      body: JSON.stringify({ pin: '9753' }),
    }));
    assert.equal(pinChanged.displayName, 'Other Parent');

    const oldPin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'other', pin: '1357' }),
    });
    assert.equal(oldPin.status, 401);
    const newPin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'other', pin: '9753' }),
    });
    await responseJson(newPin);

    const badPin = await fetch(`${baseUrl}/api/parents/${created.id}`, {
      method: 'PUT',
      headers: parentHeaders(parentSession),
      body: JSON.stringify({ pin: '12' }),
    });
    assert.equal(badPin.status, 400);

    const removed = await fetch(`${baseUrl}/api/parents/${created.id}`, {
      method: 'DELETE',
      headers: parentHeaders(parentSession),
    });
    assert.equal(removed.status, 204);

    const after = await responseJson(await fetch(`${baseUrl}/api/parents`, { headers: parentHeaders(parentSession) }));
    assert.equal(after.parents.length, 1);
    assert.equal(after.parents[0].username, 'parent');

    const enrolled = await fetch(`${baseUrl}/api/client/v1/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        enrollmentCode: otherCode.code,
        name: 'Other Laptop',
        platform: 'windows',
        capabilities: ['target-scan'],
      }),
    });
    await responseJson(enrolled);

    const missing = await fetch(`${baseUrl}/api/parents/${created.id}`, {
      method: 'DELETE',
      headers: parentHeaders(parentSession),
    });
    assert.equal(missing.status, 404);
  } finally {
    child.kill();
    await new Promise((resolve) => child.once('exit', resolve));
    rmSync(dataDirectory, { recursive: true, force: true });
  }
});
