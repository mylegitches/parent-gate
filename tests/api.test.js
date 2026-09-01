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

test('setup, enrollment, target discovery, assignment, and policy form one working flow', { timeout: 30000 }, async () => {
  const dataDirectory = mkdtempSync(join(tmpdir(), 'crackdown-api-'));
  const port = 19080 + Math.floor(Math.random() * 800);
  const baseUrl = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: process.cwd(),
    env: { ...process.env, PORT: String(port), DATA_DIR: dataDirectory, COOKIE_SECURE: 'false', APP_BASE_URL: baseUrl },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  try {
    await waitForServer(baseUrl, child);
    const setupResponse = await fetch(`${baseUrl}/api/setup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'parent', displayName: 'Parent', password: 'long-test-password', pin: '2468' }),
    });
    const cookie = setupResponse.headers.get('set-cookie').split(';')[0];
    const setup = await responseJson(setupResponse);
    const parentHeaders = { Cookie: cookie, 'X-CSRF-Token': setup.csrfToken, 'Content-Type': 'application/json' };

    const code = await responseJson(await fetch(`${baseUrl}/api/enrollment-codes`, { method: 'POST', headers: parentHeaders, body: '{}' }));
    const enrollment = await responseJson(await fetch(`${baseUrl}/api/client/v1/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enrollmentCode: code.code, name: 'Test PC', platform: 'windows', capabilities: ['target-scan'] }),
    }));
    const clientHeaders = { Authorization: `Bearer ${enrollment.credential}`, 'Content-Type': 'application/json' };

    await responseJson(await fetch(`${baseUrl}/api/client/v1/targets`, {
      method: 'POST',
      headers: clientHeaders,
      body: JSON.stringify({ targets: [{ key: 'process:zoom.exe', displayName: 'Zoom', kind: 'application', mapping: { processes: ['zoom.exe'] } }] }),
    }));
    await responseJson(await fetch(`${baseUrl}/api/devices/${enrollment.deviceId}/targets`, {
      method: 'PUT',
      headers: parentHeaders,
      body: JSON.stringify({ targetKey: 'process:zoom.exe', profiles: ['homework'] }),
    }));
    await responseJson(await fetch(`${baseUrl}/api/devices/${enrollment.deviceId}/override`, {
      method: 'PUT',
      headers: parentHeaders,
      body: JSON.stringify({ targetType: 'profile', targetId: 'homework', action: 'set', durationMinutes: 30 }),
    }));
    const policy = await responseJson(await fetch(`${baseUrl}/api/client/v1/policy`, { headers: clientHeaders }));
    assert.equal(policy.profile, 'homework');
    assert.equal(policy.customTargets[0].key, 'process:zoom.exe');
    assert.equal(policy.customTargets[0].blocked, true);
    assert.equal(policy.pinVerifiers.length, 1);

    const operationId = crypto.randomUUID();
    const localOperation = {
      operationId,
      deviceId: enrollment.deviceId,
      baseRevision: policy.revision,
      parentKeyId: policy.pinVerifiers[0].parentKeyId,
      targetType: 'service',
      targetId: 'youtube',
      action: 'allow',
      durationMinutes: 30,
    };
    const localResult = await responseJson(await fetch(`${baseUrl}/api/client/v1/local-operations`, {
      method: 'POST', headers: clientHeaders, body: JSON.stringify(localOperation),
    }));
    assert.equal(localResult.accepted, true);
    assert.equal(localResult.policy.revision, policy.revision + 1);

    const duplicate = await responseJson(await fetch(`${baseUrl}/api/client/v1/local-operations`, {
      method: 'POST', headers: clientHeaders, body: JSON.stringify(localOperation),
    }));
    assert.equal(duplicate.duplicate, true);

    const staleResponse = await fetch(`${baseUrl}/api/client/v1/local-operations`, {
      method: 'POST',
      headers: clientHeaders,
      body: JSON.stringify({ ...localOperation, operationId: crypto.randomUUID() }),
    });
    assert.equal(staleResponse.status, 409);
  } finally {
    child.kill();
    await new Promise((resolve) => child.once('exit', resolve));
    rmSync(dataDirectory, { recursive: true, force: true });
  }
});
