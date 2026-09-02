import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, createHmac } from 'node:crypto';

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

test('setup, enrollment, direct controls, custom websites, and policy form one working flow', { timeout: 30000 }, async () => {
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

    const passwordOnlyLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'parent', password: 'long-test-password' }),
    });
    assert.equal(passwordOnlyLogin.status, 401);
    const pinLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'parent', pin: '2468' }),
    });
    await responseJson(pinLogin);

    const code = await responseJson(await fetch(`${baseUrl}/api/enrollment-codes`, { method: 'POST', headers: parentHeaders, body: '{}' }));
    const enrollment = await responseJson(await fetch(`${baseUrl}/api/client/v1/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enrollmentCode: code.code, name: 'Test PC', platform: 'windows', capabilities: ['target-scan'] }),
    }));
    const clientHeaders = { Authorization: `Bearer ${enrollment.credential}`, 'Content-Type': 'application/json' };

    const update = await responseJson(await fetch(`${baseUrl}/api/client/v1/update`, { headers: clientHeaders }));
    assert.equal(update.version, '0.3.2');
    assert.deepEqual(update.files.map((file) => file.name), ['OperationCrackdown.ps1', 'ShowInternetNotice.ps1', 'ApplyUpdate.ps1']);
    const updateCanonical = [update.version, ...update.files.map((file) => `${file.name}|${file.sha256}|${file.url}`)].join('\n');
    const updateKey = createHash('sha256').update(enrollment.credential, 'utf8').digest();
    assert.equal(createHmac('sha256', updateKey).update(updateCanonical).digest('hex'), update.signature);
    for (const file of update.files) {
      const fileResponse = await fetch(`${baseUrl}${file.url}`, { headers: clientHeaders });
      assert.equal(fileResponse.ok, true);
      const bytes = Buffer.from(await fileResponse.arrayBuffer());
      assert.equal(createHash('sha256').update(bytes).digest('hex'), file.sha256);
    }

    await responseJson(await fetch(`${baseUrl}/api/client/v1/targets`, {
      method: 'POST',
      headers: clientHeaders,
      body: JSON.stringify({ targets: [{ key: 'process:zoom.exe', displayName: 'Zoom', kind: 'application', mapping: { processes: ['zoom.exe'] } }] }),
    }));
    const activityStart = new Date(Date.now() - 5000).toISOString();
    const activityStop = new Date().toISOString();
    const activityResult = await responseJson(await fetch(`${baseUrl}/api/client/v1/application-events`, {
      method: 'POST',
      headers: clientHeaders,
      body: JSON.stringify({ events: [
        { id: crypto.randomUUID(), targetKey: 'process:zoom.exe', displayName: 'Zoom', categoryGuess: 'communication', eventType: 'started', occurredAt: activityStart },
        { id: crypto.randomUUID(), targetKey: 'process:zoom.exe', displayName: 'Zoom', categoryGuess: 'communication', eventType: 'stopped', occurredAt: activityStop },
      ] }),
    }));
    assert.equal(activityResult.accepted, 2);
    const websiteActivityResult = await responseJson(await fetch(`${baseUrl}/api/client/v1/website-events`, {
      method: 'POST',
      headers: clientHeaders,
      body: JSON.stringify({ events: [{
        id: crypto.randomUUID(),
        domain: 'messages.google.com',
        browser: 'Microsoft Edge',
        occurredAt: new Date().toISOString(),
      }] }),
    }));
    assert.equal(websiteActivityResult.accepted, 1);
    await responseJson(await fetch(`${baseUrl}/api/devices/${enrollment.deviceId}/override`, {
      method: 'PUT',
      headers: parentHeaders,
      body: JSON.stringify({ targetType: 'target', targetId: 'process:zoom.exe', action: 'block' }),
    }));
    const website = await responseJson(await fetch(`${baseUrl}/api/devices/${enrollment.deviceId}/websites`, {
      method: 'POST',
      headers: parentHeaders,
      body: JSON.stringify({ url: 'https://social.example.com/messages', displayName: 'Example Social' }),
    }));
    const missingMessage = await fetch(`${baseUrl}/api/devices/${enrollment.deviceId}/override`, {
      method: 'PUT',
      headers: parentHeaders,
      body: JSON.stringify({ targetType: 'internet', targetId: 'access', action: 'block', message: '' }),
    });
    assert.equal(missingMessage.status, 400);
    const unsupportedPause = await fetch(`${baseUrl}/api/devices/${enrollment.deviceId}/override`, {
      method: 'PUT',
      headers: parentHeaders,
      body: JSON.stringify({ targetType: 'internet', targetId: 'access', action: 'block', message: 'Please feed the dogs.' }),
    });
    assert.equal(unsupportedPause.status, 409);
    await fetch(`${baseUrl}/api/client/v1/status`, {
      method: 'POST',
      headers: clientHeaders,
      body: JSON.stringify({
        appliedRevision: 0,
        clientVersion: '0.3.2',
        capabilities: ['target-scan', 'internet-pause-message', 'self-update'],
        status: { state: 'applied' },
      }),
    });
    const currentUpdate = await fetch(`${baseUrl}/api/client/v1/update`, { headers: clientHeaders });
    assert.equal(currentUpdate.status, 204);
    const pause = await responseJson(await fetch(`${baseUrl}/api/devices/${enrollment.deviceId}/override`, {
      method: 'PUT',
      headers: parentHeaders,
      body: JSON.stringify({ targetType: 'internet', targetId: 'access', action: 'block', message: 'Please feed the dogs.' }),
    }));
    assert.equal(pause.policy.internetBlocked, true);
    assert.equal(pause.policy.internetMessage, 'Please feed the dogs.');
    const pausedDelete = await fetch(`${baseUrl}/api/devices/${enrollment.deviceId}`, {
      method: 'DELETE',
      headers: parentHeaders,
    });
    assert.equal(pausedDelete.status, 409);
    const restore = await responseJson(await fetch(`${baseUrl}/api/devices/${enrollment.deviceId}/override`, {
      method: 'PUT',
      headers: parentHeaders,
      body: JSON.stringify({ targetType: 'internet', targetId: 'access', action: 'allow' }),
    }));
    assert.equal(restore.policy.internetBlocked, false);
    const policy = await responseJson(await fetch(`${baseUrl}/api/client/v1/policy`, { headers: clientHeaders }));
    assert.equal(policy.masterEnabled, true);
    assert.equal(policy.customTargets[0].key, 'process:zoom.exe');
    assert.equal(policy.customTargets[0].blocked, true);
    assert.equal(policy.customWebsites[0].id, website.id);
    assert.equal(policy.customWebsites[0].domain, 'social.example.com');
    assert.equal(policy.customWebsites[0].blocked, true);
    assert.equal(policy.pinVerifiers.length, 1);
    const dashboardDevices = await responseJson(await fetch(`${baseUrl}/api/devices`, { headers: parentHeaders }));
    assert.equal(dashboardDevices.devices[0].clientVersion, '0.3.2');
    assert.equal(dashboardDevices.devices[0].latestClientVersion, '0.3.2');
    assert.equal(dashboardDevices.devices[0].updateAvailable, false);
    assert.equal(dashboardDevices.devices[0].applicationActivity.length, 2);
    assert.equal(dashboardDevices.devices[0].applicationActivity[0].eventType, 'stopped');
    assert.equal(dashboardDevices.devices[0].websiteActivity.length, 1);
    assert.equal(dashboardDevices.devices[0].websiteActivity[0].domain, 'messages.google.com');

    const operationId = crypto.randomUUID();
    const localOperation = {
      operationId,
      deviceId: enrollment.deviceId,
      baseRevision: policy.revision,
      parentKeyId: policy.pinVerifiers[0].parentKeyId,
      targetType: 'service',
      targetId: 'youtube',
      action: 'block',
      durationMinutes: 0,
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

    const deleteResponse = await fetch(`${baseUrl}/api/devices/${enrollment.deviceId}`, {
      method: 'DELETE',
      headers: parentHeaders,
    });
    assert.equal(deleteResponse.status, 204);
    const afterDelete = await responseJson(await fetch(`${baseUrl}/api/devices`, { headers: parentHeaders }));
    assert.equal(afterDelete.devices.length, 0);
    const revokedClient = await fetch(`${baseUrl}/api/client/v1/policy`, { headers: clientHeaders });
    assert.equal(revokedClient.status, 401);
  } finally {
    child.kill();
    await new Promise((resolve) => child.once('exit', resolve));
    rmSync(dataDirectory, { recursive: true, force: true });
  }
});
