import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDatabase } from '../src/db.js';
import { resolvePolicy } from '../src/policy.js';

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'crackdown-policy-'));
  const db = openDatabase(directory);
  const device = { id: 'device-1', name: 'Test PC', platform: 'windows', desired_revision: 1 };
  db.prepare(`INSERT INTO devices (id, name, platform, credential_hash, created_at) VALUES (?, ?, ?, ?, ?)`)
    .run(device.id, device.name, device.platform, 'credential-hash', new Date().toISOString());
  return { directory, db, device: db.prepare('SELECT * FROM devices WHERE id = ?').get(device.id) };
}

function addOverride(db, deviceId, id, targetType, targetId, action, createdAt, effectiveUntil = null) {
  db.prepare(`
    INSERT INTO overrides (id, device_id, target_type, target_id, action, effective_until, source, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 'test', 'accepted', ?)
  `).run(id, deviceId, targetType, targetId, action, effectiveUntil, createdAt);
}

test('individual services are persistent selections', () => {
  const { directory, db, device } = fixture();
  try {
    addOverride(db, device.id, 'discord', 'service', 'discord', 'block', new Date().toISOString());
    const policy = resolvePolicy(db, device);
    assert.equal(policy.masterEnabled, true);
    assert.equal(policy.services.find((service) => service.id === 'discord').configuredBlocked, true);
    assert.equal(policy.services.find((service) => service.id === 'discord').blocked, true);
    assert.equal(policy.services.find((service) => service.id === 'netflix').blocked, false);
    assert.equal(policy.services.find((service) => service.id === 'roblox').windows.processes.includes('RobloxPlayerBeta.exe'), true);
    assert.equal(policy.services.find((service) => service.id === 'roblox').windows.domains.includes('roblox.com'), true);
    assert.equal(policy.services.find((service) => service.id === 'google-messages').windows.domains.includes('messages.google.com'), true);
  } finally {
    db.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test('master off pauses blocks without forgetting selections', () => {
  const { directory, db, device } = fixture();
  try {
    const now = Date.now();
    addOverride(db, device.id, 'discord', 'service', 'discord', 'block', new Date(now).toISOString());
    addOverride(db, device.id, 'master', 'master', 'blocking', 'disable', new Date(now + 1).toISOString());
    const policy = resolvePolicy(db, device);
    const discord = policy.services.find((service) => service.id === 'discord');
    assert.equal(policy.masterEnabled, false);
    assert.equal(discord.configuredBlocked, true);
    assert.equal(discord.blocked, false);
  } finally {
    db.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test('discovered application targets can be blocked directly', () => {
  const { directory, db, device } = fixture();
  try {
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO device_targets
        (device_id, target_key, display_name, target_kind, mapping_json, source, first_seen, last_seen)
      VALUES (?, 'process:zoom.exe', 'Zoom', 'application', '{"processes":["zoom.exe"]}', 'test', ?, ?)
    `).run(device.id, now, now);
    addOverride(db, device.id, 'zoom', 'target', 'process:zoom.exe', 'block', now);
    const policy = resolvePolicy(db, device);
    assert.equal(policy.customTargets[0].key, 'process:zoom.exe');
    assert.equal(policy.customTargets[0].blocked, true);
  } finally {
    db.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test('custom websites are blocked by default and respect master off', () => {
  const { directory, db, device } = fixture();
  try {
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO custom_websites (id, device_id, display_name, domain, created_at, updated_at)
      VALUES ('site-1', ?, 'Example', 'example.com', ?, ?)
    `).run(device.id, now, now);
    assert.equal(resolvePolicy(db, device).customWebsites[0].blocked, true);
    addOverride(db, device.id, 'master', 'master', 'blocking', 'disable', now);
    const paused = resolvePolicy(db, device).customWebsites[0];
    assert.equal(paused.configuredBlocked, true);
    assert.equal(paused.blocked, false);
  } finally {
    db.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test('temporary policy includes an offline fallback for its expiration', () => {
  const { directory, db, device } = fixture();
  try {
    const now = new Date('2026-09-01T20:00:00.000Z');
    addOverride(db, device.id, 'temporary', 'service', 'netflix', 'block', now.toISOString(), '2026-09-01T20:30:00.000Z');
    const policy = resolvePolicy(db, device, now);
    assert.equal(policy.services.find((service) => service.id === 'netflix').blocked, true);
    assert.equal(policy.nextExpiry, '2026-09-01T20:30:00.000Z');
    assert.equal(policy.afterExpiry.services.find((service) => service.id === 'netflix').blocked, false);
    assert.equal(policy.afterExpiry.nextExpiry, null);
  } finally {
    db.close();
    rmSync(directory, { recursive: true, force: true });
  }
});
