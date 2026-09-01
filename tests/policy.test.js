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
  const device = {
    id: 'device-1',
    name: 'Test PC',
    platform: 'windows',
    desired_revision: 1,
  };
  db.prepare(`
    INSERT INTO devices (id, name, platform, credential_hash, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(device.id, device.name, device.platform, 'credential-hash', new Date().toISOString());
  return { directory, db, device: db.prepare('SELECT * FROM devices WHERE id = ?').get(device.id) };
}

test('deep focus blocks social and streaming defaults', () => {
  const { directory, db, device } = fixture();
  try {
    db.prepare(`
      INSERT INTO overrides (id, device_id, target_type, target_id, action, source, status, created_at)
      VALUES ('override-1', ?, 'profile', 'deep-focus', 'set', 'test', 'accepted', ?)
    `).run(device.id, new Date().toISOString());
    const policy = resolvePolicy(db, device);
    assert.equal(policy.profile, 'deep-focus');
    assert.equal(policy.services.every((service) => service.blocked), true);
  } finally {
    db.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test('individual service allow overrides a blocked category', () => {
  const { directory, db, device } = fixture();
  try {
    const now = Date.now();
    const insert = db.prepare(`
      INSERT INTO overrides (id, device_id, target_type, target_id, action, source, status, created_at)
      VALUES (?, ?, ?, ?, ?, 'test', 'accepted', ?)
    `);
    insert.run('category', device.id, 'category', 'streaming', 'block', new Date(now).toISOString());
    insert.run('youtube', device.id, 'service', 'youtube', 'allow', new Date(now + 10).toISOString());
    const policy = resolvePolicy(db, device);
    assert.equal(policy.services.find((service) => service.id === 'netflix').blocked, true);
    assert.equal(policy.services.find((service) => service.id === 'youtube').blocked, false);
  } finally {
    db.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test('discovered target assigned to homework is resolved as blocked', () => {
  const { directory, db, device } = fixture();
  try {
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO device_targets
        (device_id, target_key, display_name, target_kind, mapping_json, source, first_seen, last_seen)
      VALUES (?, 'process:zoom.exe', 'Zoom', 'application', '{"processes":["zoom.exe"]}', 'test', ?, ?)
    `).run(device.id, now, now);
    db.prepare(`
      INSERT INTO device_target_profiles (device_id, target_key, profile_id, created_at)
      VALUES (?, 'process:zoom.exe', 'homework', ?)
    `).run(device.id, now);
    db.prepare(`
      INSERT INTO overrides (id, device_id, target_type, target_id, action, source, status, created_at)
      VALUES ('homework', ?, 'profile', 'homework', 'set', 'test', 'accepted', ?)
    `).run(device.id, now);
    const policy = resolvePolicy(db, device);
    assert.equal(policy.customTargets[0].key, 'process:zoom.exe');
    assert.equal(policy.customTargets[0].blocked, true);
  } finally {
    db.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test('temporary policy includes an offline fallback for its expiration', () => {
  const { directory, db, device } = fixture();
  try {
    const now = new Date('2026-09-01T20:00:00.000Z');
    db.prepare(`
      INSERT INTO overrides (id, device_id, target_type, target_id, action, effective_until, source, status, created_at)
      VALUES ('temporary', ?, 'category', 'streaming', 'block', ?, 'test', 'accepted', ?)
    `).run(device.id, '2026-09-01T20:30:00.000Z', now.toISOString());
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
