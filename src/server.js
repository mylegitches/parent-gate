import { createServer } from 'node:http';
import { mkdir, readFile, unlink, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, createHmac, randomUUID } from 'node:crypto';
import { openDatabase, audit } from './db.js';
import {
  hashPassword,
  hashPin,
  verifyPin,
  randomToken,
  randomEnrollmentCode,
  sha256,
} from './auth.js';
import { SERVICE_CATALOG } from './catalog.js';
import { calculateEffectiveUntil, resolvePolicy, validateOverride } from './policy.js';

const port = Number(process.env.PORT ?? 8080);
const dataDir = resolve(process.env.DATA_DIR ?? './data');
const publicDir = resolve(dirname(fileURLToPath(import.meta.url)), '../public');
const windowsClientDir = resolve(dirname(fileURLToPath(import.meta.url)), '../client/windows');
const cookieSecure = String(process.env.COOKIE_SECURE ?? 'true').toLowerCase() === 'true';
const sessionDays = Math.max(1, Number(process.env.SESSION_DAYS ?? 14));
const householdTimezone = process.env.HOUSEHOLD_TIMEZONE ?? 'America/Chicago';
const appBaseUrl = process.env.APP_BASE_URL || `http://localhost:${port}`;
const db = openDatabase(dataDir);
const screenshotDir = join(dataDir, 'screenshots');
await mkdir(screenshotDir, { recursive: true });
const loginAttempts = new Map();
const windowsUpdateDefinition = JSON.parse(await readFile(join(windowsClientDir, 'update.json'), 'utf8'));
const windowsUpdateFiles = new Map(await Promise.all(windowsUpdateDefinition.files.map(async (name) => {
  if (!/^[A-Za-z0-9.-]+$/.test(name)) throw new Error(`Invalid Windows update filename: ${name}`);
  const content = await readFile(join(windowsClientDir, name));
  return [name, { content, sha256: createHash('sha256').update(content).digest('hex') }];
})));

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

function securityHeaders(extra = {}) {
  return {
    'Content-Security-Policy': "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    ...extra,
  };
}

function json(res, status, value, headers = {}) {
  const payload = JSON.stringify(value);
  res.writeHead(status, securityHeaders({
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store',
    ...headers,
  }));
  res.end(payload);
}

function noContent(res, headers = {}) {
  res.writeHead(204, securityHeaders({ 'Cache-Control': 'no-store', ...headers }));
  res.end();
}

async function bodyBytes(req, maxBytes = 1024 * 1024) {
  const chunks = [];
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > maxBytes) throw new Error('Request body is too large.');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function bodyJson(req, maxBytes = 1024 * 1024) {
  const raw = await bodyBytes(req, maxBytes);
  if (raw.length === 0) return {};
  return JSON.parse(raw.toString('utf8'));
}

function screenshotPath(deviceId) {
  return join(screenshotDir, `${deviceId}.jpg`);
}

function screenshotView(device) {
  const pending = Boolean(device.screenshot_request_id);
  const capturedAt = device.screenshot_captured_at || null;
  return {
    pending,
    capturedAt,
    error: device.screenshot_error || null,
    url: capturedAt ? `/api/devices/${device.id}/screenshot?t=${encodeURIComponent(capturedAt)}` : null,
  };
}

function parseCookies(req) {
  const result = {};
  for (const item of (req.headers.cookie ?? '').split(';')) {
    const index = item.indexOf('=');
    if (index > 0) result[item.slice(0, index).trim()] = decodeURIComponent(item.slice(index + 1).trim());
  }
  return result;
}

function sessionCookie(token, maxAgeSeconds) {
  const parts = [
    `oc_session=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (cookieSecure) parts.push('Secure');
  return parts.join('; ');
}

function parentFromRequest(req) {
  const raw = parseCookies(req).oc_session;
  if (!raw) return null;
  return db.prepare(`
    SELECT p.*, s.csrf_token, s.expires_at
    FROM sessions s JOIN parents p ON p.id = s.parent_id
    WHERE s.token_hash = ? AND s.expires_at > ?
  `).get(sha256(raw), new Date().toISOString()) ?? null;
}

function clientFromRequest(req) {
  const header = req.headers.authorization ?? '';
  if (!header.startsWith('Bearer ')) return null;
  const raw = header.slice(7).trim();
  if (!raw) return null;
  return db.prepare('SELECT * FROM devices WHERE credential_hash = ?').get(sha256(raw)) ?? null;
}

function requireParent(req, res, { csrf = false } = {}) {
  const parent = parentFromRequest(req);
  if (!parent) {
    json(res, 401, { error: 'Authentication required.' });
    return null;
  }
  if (csrf && req.headers['x-csrf-token'] !== parent.csrf_token) {
    json(res, 403, { error: 'Invalid CSRF token.' });
    return null;
  }
  return parent;
}

function requireClient(req, res) {
  const device = clientFromRequest(req);
  if (!device) {
    json(res, 401, { error: 'Invalid device credential.' });
    return null;
  }
  return device;
}

function deviceView(device) {
  const status = safeJson(device.status_json, {});
  const policy = resolvePolicy(db, device);
  const targetPolicy = new Map(policy.customTargets.map((target) => [target.key, target]));
  const availableTargets = db.prepare(`
    SELECT t.* FROM device_targets t
    WHERE t.device_id = ?
    ORDER BY t.currently_running DESC, t.display_name COLLATE NOCASE
  `).all(device.id).map((target) => ({
    key: target.target_key,
    displayName: target.display_name,
    kind: target.target_kind,
    categoryGuess: target.category_guess,
    source: target.source,
    mapping: safeJson(target.mapping_json, {}),
    currentlyRunning: Boolean(target.currently_running),
    lastSeen: target.last_seen,
    configuredBlocked: Boolean(targetPolicy.get(target.target_key)?.configuredBlocked),
    blocked: Boolean(targetPolicy.get(target.target_key)?.blocked),
  }));
  const applicationActivity = db.prepare(`
    SELECT id, target_key, display_name, event_type, occurred_at
    FROM application_events
    WHERE device_id = ?
    ORDER BY occurred_at DESC, rowid DESC
    LIMIT 250
  `).all(device.id).map((event) => ({
    id: event.id,
    targetKey: event.target_key,
    displayName: event.display_name,
    eventType: event.event_type,
    occurredAt: event.occurred_at,
  }));
  const websiteActivity = db.prepare(`
    SELECT id, domain, browser, occurred_at
    FROM website_events
    WHERE device_id = ?
    ORDER BY occurred_at DESC, rowid DESC
    LIMIT 250
  `).all(device.id).map((event) => ({
    id: event.id,
    domain: event.domain,
    browser: event.browser,
    occurredAt: event.occurred_at,
  }));
  return {
    id: device.id,
    name: device.name,
    platform: device.platform,
    osVersion: device.os_version,
    clientVersion: device.client_version,
    latestClientVersion: device.platform === 'windows' ? windowsUpdateDefinition.version : null,
    updateAvailable: device.platform === 'windows' && device.client_version !== windowsUpdateDefinition.version,
    capabilities: safeJson(device.capabilities_json, []),
    desiredRevision: device.desired_revision,
    appliedRevision: device.applied_revision,
    lastSeen: device.last_seen,
    status,
    online: device.last_seen ? Date.now() - new Date(device.last_seen).valueOf() < 45000 : false,
    policy,
    availableTargets,
    applicationActivity,
    websiteActivity,
    screenshot: screenshotView(device),
  };
}

function safeJson(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function supportsInternetPause(device) {
  return device.platform !== 'ios'
    && safeJson(device.capabilities_json, []).includes('internet-pause-message');
}

function windowsUpdateManifest(device) {
  const files = [...windowsUpdateFiles].map(([name, file]) => ({
    name,
    sha256: file.sha256,
    url: `/api/client/v1/update/files/${encodeURIComponent(name)}`,
  }));
  const canonical = [windowsUpdateDefinition.version, ...files.map((file) => `${file.name}|${file.sha256}|${file.url}`)].join('\n');
  const signature = createHmac('sha256', Buffer.from(device.credential_hash, 'hex')).update(canonical).digest('hex');
  return {
    version: windowsUpdateDefinition.version,
    releasedAt: windowsUpdateDefinition.releasedAt,
    files,
    signatureAlgorithm: 'device-hmac-sha256',
    signature,
  };
}

function normalizeWebsite(value) {
  const input = String(value ?? '').trim();
  if (!input || input.length > 2048) return null;
  try {
    const parsed = new URL(input.includes('://') ? input : `https://${input}`);
    const domain = parsed.hostname.toLowerCase().replace(/^\.+|\.+$/g, '');
    if (!domain || domain.length > 253 || !domain.includes('.') || !/^[a-z0-9.-]+$/i.test(domain)) return null;
    return domain;
  } catch {
    return null;
  }
}

function normalizeExecutablePath(value) {
  const input = String(value ?? '').trim().replace(/^["']+|["']+$/g, '');
  if (!input || input.length > 260) return null;
  if (/[\u0000-\u001f]/.test(input) || input.includes('..')) return null;
  const windowsPath = input.replace(/\//g, '\\').replace(/\\+/g, '\\');
  if (!/^[a-zA-Z]:\\/.test(windowsPath) || !/\.exe$/i.test(windowsPath)) return null;
  const fileName = windowsPath.split('\\').pop() ?? '';
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*\.exe$/i.test(fileName)) return null;
  const lower = windowsPath.toLowerCase();
  if (
    lower.startsWith('c:\\windows\\')
    || lower.includes('\\windows\\system32\\')
    || lower.includes('\\windows\\syswow64\\')
    || lower.includes('\\parentgate\\')
    || ['powershell.exe', 'pwsh.exe', 'cmd.exe', 'conhost.exe'].includes(fileName.toLowerCase())
  ) {
    return null;
  }
  return {
    path: windowsPath,
    fileName,
    key: `path:${createHash('sha256').update(lower).digest('hex').slice(0, 32)}`,
  };
}

function incrementRevision(deviceId) {
  db.prepare('UPDATE devices SET desired_revision = desired_revision + 1 WHERE id = ?').run(deviceId);
}

function resolveClientPolicy(device) {
  const pinVerifiers = db.prepare(`
    SELECT id AS parentKeyId, display_name AS displayName, pin_hash AS verifier
    FROM parents ORDER BY created_at
  `).all();
  return {
    ...resolvePolicy(db, device),
    deviceId: device.id,
    pinVerifiers,
    screenshotRequestId: device.screenshot_request_id || null,
  };
}

function insertOverride({ deviceId, targetType, targetId, action, effectiveUntil, source, parentId, baseRevision = null, operationId = null, message = null }) {
  const id = randomUUID();
  db.prepare(`
    INSERT INTO overrides
      (id, operation_id, device_id, target_type, target_id, action, effective_until, source, parent_id, base_revision, message, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'accepted', ?)
  `).run(
    id,
    operationId,
    deviceId,
    targetType,
    targetId,
    action,
    effectiveUntil,
    source,
    parentId,
    baseRevision,
    message,
    new Date().toISOString(),
  );
  incrementRevision(deviceId);
  return id;
}

function createSession(parentId) {
  const raw = randomToken(32);
  const csrf = randomToken(24);
  const now = new Date();
  const expires = new Date(now.valueOf() + sessionDays * 86400000);
  db.prepare(`
    INSERT INTO sessions (token_hash, parent_id, csrf_token, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(sha256(raw), parentId, csrf, expires.toISOString(), now.toISOString());
  return { raw, csrf, expires };
}

function rateLimited(key) {
  const now = Date.now();
  const entry = loginAttempts.get(key) ?? [];
  const recent = entry.filter((time) => now - time < 15 * 60 * 1000);
  loginAttempts.set(key, recent);
  return recent.length >= 8;
}

function recordFailedLogin(key) {
  const entry = loginAttempts.get(key) ?? [];
  entry.push(Date.now());
  loginAttempts.set(key, entry);
}

function validateUsername(value) {
  const username = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9._-]{3,40}$/.test(username)) return { error: 'Username must be 3–40 letters, numbers, dots, underscores, or dashes.' };
  return { username };
}

function validateDisplayName(value, fallback = '') {
  const displayName = String(value ?? fallback).trim();
  if (displayName.length < 1 || displayName.length > 80) return { error: 'Display name is required.' };
  return { displayName };
}

function validatePassword(value, { required = true } = {}) {
  const password = String(value ?? '');
  if (!password) return required ? { error: 'Password must be at least 10 characters.' } : {};
  if (password.length < 10) return { error: 'Password must be at least 10 characters.' };
  return { password };
}

function validatePin(value, { required = true } = {}) {
  const pin = String(value ?? '');
  if (!pin) return required ? { error: 'PIN must contain 4–8 digits.' } : {};
  if (!/^\d{4,8}$/.test(pin)) return { error: 'PIN must contain 4–8 digits.' };
  return { pin };
}

function validateParentFields(body) {
  const username = validateUsername(body.username);
  if (username.error) return username;
  const displayName = validateDisplayName(body.displayName, username.username);
  if (displayName.error) return displayName;
  const password = validatePassword(body.password);
  if (password.error) return password;
  const pin = validatePin(body.pin);
  if (pin.error) return pin;
  return { ...username, ...displayName, ...password, ...pin };
}

function parentView(row, currentParentId) {
  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name,
    createdAt: row.created_at,
    isSelf: row.id === currentParentId,
  };
}

async function handleApi(req, res, url) {
  const path = url.pathname;

  if (req.method === 'GET' && path === '/api/bootstrap') {
    const count = db.prepare('SELECT COUNT(*) AS count FROM parents').get().count;
    return json(res, 200, { setupRequired: count === 0, appBaseUrl, householdTimezone });
  }

  if (req.method === 'POST' && path === '/api/setup') {
    if (db.prepare('SELECT COUNT(*) AS count FROM parents').get().count !== 0) {
      return json(res, 409, { error: 'Initial setup is already complete.' });
    }
    const fields = validateParentFields(await bodyJson(req));
    if (fields.error) return json(res, 400, { error: fields.error });
    const parentId = randomUUID();
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO parents (id, username, display_name, password_hash, pin_hash, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(parentId, fields.username, fields.displayName, hashPassword(fields.password), hashPin(fields.pin), now);
    audit(db, { parentId, eventType: 'setup.completed', summary: `${fields.displayName} completed initial setup.` });
    const session = createSession(parentId);
    return json(res, 201, { ok: true, csrfToken: session.csrf }, {
      'Set-Cookie': sessionCookie(session.raw, Math.floor((session.expires.valueOf() - Date.now()) / 1000)),
    });
  }

  if (req.method === 'POST' && path === '/api/auth/login') {
    const remote = String(req.headers['x-forwarded-for'] ?? req.socket.remoteAddress ?? 'unknown').split(',')[0];
    const body = await bodyJson(req);
    const username = String(body.username ?? '').trim();
    const attemptKey = `${remote}:${username.toLowerCase()}`;
    if (rateLimited(attemptKey)) return json(res, 429, { error: 'Too many login attempts. Try again later.' });
    const parent = db.prepare('SELECT * FROM parents WHERE username = ? COLLATE NOCASE').get(username);
    if (!parent || !verifyPin(String(body.pin ?? ''), parent.pin_hash)) {
      recordFailedLogin(attemptKey);
      return json(res, 401, { error: 'Invalid username or PIN.' });
    }
    loginAttempts.delete(attemptKey);
    const session = createSession(parent.id);
    audit(db, { parentId: parent.id, eventType: 'auth.login', summary: `${parent.display_name} signed in.` });
    return json(res, 200, { ok: true, csrfToken: session.csrf }, {
      'Set-Cookie': sessionCookie(session.raw, Math.floor((session.expires.valueOf() - Date.now()) / 1000)),
    });
  }

  if (req.method === 'POST' && path === '/api/client/v1/enroll') {
    const body = await bodyJson(req);
    const codeHash = sha256(String(body.enrollmentCode ?? '').toUpperCase());
    const code = db.prepare(`
      SELECT * FROM enrollment_codes WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?
    `).get(codeHash, new Date().toISOString());
    if (!code) return json(res, 400, { error: 'Enrollment code is invalid or expired.' });
    const name = String(body.name ?? '').trim();
    const platform = String(body.platform ?? '').toLowerCase();
    if (!name || name.length > 100) return json(res, 400, { error: 'A device name is required.' });
    if (!['windows', 'android', 'ios'].includes(platform)) return json(res, 400, { error: 'Unsupported platform.' });
    const deviceId = randomUUID();
    const credential = randomToken(40);
    const now = new Date().toISOString();
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare(`
        INSERT INTO devices
          (id, name, platform, os_version, client_version, capabilities_json, credential_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        deviceId,
        name,
        platform,
        String(body.osVersion ?? ''),
        String(body.clientVersion ?? ''),
        JSON.stringify(Array.isArray(body.capabilities) ? body.capabilities : []),
        sha256(credential),
        now,
      );
      db.prepare('UPDATE enrollment_codes SET used_at = ? WHERE code_hash = ?').run(now, codeHash);
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
    audit(db, { parentId: code.created_by, deviceId, eventType: 'device.enrolled', summary: `${name} enrolled as ${platform}.` });
    return json(res, 201, { deviceId, credential, serverUrl: appBaseUrl });
  }

  if (path.startsWith('/api/client/v1/')) {
    const device = requireClient(req, res);
    if (!device) return;
    const now = new Date().toISOString();

    if (req.method === 'GET' && path === '/api/client/v1/policy') {
      db.prepare('UPDATE devices SET last_seen = ? WHERE id = ?').run(now, device.id);
      const refreshed = db.prepare('SELECT * FROM devices WHERE id = ?').get(device.id);
      return json(res, 200, resolveClientPolicy(refreshed));
    }

    if (req.method === 'GET' && path === '/api/client/v1/update') {
      if (device.platform !== 'windows' || device.client_version === windowsUpdateDefinition.version) return noContent(res);
      return json(res, 200, windowsUpdateManifest(device));
    }

    const updateFileMatch = path.match(/^\/api\/client\/v1\/update\/files\/([^/]+)$/);
    if (req.method === 'GET' && updateFileMatch) {
      if (device.platform !== 'windows') return json(res, 404, { error: 'Update file not found.' });
      const name = decodeURIComponent(updateFileMatch[1]);
      const file = windowsUpdateFiles.get(name);
      if (!file) return json(res, 404, { error: 'Update file not found.' });
      res.writeHead(200, securityHeaders({
        'Content-Type': 'application/octet-stream',
        'Content-Length': file.content.length,
        'Cache-Control': 'no-store',
        'X-Content-SHA256': file.sha256,
      }));
      res.end(file.content);
      return;
    }

    if (req.method === 'POST' && path === '/api/client/v1/status') {
      const body = await bodyJson(req);
      const appliedRevision = Math.max(0, Number(body.appliedRevision ?? device.applied_revision));
      db.prepare(`
        UPDATE devices SET last_seen = ?, applied_revision = ?, status_json = ?, client_version = COALESCE(?, client_version), os_version = COALESCE(?, os_version), capabilities_json = COALESCE(?, capabilities_json)
        WHERE id = ?
      `).run(
        now,
        appliedRevision,
        JSON.stringify(body.status ?? {}),
        body.clientVersion ? String(body.clientVersion) : null,
        body.osVersion ? String(body.osVersion) : null,
        Array.isArray(body.capabilities) ? JSON.stringify(body.capabilities) : null,
        device.id,
      );
      return noContent(res);
    }

    if (req.method === 'POST' && path === '/api/client/v1/screenshot') {
      const requestId = String(req.headers['x-screenshot-request-id'] ?? '').trim();
      const contentType = String(req.headers['content-type'] ?? '');
      const nowIso = new Date().toISOString();
      if (!device.screenshot_request_id) return json(res, 409, { error: 'No screenshot is currently requested.' });
      if (requestId && requestId !== device.screenshot_request_id) {
        return json(res, 409, { error: 'This screenshot request is no longer current.' });
      }
      if (contentType.includes('application/json')) {
        const body = await bodyJson(req);
        const headerId = requestId || String(body.requestId ?? '').trim();
        if (headerId !== device.screenshot_request_id) {
          return json(res, 409, { error: 'This screenshot request is no longer current.' });
        }
        const error = String(body.error ?? 'Screenshot capture failed.').slice(0, 240);
        db.prepare('UPDATE devices SET last_seen = ?, screenshot_request_id = NULL, screenshot_error = ? WHERE id = ?').run(nowIso, error, device.id);
        audit(db, { deviceId: device.id, eventType: 'screenshot.failed', summary: `${device.name} could not capture the desktop.`, details: { error } });
        return noContent(res);
      }
      const bytes = await bodyBytes(req, 8 * 1024 * 1024);
      if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8 || bytes[2] !== 0xff) {
        return json(res, 400, { error: 'A JPEG screenshot is required.' });
      }
      await writeFile(screenshotPath(device.id), bytes);
      db.prepare(`
        UPDATE devices
        SET last_seen = ?, screenshot_request_id = NULL, screenshot_captured_at = ?, screenshot_error = NULL
        WHERE id = ?
      `).run(nowIso, nowIso, device.id);
      audit(db, { deviceId: device.id, eventType: 'screenshot.captured', summary: `${device.name} sent a desktop screenshot.` });
      return noContent(res);
    }

    if (req.method === 'POST' && path === '/api/client/v1/push-token') {
      const body = await bodyJson(req);
      db.prepare('UPDATE devices SET push_token = ?, last_seen = ? WHERE id = ?').run(String(body.pushToken ?? ''), now, device.id);
      return noContent(res);
    }

    if (req.method === 'POST' && path === '/api/client/v1/targets') {
      const body = await bodyJson(req);
      const targets = Array.isArray(body.targets) ? body.targets.slice(0, 250) : [];
      db.prepare("UPDATE device_targets SET currently_running = 0 WHERE device_id = ? AND source != 'parent-path'").run(device.id);
      const upsert = db.prepare(`
        INSERT INTO device_targets
          (device_id, target_key, display_name, target_kind, category_guess, mapping_json, source, currently_running, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_id, target_key) DO UPDATE SET
          display_name = excluded.display_name,
          target_kind = excluded.target_kind,
          category_guess = excluded.category_guess,
          mapping_json = excluded.mapping_json,
          source = excluded.source,
          currently_running = excluded.currently_running,
          last_seen = excluded.last_seen
      `);
      for (const target of targets) {
        const key = String(target.key ?? '');
        const displayName = String(target.displayName ?? '').trim();
        const kind = String(target.kind ?? 'application');
        const categoryGuess = String(target.categoryGuess ?? 'unknown');
        if (!/^[a-z0-9._:-]{3,160}$/i.test(key) || !displayName || displayName.length > 120) continue;
        if (!['application', 'package', 'local-selection'].includes(kind)) continue;
        const mapping = target.mapping && typeof target.mapping === 'object' ? target.mapping : {};
        upsert.run(
          device.id,
          key,
          displayName,
          kind,
          categoryGuess,
          JSON.stringify(mapping),
          String(target.source ?? 'client-scan').slice(0, 40),
          target.currentlyRunning === false ? 0 : 1,
          now,
          now,
        );
      }
      return json(res, 200, { accepted: targets.length });
    }

    if (req.method === 'POST' && path === '/api/client/v1/application-events') {
      const body = await bodyJson(req);
      const events = Array.isArray(body.events) ? body.events.slice(0, 500) : [];
      const receivedAt = new Date().toISOString();
      const insertEvent = db.prepare(`
        INSERT OR IGNORE INTO application_events
          (id, device_id, target_key, display_name, event_type, occurred_at, received_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      const upsertTarget = db.prepare(`
        INSERT INTO device_targets
          (device_id, target_key, display_name, target_kind, category_guess, mapping_json, source, currently_running, first_seen, last_seen)
        VALUES (?, ?, ?, 'application', ?, ?, 'windows-activity-monitor', ?, ?, ?)
        ON CONFLICT(device_id, target_key) DO UPDATE SET
          display_name = excluded.display_name,
          mapping_json = excluded.mapping_json,
          source = excluded.source,
          currently_running = excluded.currently_running,
          last_seen = excluded.last_seen
      `);
      let accepted = 0;
      db.exec('BEGIN IMMEDIATE');
      try {
        for (const event of events) {
          const id = String(event.id ?? '');
          const targetKey = String(event.targetKey ?? '').toLowerCase();
          const displayName = String(event.displayName ?? '').trim().slice(0, 120);
          const eventType = String(event.eventType ?? '');
          const occurred = new Date(String(event.occurredAt ?? ''));
          if (!/^[0-9a-f-]{36}$/i.test(id) || !/^process:[a-z0-9._-]+\.exe$/i.test(targetKey)) continue;
          if (!displayName || !['started', 'stopped'].includes(eventType) || Number.isNaN(occurred.valueOf())) continue;
          const occurredAt = occurred.toISOString();
          const processName = targetKey.slice('process:'.length);
          const result = insertEvent.run(id, device.id, targetKey, displayName, eventType, occurredAt, receivedAt);
          if (result.changes) accepted += 1;
          upsertTarget.run(
            device.id,
            targetKey,
            displayName,
            String(event.categoryGuess ?? 'unknown').slice(0, 40),
            JSON.stringify({ processes: [processName] }),
            eventType === 'started' ? 1 : 0,
            occurredAt,
            occurredAt,
          );
        }
        const cutoff = new Date(Date.now() - 30 * 86400000).toISOString();
        db.prepare('DELETE FROM application_events WHERE device_id = ? AND occurred_at < ?').run(device.id, cutoff);
        db.prepare(`
          DELETE FROM application_events WHERE id IN (
            SELECT id FROM application_events WHERE device_id = ?
            ORDER BY occurred_at DESC, rowid DESC LIMIT -1 OFFSET 5000
          )
        `).run(device.id);
        db.exec('COMMIT');
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
      return json(res, 200, { accepted });
    }

    if (req.method === 'POST' && path === '/api/client/v1/website-events') {
      const body = await bodyJson(req);
      const events = Array.isArray(body.events) ? body.events.slice(0, 500) : [];
      const receivedAt = new Date().toISOString();
      const insert = db.prepare(`
        INSERT OR IGNORE INTO website_events
          (id, device_id, domain, browser, occurred_at, received_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      let accepted = 0;
      db.exec('BEGIN IMMEDIATE');
      try {
        for (const event of events) {
          const id = String(event.id ?? '');
          const domain = normalizeWebsite(event.domain);
          const browser = String(event.browser ?? 'browser').trim().slice(0, 40) || 'browser';
          const occurred = new Date(String(event.occurredAt ?? ''));
          if (!/^[0-9a-f-]{36}$/i.test(id) || !domain || Number.isNaN(occurred.valueOf())) continue;
          const result = insert.run(id, device.id, domain, browser, occurred.toISOString(), receivedAt);
          if (result.changes) accepted += 1;
        }
        const cutoff = new Date(Date.now() - 30 * 86400000).toISOString();
        db.prepare('DELETE FROM website_events WHERE device_id = ? AND occurred_at < ?').run(device.id, cutoff);
        db.prepare(`
          DELETE FROM website_events WHERE id IN (
            SELECT id FROM website_events WHERE device_id = ?
            ORDER BY occurred_at DESC, rowid DESC LIMIT -1 OFFSET 5000
          )
        `).run(device.id);
        db.exec('COMMIT');
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
      return json(res, 200, { accepted });
    }

    if (req.method === 'GET' && path === '/api/client/v1/local-pin-verifiers') {
      const verifiers = db.prepare('SELECT id AS parentKeyId, display_name AS displayName, pin_hash AS verifier FROM parents ORDER BY created_at').all();
      return json(res, 200, { verifiers });
    }

    if (req.method === 'POST' && path === '/api/client/v1/local-operations') {
      const body = await bodyJson(req);
      const operationId = String(body.operationId ?? '');
      if (!/^[0-9a-f-]{36}$/i.test(operationId)) return json(res, 400, { error: 'A valid operationId is required.' });
      const duplicate = db.prepare('SELECT * FROM overrides WHERE operation_id = ?').get(operationId);
      if (duplicate) {
        const current = db.prepare('SELECT * FROM devices WHERE id = ?').get(device.id);
        return json(res, 200, { accepted: true, duplicate: true, policy: resolveClientPolicy(current) });
      }
      const baseRevision = Number(body.baseRevision);
      if (baseRevision !== device.desired_revision) {
        return json(res, 409, { error: 'Policy revision conflict.', currentRevision: device.desired_revision, policy: resolveClientPolicy(device) });
      }
      const parent = db.prepare('SELECT * FROM parents WHERE id = ?').get(String(body.parentKeyId ?? ''));
      if (!parent) return json(res, 400, { error: 'Unknown parent key.' });
      const targetType = String(body.targetType ?? '');
      const targetId = String(body.targetId ?? '');
      const action = String(body.action ?? '');
      if (!validateOverride(targetType, targetId, action)) return json(res, 400, { error: 'Invalid override.' });
      if (targetType === 'target' && !db.prepare('SELECT 1 FROM device_targets WHERE device_id = ? AND target_key = ?').get(device.id, targetId)) {
        return json(res, 404, { error: 'Discovered target not found.' });
      }
      if (targetType === 'website' && !db.prepare('SELECT 1 FROM custom_websites WHERE device_id = ? AND id = ?').get(device.id, targetId)) {
        return json(res, 404, { error: 'Custom website not found.' });
      }
      const effectiveUntil = calculateEffectiveUntil(body);
      insertOverride({
        deviceId: device.id,
        targetType,
        targetId,
        action,
        effectiveUntil,
        source: 'local-client',
        parentId: parent.id,
        baseRevision,
        operationId,
      });
      audit(db, {
        parentId: parent.id,
        deviceId: device.id,
        eventType: 'override.local',
        summary: `${parent.display_name} set ${targetId} to ${action} locally on ${device.name}.`,
        details: { targetType, targetId, action, effectiveUntil, operationId },
      });
      const current = db.prepare('SELECT * FROM devices WHERE id = ?').get(device.id);
      return json(res, 201, { accepted: true, policy: resolveClientPolicy(current) });
    }

    return json(res, 404, { error: 'Client API route not found.' });
  }

  const mutating = !['GET', 'HEAD'].includes(req.method);
  const parent = requireParent(req, res, { csrf: mutating });
  if (!parent) return;

  if (req.method === 'GET' && path === '/api/me') {
    return json(res, 200, { id: parent.id, username: parent.username, displayName: parent.display_name, csrfToken: parent.csrf_token });
  }

  if (req.method === 'POST' && path === '/api/auth/logout') {
    const raw = parseCookies(req).oc_session;
    if (raw) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(raw));
    return noContent(res, { 'Set-Cookie': sessionCookie('', 0) });
  }

  if (req.method === 'GET' && path === '/api/parents') {
    const parents = db.prepare('SELECT id, username, display_name, created_at FROM parents ORDER BY created_at').all()
      .map((row) => parentView(row, parent.id));
    return json(res, 200, { parents });
  }

  if (req.method === 'POST' && path === '/api/parents') {
    const fields = validateParentFields(await bodyJson(req));
    if (fields.error) return json(res, 400, { error: fields.error });
    const id = randomUUID();
    try {
      db.prepare(`
        INSERT INTO parents (id, username, display_name, password_hash, pin_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(id, fields.username, fields.displayName, hashPassword(fields.password), hashPin(fields.pin), new Date().toISOString());
    } catch (error) {
      if (String(error.message).includes('UNIQUE')) return json(res, 409, { error: 'That username already exists.' });
      throw error;
    }
    audit(db, { parentId: parent.id, eventType: 'parent.created', summary: `${parent.display_name} added parent ${fields.displayName}.` });
    return json(res, 201, parentView(db.prepare('SELECT id, username, display_name, created_at FROM parents WHERE id = ?').get(id), parent.id));
  }

  const parentMatch = path.match(/^\/api\/parents\/([^/]+)$/);
  if (parentMatch && req.method === 'PUT') {
    const existing = db.prepare('SELECT * FROM parents WHERE id = ?').get(parentMatch[1]);
    if (!existing) return json(res, 404, { error: 'Parent not found.' });
    const body = await bodyJson(req);
    const username = body.username == null ? { username: existing.username } : validateUsername(body.username);
    if (username.error) return json(res, 400, { error: username.error });
    const displayName = body.displayName == null ? { displayName: existing.display_name } : validateDisplayName(body.displayName);
    if (displayName.error) return json(res, 400, { error: displayName.error });
    const password = validatePassword(body.password, { required: false });
    if (password.error) return json(res, 400, { error: password.error });
    const pin = validatePin(body.pin, { required: false });
    if (pin.error) return json(res, 400, { error: pin.error });
    try {
      db.prepare('UPDATE parents SET username = ?, display_name = ? WHERE id = ?')
        .run(username.username, displayName.displayName, existing.id);
      if (password.password) {
        db.prepare('UPDATE parents SET password_hash = ? WHERE id = ?').run(hashPassword(password.password), existing.id);
      }
      if (pin.pin) {
        db.prepare('UPDATE parents SET pin_hash = ? WHERE id = ?').run(hashPin(pin.pin), existing.id);
      }
    } catch (error) {
      if (String(error.message).includes('UNIQUE')) return json(res, 409, { error: 'That username already exists.' });
      throw error;
    }
    if (password.password) {
      const currentHash = sha256(parseCookies(req).oc_session ?? '');
      if (existing.id === parent.id) {
        db.prepare('DELETE FROM sessions WHERE parent_id = ? AND token_hash != ?').run(existing.id, currentHash);
      } else {
        db.prepare('DELETE FROM sessions WHERE parent_id = ?').run(existing.id);
      }
    }
    audit(db, {
      parentId: parent.id,
      eventType: 'parent.updated',
      summary: `${parent.display_name} updated parent ${displayName.displayName}.`,
      details: { targetParentId: existing.id, passwordChanged: Boolean(password.password), pinChanged: Boolean(pin.pin) },
    });
    const current = db.prepare('SELECT id, username, display_name, created_at FROM parents WHERE id = ?').get(existing.id);
    return json(res, 200, parentView(current, parent.id));
  }

  if (parentMatch && req.method === 'DELETE') {
    const existing = db.prepare('SELECT * FROM parents WHERE id = ?').get(parentMatch[1]);
    if (!existing) return json(res, 404, { error: 'Parent not found.' });
    if (existing.id === parent.id) return json(res, 409, { error: 'Sign in as another parent before removing your own account.' });
    const count = db.prepare('SELECT COUNT(*) AS count FROM parents').get().count;
    if (count <= 1) return json(res, 409, { error: 'The last parent account cannot be removed.' });
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare('UPDATE enrollment_codes SET created_by = ? WHERE created_by = ?').run(parent.id, existing.id);
      db.prepare('UPDATE overrides SET parent_id = NULL WHERE parent_id = ?').run(existing.id);
      db.prepare('DELETE FROM parents WHERE id = ?').run(existing.id);
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
    audit(db, { parentId: parent.id, eventType: 'parent.removed', summary: `${parent.display_name} removed parent ${existing.display_name}.` });
    return noContent(res);
  }

  if (req.method === 'GET' && path === '/api/services') {
    return json(res, 200, { services: SERVICE_CATALOG });
  }

  if (req.method === 'GET' && path === '/api/devices') {
    const devices = db.prepare('SELECT * FROM devices ORDER BY name COLLATE NOCASE').all().map(deviceView);
    return json(res, 200, { devices });
  }

  const deviceMatch = path.match(/^\/api\/devices\/([^/]+)$/);
  if (deviceMatch && req.method === 'PUT') {
    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceMatch[1]);
    if (!device) return json(res, 404, { error: 'Device not found.' });
    const body = await bodyJson(req);
    const name = String(body.name ?? '').trim();
    if (!name || name.length > 100) return json(res, 400, { error: 'A valid name is required.' });
    db.prepare('UPDATE devices SET name = ? WHERE id = ?').run(name, device.id);
    audit(db, { parentId: parent.id, deviceId: device.id, eventType: 'device.renamed', summary: `${parent.display_name} renamed ${device.name} to ${name}.` });
    return json(res, 200, { ...deviceView(db.prepare('SELECT * FROM devices WHERE id = ?').get(device.id)) });
  }
  if (deviceMatch && req.method === 'DELETE') {
    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceMatch[1]);
    if (!device) return json(res, 404, { error: 'Device not found.' });
    if (resolvePolicy(db, device).internetBlocked) {
      return json(res, 409, { error: 'Restore this device’s internet access before removing it.' });
    }
    db.exec('BEGIN IMMEDIATE');
    try {
      audit(db, {
        parentId: parent.id,
        deviceId: device.id,
        eventType: 'device.removed',
        summary: `${parent.display_name} removed ${device.name} from the dashboard.`,
        details: { name: device.name, platform: device.platform },
      });
      db.prepare('DELETE FROM devices WHERE id = ?').run(device.id);
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
    try { await unlink(screenshotPath(device.id)); } catch { /* no screenshot stored */ }
    return noContent(res);
  }

  const screenshotMatch = path.match(/^\/api\/devices\/([^/]+)\/screenshot$/);
  if (screenshotMatch && req.method === 'POST') {
    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(screenshotMatch[1]);
    if (!device) return json(res, 404, { error: 'Device not found.' });
    if (device.platform !== 'windows') return json(res, 409, { error: 'Desktop screenshots are available on Windows devices.' });
    if (!safeJson(device.capabilities_json, []).includes('desktop-screenshot')) {
      return json(res, 409, { error: 'Update this device client before capturing the screen.' });
    }
    const requestId = randomUUID();
    db.prepare('UPDATE devices SET screenshot_request_id = ?, screenshot_error = NULL WHERE id = ?').run(requestId, device.id);
    audit(db, { parentId: parent.id, deviceId: device.id, eventType: 'screenshot.requested', summary: `${parent.display_name} requested a desktop screenshot of ${device.name}.` });
    return json(res, 202, deviceView(db.prepare('SELECT * FROM devices WHERE id = ?').get(device.id)));
  }
  if (screenshotMatch && req.method === 'GET') {
    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(screenshotMatch[1]);
    if (!device) return json(res, 404, { error: 'Device not found.' });
    const filePath = screenshotPath(device.id);
    if (!device.screenshot_captured_at || !existsSync(filePath)) return json(res, 404, { error: 'No screenshot is available yet.' });
    const content = await readFile(filePath);
    res.writeHead(200, securityHeaders({
      'Content-Type': 'image/jpeg',
      'Content-Length': content.length,
      'Cache-Control': 'no-store',
    }));
    res.end(content);
    return;
  }

  const overrideMatch = path.match(/^\/api\/devices\/([^/]+)\/override$/);
  if (overrideMatch && req.method === 'PUT') {
    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(overrideMatch[1]);
    if (!device) return json(res, 404, { error: 'Device not found.' });
    const body = await bodyJson(req);
    const targetType = String(body.targetType ?? '');
    const targetId = String(body.targetId ?? '');
    const action = String(body.action ?? '');
    if (!validateOverride(targetType, targetId, action)) return json(res, 400, { error: 'Invalid override.' });
    const message = targetType === 'internet' && action === 'block' ? String(body.message ?? '').trim() : null;
    if (targetType === 'internet' && action === 'block' && (!message || message.length > 240)) {
      return json(res, 400, { error: 'Enter a message between 1 and 240 characters.' });
    }
    if (targetType === 'internet' && action === 'block' && !supportsInternetPause(device)) {
      return json(res, 409, { error: 'Update this device client before using Internet pause.' });
    }
    if (targetType === 'target' && !db.prepare('SELECT 1 FROM device_targets WHERE device_id = ? AND target_key = ?').get(device.id, targetId)) {
      return json(res, 404, { error: 'Discovered target not found.' });
    }
    if (targetType === 'website' && !db.prepare('SELECT 1 FROM custom_websites WHERE device_id = ? AND id = ?').get(device.id, targetId)) {
      return json(res, 404, { error: 'Custom website not found.' });
    }
    const effectiveUntil = calculateEffectiveUntil(body);
    const id = insertOverride({
      deviceId: device.id,
      targetType,
      targetId,
      action,
      effectiveUntil,
      source: 'dashboard',
      parentId: parent.id,
      message,
    });
    audit(db, {
      parentId: parent.id,
      deviceId: device.id,
      eventType: 'override.dashboard',
      summary: targetType === 'internet'
        ? `${parent.display_name} ${action === 'block' ? 'paused' : 'restored'} internet access on ${device.name}.`
        : `${parent.display_name} set ${targetId} to ${action} on ${device.name}.`,
      details: { targetType, targetId, action, effectiveUntil, overrideId: id, message },
    });
    const current = db.prepare('SELECT * FROM devices WHERE id = ?').get(device.id);
    return json(res, 201, { overrideId: id, policy: resolvePolicy(db, current) });
  }

  const websitesMatch = path.match(/^\/api\/devices\/([^/]+)\/websites$/);
  if (websitesMatch && req.method === 'POST') {
    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(websitesMatch[1]);
    if (!device) return json(res, 404, { error: 'Device not found.' });
    const body = await bodyJson(req);
    const domain = normalizeWebsite(body.url);
    if (!domain) return json(res, 400, { error: 'Enter a valid public website or URL.' });
    const displayName = String(body.displayName ?? '').trim() || domain;
    if (displayName.length > 100) return json(res, 400, { error: 'Website name must be 100 characters or fewer.' });
    const id = randomUUID();
    const now = new Date().toISOString();
    try {
      db.prepare(`
        INSERT INTO custom_websites (id, device_id, display_name, domain, default_blocked, created_at, updated_at)
        VALUES (?, ?, ?, ?, 1, ?, ?)
      `).run(id, device.id, displayName, domain, now, now);
    } catch (error) {
      if (String(error.message).includes('UNIQUE')) return json(res, 409, { error: 'That website is already listed for this device.' });
      throw error;
    }
    incrementRevision(device.id);
    audit(db, { parentId: parent.id, deviceId: device.id, eventType: 'website.added', summary: `${parent.display_name} added ${domain} to ${device.name}.`, details: { id, domain } });
    return json(res, 201, { id, displayName, domain, configuredBlocked: true, blocked: true });
  }

  const executablesMatch = path.match(/^\/api\/devices\/([^/]+)\/executables$/);
  if (executablesMatch && req.method === 'POST') {
    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(executablesMatch[1]);
    if (!device) return json(res, 404, { error: 'Device not found.' });
    if (device.platform !== 'windows') return json(res, 409, { error: 'Executable paths can be added on Windows devices only.' });
    const body = await bodyJson(req);
    const executable = normalizeExecutablePath(body.path);
    if (!executable) return json(res, 400, { error: 'Enter a local Windows .exe path such as C:\\Games\\App\\App.exe.' });
    const displayName = String(body.displayName ?? '').trim() || executable.fileName.replace(/\.exe$/i, '');
    if (displayName.length > 100) return json(res, 400, { error: 'Program name must be 100 characters or fewer.' });
    const now = new Date().toISOString();
    const existing = db.prepare('SELECT * FROM device_targets WHERE device_id = ? AND target_key = ?').get(device.id, executable.key);
    if (existing) return json(res, 409, { error: 'That executable is already listed for this device.' });
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare(`
        INSERT INTO device_targets
          (device_id, target_key, display_name, target_kind, category_guess, mapping_json, source, currently_running, first_seen, last_seen)
        VALUES (?, ?, ?, 'application', 'unknown', ?, 'parent-path', 0, ?, ?)
      `).run(
        device.id,
        executable.key,
        displayName,
        JSON.stringify({ processes: [executable.fileName], paths: [executable.path] }),
        now,
        now,
      );
      insertOverride({
        deviceId: device.id,
        targetType: 'target',
        targetId: executable.key,
        action: 'block',
        effectiveUntil: null,
        source: 'dashboard',
        parentId: parent.id,
      });
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      if (String(error.message).includes('UNIQUE')) return json(res, 409, { error: 'That executable is already listed for this device.' });
      throw error;
    }
    audit(db, {
      parentId: parent.id,
      deviceId: device.id,
      eventType: 'executable.added',
      summary: `${parent.display_name} added ${executable.fileName} to ${device.name}.`,
      details: { key: executable.key, path: executable.path },
    });
    return json(res, 201, {
      key: executable.key,
      displayName,
      path: executable.path,
      configuredBlocked: true,
      blocked: true,
    });
  }

  const executableDeleteMatch = path.match(/^\/api\/devices\/([^/]+)\/executables\/([^/]+)$/);
  if (executableDeleteMatch && req.method === 'DELETE') {
    const target = db.prepare('SELECT * FROM device_targets WHERE device_id = ? AND target_key = ?')
      .get(executableDeleteMatch[1], decodeURIComponent(executableDeleteMatch[2]));
    if (!target || target.source !== 'parent-path') return json(res, 404, { error: 'Executable path not found.' });
    db.prepare('DELETE FROM device_targets WHERE device_id = ? AND target_key = ?').run(target.device_id, target.target_key);
    db.prepare("UPDATE overrides SET status = 'cancelled' WHERE device_id = ? AND target_type = 'target' AND target_id = ?")
      .run(target.device_id, target.target_key);
    incrementRevision(target.device_id);
    audit(db, {
      parentId: parent.id,
      deviceId: target.device_id,
      eventType: 'executable.removed',
      summary: `${parent.display_name} removed ${target.display_name}.`,
    });
    return noContent(res);
  }

  const websiteDeleteMatch = path.match(/^\/api\/devices\/([^/]+)\/websites\/([^/]+)$/);
  if (websiteDeleteMatch && req.method === 'DELETE') {
    const website = db.prepare('SELECT * FROM custom_websites WHERE device_id = ? AND id = ?').get(websiteDeleteMatch[1], websiteDeleteMatch[2]);
    if (!website) return json(res, 404, { error: 'Custom website not found.' });
    db.prepare('DELETE FROM custom_websites WHERE id = ?').run(website.id);
    db.prepare("UPDATE overrides SET status = 'cancelled' WHERE device_id = ? AND target_type = 'website' AND target_id = ?").run(website.device_id, website.id);
    incrementRevision(website.device_id);
    audit(db, { parentId: parent.id, deviceId: website.device_id, eventType: 'website.removed', summary: `${parent.display_name} removed ${website.domain}.` });
    return noContent(res);
  }

  const deleteOverrideMatch = path.match(/^\/api\/overrides\/([^/]+)$/);
  if (deleteOverrideMatch && req.method === 'DELETE') {
    const existing = db.prepare('SELECT * FROM overrides WHERE id = ?').get(deleteOverrideMatch[1]);
    if (!existing) return json(res, 404, { error: 'Override not found.' });
    db.prepare("UPDATE overrides SET status = 'cancelled' WHERE id = ?").run(existing.id);
    incrementRevision(existing.device_id);
    audit(db, { parentId: parent.id, deviceId: existing.device_id, eventType: 'override.cancelled', summary: `${parent.display_name} cancelled an override.` });
    return noContent(res);
  }

  if (req.method === 'POST' && path === '/api/enrollment-codes') {
    const code = randomEnrollmentCode();
    const now = new Date();
    const expires = new Date(now.valueOf() + 10 * 60 * 1000);
    db.prepare(`
      INSERT INTO enrollment_codes (code_hash, created_by, expires_at, created_at)
      VALUES (?, ?, ?, ?)
    `).run(sha256(code), parent.id, expires.toISOString(), now.toISOString());
    audit(db, { parentId: parent.id, eventType: 'enrollment.created', summary: `${parent.display_name} created a device enrollment code.` });
    return json(res, 201, { code, expiresAt: expires.toISOString(), serverUrl: appBaseUrl });
  }

  if (req.method === 'GET' && path === '/api/audit') {
    const events = db.prepare(`
      SELECT a.*, p.display_name AS parent_name, d.name AS device_name
      FROM audit_events a
      LEFT JOIN parents p ON p.id = a.parent_id
      LEFT JOIN devices d ON d.id = a.device_id
      ORDER BY a.occurred_at DESC LIMIT 100
    `).all().map((event) => ({
      id: event.id,
      occurredAt: event.occurred_at,
      parentName: event.parent_name,
      deviceName: event.device_name,
      eventType: event.event_type,
      summary: event.summary,
      details: safeJson(event.details_json, {}),
    }));
    return json(res, 200, { events });
  }

  return json(res, 404, { error: 'API route not found.' });
}

async function serveStatic(res, pathname) {
  const relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const filePath = resolve(join(publicDir, relative));
  if (!filePath.startsWith(`${publicDir}\\`) && filePath !== join(publicDir, 'index.html') && process.platform === 'win32') return false;
  if (!filePath.startsWith(`${publicDir}/`) && filePath !== join(publicDir, 'index.html') && process.platform !== 'win32') return false;
  if (!existsSync(filePath)) return false;
  const content = await readFile(filePath);
  res.writeHead(200, securityHeaders({
    'Content-Type': mimeTypes[extname(filePath)] ?? 'application/octet-stream',
    'Content-Length': content.length,
    'Cache-Control': 'no-cache',
  }));
  res.end(content);
  return true;
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, appBaseUrl);
    if (req.method === 'GET' && url.pathname === '/healthz') {
      return json(res, 200, { ok: true, version: '0.3.11' });
    }
    if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
    if (req.method === 'GET' && await serveStatic(res, url.pathname)) return;
    json(res, 404, { error: 'Not found.' });
  } catch (error) {
    console.error(error);
    if (!res.headersSent) json(res, 500, { error: 'Unexpected server error.' });
    else res.destroy();
  }
});

db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(new Date().toISOString());
server.listen(port, '0.0.0.0', () => {
  console.log(`ParentGate listening on port ${port}`);
});
