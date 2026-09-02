import { SERVICE_CATALOG } from './catalog.js';

function latestByTarget(overrides, targetType) {
  const result = new Map();
  for (const override of overrides) {
    if (override.target_type === targetType) result.set(override.target_id, override);
  }
  return result;
}

export function resolvePolicy(db, device, now = new Date(), expiryDepth = 0) {
  const nowIso = now.toISOString();
  const overrides = db.prepare(`
    SELECT * FROM overrides
    WHERE device_id = ? AND status = 'accepted'
      AND (effective_until IS NULL OR effective_until > ?)
    ORDER BY created_at ASC, rowid ASC
  `).all(device.id, nowIso).filter((item) => ['master', 'service', 'target', 'website', 'internet'].includes(item.target_type));

  const masterOverride = overrides.filter((item) => item.target_type === 'master').at(-1);
  const masterEnabled = masterOverride ? masterOverride.action === 'enable' : true;
  const internetOverride = overrides.filter((item) => item.target_type === 'internet').at(-1);
  const internetBlocked = internetOverride?.action === 'block';
  const configuredServices = new Map(SERVICE_CATALOG.map((service) => [service.id, false]));

  for (const [serviceId, override] of latestByTarget(overrides, 'service')) {
    if (configuredServices.has(serviceId)) configuredServices.set(serviceId, override.action === 'block');
  }

  const nextExpiry = overrides
    .map((item) => item.effective_until)
    .filter(Boolean)
    .sort()[0] ?? null;

  const targetOverrides = latestByTarget(overrides, 'target');
  const customTargets = db.prepare(`
    SELECT * FROM device_targets WHERE device_id = ? ORDER BY display_name COLLATE NOCASE
  `).all(device.id).map((target) => {
    const configuredBlocked = targetOverrides.get(target.target_key)?.action === 'block';
    return {
      key: target.target_key,
      displayName: target.display_name,
      kind: target.target_kind,
      categoryGuess: target.category_guess,
      mapping: JSON.parse(target.mapping_json),
      configuredBlocked,
      blocked: masterEnabled && configuredBlocked,
    };
  });

  const websiteOverrides = latestByTarget(overrides, 'website');
  const customWebsites = db.prepare(`
    SELECT * FROM custom_websites WHERE device_id = ? ORDER BY display_name COLLATE NOCASE
  `).all(device.id).map((website) => {
    const configuredBlocked = websiteOverrides.has(website.id)
      ? websiteOverrides.get(website.id).action === 'block'
      : Boolean(website.default_blocked);
    return {
      id: website.id,
      displayName: website.display_name,
      domain: website.domain,
      configuredBlocked,
      blocked: masterEnabled && configuredBlocked,
    };
  });

  const policy = {
    revision: device.desired_revision,
    generatedAt: nowIso,
    profile: 'custom',
    profileDisplayName: 'Custom controls',
    effectiveUntil: null,
    masterEnabled,
    nextExpiry,
    services: SERVICE_CATALOG.map((service) => ({
      ...service,
      configuredBlocked: configuredServices.get(service.id),
      blocked: masterEnabled && configuredServices.get(service.id),
    })),
    customTargets,
    customWebsites,
    internetBlocked,
    internetMessage: internetBlocked ? internetOverride.message : null,
    internetNoticeId: internetBlocked ? internetOverride.id : null,
  };
  if (nextExpiry && expiryDepth < 20) {
    policy.afterExpiry = resolvePolicy(db, device, new Date(new Date(nextExpiry).valueOf() + 1), expiryDepth + 1);
  }
  return policy;
}

export function validateOverride(targetType, targetId, action) {
  if (targetType === 'master') {
    return targetId === 'blocking' && ['enable', 'disable'].includes(action);
  }
  if (targetType === 'internet') {
    return targetId === 'access' && ['allow', 'block'].includes(action);
  }
  if (targetType === 'service') {
    return SERVICE_CATALOG.some((service) => service.id === targetId) && ['allow', 'block'].includes(action);
  }
  if (['target', 'website'].includes(targetType)) {
    return targetId.length >= 1 && targetId.length <= 180 && ['allow', 'block'].includes(action);
  }
  return false;
}

export function calculateEffectiveUntil(body, now = new Date()) {
  if (body.effectiveUntil) {
    const parsed = new Date(body.effectiveUntil);
    if (!Number.isNaN(parsed.valueOf()) && parsed > now) return parsed.toISOString();
  }
  if (body.durationMinutes != null) {
    const minutes = Number(body.durationMinutes);
    if (Number.isFinite(minutes) && minutes > 0 && minutes <= 10080) {
      return new Date(now.valueOf() + minutes * 60000).toISOString();
    }
  }
  return null;
}
