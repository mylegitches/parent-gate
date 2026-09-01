import { PROFILE_DEFINITIONS, SERVICE_CATALOG } from './catalog.js';

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
  `).all(device.id, nowIso);

  const profileOverride = overrides.filter((item) => item.target_type === 'profile').at(-1);
  const profileId = profileOverride?.target_id ?? 'normal';
  const profile = PROFILE_DEFINITIONS[profileId] ?? PROFILE_DEFINITIONS.normal;
  const blocked = new Map(SERVICE_CATALOG.map((service) => [service.id, false]));

  for (const serviceId of profile.blockedServices ?? []) blocked.set(serviceId, true);
  for (const category of profile.blockedCategories ?? []) {
    for (const service of SERVICE_CATALOG) {
      if (service.category === category) blocked.set(service.id, true);
    }
  }

  for (const [category, override] of latestByTarget(overrides, 'category')) {
    for (const service of SERVICE_CATALOG) {
      if (service.category === category) blocked.set(service.id, override.action === 'block');
    }
  }

  for (const [serviceId, override] of latestByTarget(overrides, 'service')) {
    if (blocked.has(serviceId)) blocked.set(serviceId, override.action === 'block');
  }

  const nextExpiry = overrides
    .map((item) => item.effective_until)
    .filter(Boolean)
    .sort()[0] ?? null;

  const customTargets = db.prepare(`
    SELECT t.*, GROUP_CONCAT(p.profile_id) AS profile_ids
    FROM device_targets t
    JOIN device_target_profiles p
      ON p.device_id = t.device_id AND p.target_key = t.target_key
    WHERE t.device_id = ?
    GROUP BY t.device_id, t.target_key
    ORDER BY t.display_name COLLATE NOCASE
  `).all(device.id).map((target) => {
    const profiles = String(target.profile_ids ?? '').split(',').filter(Boolean);
    return {
      key: target.target_key,
      displayName: target.display_name,
      kind: target.target_kind,
      categoryGuess: target.category_guess,
      mapping: JSON.parse(target.mapping_json),
      profiles,
      blocked: profiles.includes(profileId),
    };
  });

  const policy = {
    revision: device.desired_revision,
    generatedAt: nowIso,
    profile: profileId,
    profileDisplayName: profile.displayName,
    effectiveUntil: profileOverride?.effective_until ?? null,
    nextExpiry,
    services: SERVICE_CATALOG.map((service) => ({
      ...service,
      blocked: blocked.get(service.id),
    })),
    customTargets,
    internetBlocked: false,
  };
  if (nextExpiry && expiryDepth < 20) {
    policy.afterExpiry = resolvePolicy(db, device, new Date(new Date(nextExpiry).valueOf() + 1), expiryDepth + 1);
  }
  return policy;
}

export function validateOverride(targetType, targetId, action) {
  if (targetType === 'profile') {
    return action === 'set' && Object.hasOwn(PROFILE_DEFINITIONS, targetId);
  }
  if (targetType === 'category') {
    return ['social', 'streaming'].includes(targetId) && ['allow', 'block'].includes(action);
  }
  if (targetType === 'service') {
    return SERVICE_CATALOG.some((service) => service.id === targetId) && ['allow', 'block'].includes(action);
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
