const state = { csrf: null, me: null, devices: [], setupRequired: false };
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

async function api(path, options = {}) {
  const headers = { ...(options.headers ?? {}) };
  if (options.body && typeof options.body !== 'string') {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(options.body);
  }
  if (state.csrf && !['GET', 'HEAD'].includes(options.method ?? 'GET')) headers['X-CSRF-Token'] = state.csrf;
  const response = await fetch(path, { credentials: 'same-origin', ...options, headers });
  const contentType = response.headers.get('content-type') ?? '';
  const body = contentType.includes('application/json') ? await response.json() : null;
  if (!response.ok) {
    const error = new Error(body?.error ?? `Request failed (${response.status}).`);
    error.status = response.status;
    error.body = body;
    throw error;
  }
  return body;
}

function showNotice(message, isError = false) {
  const notice = $('#notice');
  notice.textContent = message;
  notice.hidden = false;
  notice.classList.toggle('error', isError);
  window.setTimeout(() => { notice.hidden = true; }, 5000);
}

async function initialize() {
  const bootstrap = await api('/api/bootstrap');
  state.setupRequired = bootstrap.setupRequired;
  if (bootstrap.setupRequired) return showAuth(true);
  try {
    state.me = await api('/api/me');
    state.csrf = state.me.csrfToken;
    showDashboard();
    await refreshAll();
  } catch (error) {
    if (error.status === 401) showAuth(false);
    else throw error;
  }
}

function showAuth(setup) {
  $('#dashboard').hidden = true;
  $('#auth-view').hidden = false;
  $('#display-name-row').hidden = !setup;
  $('#password-row').hidden = !setup;
  $('#auth-copy').textContent = setup
    ? 'Create the first parent account and a PIN for local device overrides.'
    : 'Sign in to manage household focus controls.';
  const password = $('#auth-form [name=password]');
  password.disabled = !setup;
  password.required = setup;
  const pin = $('#auth-form [name=pin]');
  pin.autocomplete = setup ? 'new-password' : 'current-password';
  $('#pin-row').firstChild.textContent = setup ? 'Local parent PIN' : 'PIN';
  $('#auth-form button[type=submit]').textContent = setup ? 'Create dashboard' : 'Sign in';
}

function showDashboard() {
  $('#auth-view').hidden = true;
  $('#dashboard').hidden = false;
}

async function refreshAll() {
  const [{ devices }, { events }] = await Promise.all([api('/api/devices'), api('/api/audit')]);
  state.devices = devices;
  renderDevices();
  renderAudit(events);
}

function durationFor(card) {
  const value = Number($('.duration-select', card).value);
  return value > 0 ? value : null;
}

function formatLastSeen(device) {
  if (!device.lastSeen) return 'Never connected';
  if (device.online) return 'Online now';
  return `Last seen ${new Date(device.lastSeen).toLocaleString()}`;
}

function renderDevices() {
  const container = $('#devices');
  container.replaceChildren();
  $('#empty-state').hidden = state.devices.length !== 0;
  for (const device of state.devices) {
    const card = $('#device-template').content.firstElementChild.cloneNode(true);
    card.dataset.deviceId = device.id;
    $('.device-name', card).textContent = device.name;
    $('.device-meta', card).textContent = `${device.platform} · ${formatLastSeen(device)}`;
    $('.status-dot', card).classList.toggle('online', device.online);
    const pending = device.desiredRevision !== device.appliedRevision;
    const policyStatus = $('.policy-status', card);
    policyStatus.textContent = pending ? `Pending r${device.desiredRevision}` : `Confirmed r${device.appliedRevision}`;
    policyStatus.classList.toggle('pending', pending);
    for (const button of $$('[data-master-action]', card)) {
      button.classList.toggle('active', (button.dataset.masterAction === 'enable') === device.policy.masterEnabled);
    }
    const internetBlocked = Boolean(device.policy.internetBlocked);
    $('.internet-panel', card).hidden = device.platform === 'ios';
    const internetState = $('.internet-state', card);
    internetState.textContent = internetBlocked ? 'Paused' : 'Available';
    internetState.classList.toggle('blocked', internetBlocked);
    $('.internet-paused', card).hidden = !internetBlocked;
    $('.internet-pause-form', card).hidden = internetBlocked;
    $('.internet-message', card).textContent = device.policy.internetMessage || 'Internet access is paused.';

    const serviceList = $('.service-list', card);
    for (const service of device.policy.services) {
      const row = document.createElement('div');
      row.className = 'service-row';
      row.innerHTML = `
        <div><span class="service-name"></span><span class="service-state"></span></div>
        <div class="service-actions">
          <button class="small allow" data-service-action="allow">Allow</button>
          <button class="small block" data-service-action="block">Block</button>
        </div>`;
      row.dataset.serviceId = service.id;
      $('.service-name', row).textContent = service.displayName;
      const serviceState = $('.service-state', row);
      serviceState.textContent = service.configuredBlocked
        ? (device.policy.masterEnabled ? 'Blocked' : 'Selected · paused')
        : 'Allowed';
      serviceState.classList.toggle('blocked', service.configuredBlocked);
      if (service.warning) row.title = service.warning;
      serviceList.append(row);
    }

    const websiteList = $('.website-list', card);
    const websites = device.policy.customWebsites ?? [];
    if (websites.length === 0) {
      websiteList.innerHTML = '<p class="muted empty-list">No additional websites yet.</p>';
    } else {
      for (const website of websites) {
        const row = document.createElement('div');
        row.className = 'service-row website-row';
        row.dataset.websiteId = website.id;
        row.innerHTML = `
          <div><span class="service-name"></span><span class="service-state"></span><small class="website-domain"></small></div>
          <div class="service-actions">
            <button class="small allow" data-website-action="allow">Allow</button>
            <button class="small block" data-website-action="block">Block</button>
            <button class="small quiet" data-delete-website>Remove</button>
          </div>`;
        $('.service-name', row).textContent = website.displayName;
        $('.website-domain', row).textContent = website.domain;
        const websiteState = $('.service-state', row);
        websiteState.textContent = website.configuredBlocked
          ? (device.policy.masterEnabled ? 'Blocked' : 'Selected · paused')
          : 'Allowed';
        websiteState.classList.toggle('blocked', website.configuredBlocked);
        websiteList.append(row);
      }
    }

    const targets = device.availableTargets ?? [];
    const targetsByKey = new Map(targets.map((target) => [target.key, target]));
    $('.target-count', card).textContent = `(${targets.length})`;
    const targetList = $('.targets-list', card);
    if (targets.length === 0) {
      targetList.innerHTML = '<p class="muted">No candidate applications have been reported yet.</p>';
    } else {
      for (const target of targets) {
        const row = document.createElement('div');
        row.className = 'target-row';
        row.dataset.targetKey = target.key;
        const running = target.currentlyRunning ? '<span class="running-badge">Running</span>' : '';
        row.innerHTML = `
          <div class="target-heading"><div><strong></strong><span class="target-category"></span></div>${running}</div>
          <div class="target-actions">
            <span class="service-state"></span>
            <div class="service-actions">
              <button class="small allow" data-target-action="allow">Allow</button>
              <button class="small block" data-target-action="block">Block</button>
            </div>
          </div>`;
        $('strong', row).textContent = target.displayName;
        $('.target-category', row).textContent = target.categoryGuess && target.categoryGuess !== 'unknown'
          ? `Suggested: ${target.categoryGuess}`
          : 'Uncategorized';
        const targetState = $('.service-state', row);
        targetState.textContent = target.configuredBlocked
          ? (device.policy.masterEnabled ? 'Blocked' : 'Selected · paused')
          : 'Allowed';
        targetState.classList.toggle('blocked', target.configuredBlocked);
        targetList.append(row);
      }
    }

    const activity = device.applicationActivity ?? [];
    const websiteActivity = device.websiteActivity ?? [];
    $('.activity-count', card).textContent = `(${activity.length + websiteActivity.length})`;
    const activityList = $('.application-activity-list', card);
    if (activity.length === 0) {
      activityList.innerHTML = '<p class="muted">No application activity has been reported yet.</p>';
    } else {
      for (const item of activity) {
        const row = document.createElement('div');
        row.className = 'activity-row';
        row.dataset.targetKey = item.targetKey;
        const target = targetsByKey.get(item.targetKey);
        row.innerHTML = `
          <div class="activity-copy">
            <strong></strong>
            <span class="activity-event"></span>
            <time></time>
          </div>
          <button class="small block" data-activity-block>Block</button>`;
        $('strong', row).textContent = item.displayName;
        const eventLabel = $('.activity-event', row);
        eventLabel.textContent = item.eventType === 'started' ? 'Started' : 'Stopped';
        eventLabel.classList.toggle('stopped', item.eventType === 'stopped');
        $('time', row).textContent = new Date(item.occurredAt).toLocaleString();
        const blockButton = $('[data-activity-block]', row);
        if (target?.configuredBlocked) {
          blockButton.textContent = 'Blocked';
          blockButton.disabled = true;
        }
        activityList.append(row);
      }
    }

    const websiteActivityList = $('.website-activity-list', card);
    const blockedWebsiteDomains = new Set((device.policy.customWebsites ?? [])
      .filter((website) => website.configuredBlocked)
      .map((website) => website.domain));
    if (websiteActivity.length === 0) {
      websiteActivityList.innerHTML = '<p class="muted">No website activity has been reported yet. Install the browser extension on this PC to begin.</p>';
    } else {
      for (const item of websiteActivity) {
        const row = document.createElement('div');
        row.className = 'activity-row website-activity-row';
        row.dataset.domain = item.domain;
        row.innerHTML = `
          <div class="activity-copy">
            <strong></strong>
            <span class="activity-event">Visited</span>
            <time></time>
            <small class="activity-browser"></small>
          </div>
          <button class="small block" data-website-activity-block>Block</button>`;
        $('strong', row).textContent = item.domain;
        $('time', row).textContent = new Date(item.occurredAt).toLocaleString();
        $('.activity-browser', row).textContent = item.browser;
        const blockButton = $('[data-website-activity-block]', row);
        if (blockedWebsiteDomains.has(item.domain)) {
          blockButton.textContent = 'Blocked';
          blockButton.disabled = true;
        }
        websiteActivityList.append(row);
      }
    }
    container.append(card);
  }
}

function renderAudit(events) {
  const list = $('#audit-list');
  list.replaceChildren();
  for (const event of events.slice(0, 30)) {
    const row = document.createElement('div');
    row.className = 'audit-item';
    const time = document.createElement('time');
    time.dateTime = event.occurredAt;
    time.textContent = new Date(event.occurredAt).toLocaleString();
    const summary = document.createElement('span');
    summary.textContent = event.summary;
    row.append(time, summary);
    list.append(row);
  }
}

async function applyOverride(card, targetType, targetId, action) {
  const deviceId = card.dataset.deviceId;
  await api(`/api/devices/${encodeURIComponent(deviceId)}/override`, {
    method: 'PUT',
    body: { targetType, targetId, action, durationMinutes: durationFor(card) },
  });
  showNotice(`${targetId} updated.`);
  await refreshAll();
}

$('#auth-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('#auth-error').textContent = '';
  const values = Object.fromEntries(new FormData(event.currentTarget));
  try {
    const result = await api(state.setupRequired ? '/api/setup' : '/api/auth/login', { method: 'POST', body: values });
    state.csrf = result.csrfToken;
    state.me = await api('/api/me');
    state.csrf = state.me.csrfToken;
    showDashboard();
    await refreshAll();
  } catch (error) {
    $('#auth-error').textContent = error.message;
  }
});

$('#devices').addEventListener('click', async (event) => {
  const card = event.target.closest('.device-card');
  if (!card || !event.target.matches('button')) return;
  event.target.disabled = true;
  try {
    if (event.target.dataset.masterAction) await applyOverride(card, 'master', 'blocking', event.target.dataset.masterAction);
    if (event.target.hasAttribute('data-internet-restore')) {
      await api(`/api/devices/${encodeURIComponent(card.dataset.deviceId)}/override`, {
        method: 'PUT',
        body: { targetType: 'internet', targetId: 'access', action: 'allow' },
      });
      showNotice('Internet access restored.');
      await refreshAll();
    }
    if (event.target.dataset.serviceAction) {
      const service = event.target.closest('[data-service-id]').dataset.serviceId;
      await applyOverride(card, 'service', service, event.target.dataset.serviceAction);
    }
    if (event.target.dataset.websiteAction) {
      const website = event.target.closest('[data-website-id]').dataset.websiteId;
      await applyOverride(card, 'website', website, event.target.dataset.websiteAction);
    }
    if (event.target.dataset.targetAction) {
      const target = event.target.closest('[data-target-key]').dataset.targetKey;
      await applyOverride(card, 'target', target, event.target.dataset.targetAction);
    }
    if (event.target.hasAttribute('data-activity-block')) {
      const target = event.target.closest('[data-target-key]').dataset.targetKey;
      await applyOverride(card, 'target', target, 'block');
    }
    if (event.target.hasAttribute('data-website-activity-block')) {
      const domain = event.target.closest('[data-domain]').dataset.domain;
      await api(`/api/devices/${encodeURIComponent(card.dataset.deviceId)}/websites`, {
        method: 'POST',
        body: { url: domain, displayName: domain },
      });
      showNotice(`${domain} added to the block list.`);
      await refreshAll();
    }
    if (event.target.dataset.activityFilter) {
      const selected = event.target.dataset.activityFilter;
      for (const button of $$('[data-activity-filter]', card)) button.classList.toggle('active', button === event.target);
      for (const group of $$('[data-activity-group]', card)) {
        group.hidden = selected !== 'all' && group.dataset.activityGroup !== selected;
      }
    }
    if (event.target.hasAttribute('data-delete-website')) {
      const website = event.target.closest('[data-website-id]').dataset.websiteId;
      await api(`/api/devices/${encodeURIComponent(card.dataset.deviceId)}/websites/${encodeURIComponent(website)}`, { method: 'DELETE' });
      showNotice('Website removed.');
      await refreshAll();
    }
  } catch (error) {
    showNotice(error.message, true);
  } finally {
    event.target.disabled = false;
  }
});

$('#devices').addEventListener('submit', async (event) => {
  if (event.target.matches('.internet-pause-form')) {
    event.preventDefault();
    const card = event.target.closest('.device-card');
    const submit = $('button[type=submit]', event.target);
    submit.disabled = true;
    try {
      const values = Object.fromEntries(new FormData(event.target));
      await api(`/api/devices/${encodeURIComponent(card.dataset.deviceId)}/override`, {
        method: 'PUT',
        body: { targetType: 'internet', targetId: 'access', action: 'block', message: values.message },
      });
      showNotice('Internet pause sent to the device.');
      event.target.reset();
      await refreshAll();
    } catch (error) {
      showNotice(error.message, true);
    } finally {
      submit.disabled = false;
    }
    return;
  }
  if (!event.target.matches('.website-form')) return;
  event.preventDefault();
  const card = event.target.closest('.device-card');
  const submit = $('button[type=submit]', event.target);
  submit.disabled = true;
  try {
    await api(`/api/devices/${encodeURIComponent(card.dataset.deviceId)}/websites`, {
      method: 'POST',
      body: Object.fromEntries(new FormData(event.target)),
    });
    showNotice('Website added and selected for blocking.');
    await refreshAll();
  } catch (error) {
    showNotice(error.message, true);
  } finally {
    submit.disabled = false;
  }
});

function openEnrollment() {
  $('#enrollment-result').innerHTML = '<p>Create a one-time code that remains valid for ten minutes.</p><button id="create-code-button" class="primary" type="button">Create code</button>';
  $('#enroll-dialog').showModal();
}

$('#enroll-button').addEventListener('click', openEnrollment);
$('#empty-state').addEventListener('click', (event) => { if (event.target.dataset.action === 'open-enroll') openEnrollment(); });
$('#enrollment-result').addEventListener('click', async (event) => {
  if (event.target.id !== 'create-code-button') return;
  event.target.disabled = true;
  try {
    const result = await api('/api/enrollment-codes', { method: 'POST', body: {} });
    $('#enrollment-result').innerHTML = `
      <p class="enrollment-code"></p>
      <p class="code-details">Server: <strong></strong></p>
      <p class="muted">Expires <time></time>. Enter this server URL and code in the client installer.</p>`;
    $('.enrollment-code', $('#enrollment-result')).textContent = result.code;
    $('.code-details strong', $('#enrollment-result')).textContent = result.serverUrl;
    $('time', $('#enrollment-result')).textContent = new Date(result.expiresAt).toLocaleTimeString();
  } catch (error) {
    showNotice(error.message, true);
  }
});

$('#parent-button').addEventListener('click', () => $('#parent-dialog').showModal());
$('#parent-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('#parent-error').textContent = '';
  try {
    await api('/api/parents', { method: 'POST', body: Object.fromEntries(new FormData(event.currentTarget)) });
    $('#parent-dialog').close();
    event.currentTarget.reset();
    showNotice('Parent account added. New PIN verifiers will sync to clients.');
  } catch (error) {
    $('#parent-error').textContent = error.message;
  }
});

document.addEventListener('click', (event) => {
  if (event.target.dataset.closeDialog) $(`#${event.target.dataset.closeDialog}`).close();
});
$('#refresh-button').addEventListener('click', () => refreshAll().catch((error) => showNotice(error.message, true)));
$('#logout-button').addEventListener('click', async () => {
  await api('/api/auth/logout', { method: 'POST', body: {} });
  state.csrf = null;
  state.me = null;
  showAuth(false);
});

window.setInterval(() => {
  if (!$('#dashboard').hidden) refreshAll().catch(() => {});
}, 10000);

initialize().catch((error) => {
  document.body.textContent = `Unable to start dashboard: ${error.message}`;
});
