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
  $('#pin-row').hidden = !setup;
  $('#auth-copy').textContent = setup
    ? 'Create the first parent account and a PIN for local device overrides.'
    : 'Sign in to manage household focus controls.';
  const password = $('#auth-form [name=password]');
  password.autocomplete = setup ? 'new-password' : 'current-password';
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
    for (const button of $$('[data-profile]', card)) button.classList.toggle('active', button.dataset.profile === device.policy.profile);

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
      serviceState.textContent = service.blocked ? 'Blocked' : 'Allowed';
      serviceState.classList.toggle('blocked', service.blocked);
      if (service.warning) row.title = service.warning;
      serviceList.append(row);
    }

    const targets = device.availableTargets ?? [];
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
          <div class="profile-checks">
            <label><input type="checkbox" data-target-profile="homework"> Homework</label>
            <label><input type="checkbox" data-target-profile="deep-focus"> Deep Focus</label>
          </div>`;
        $('strong', row).textContent = target.displayName;
        $('.target-category', row).textContent = target.categoryGuess && target.categoryGuess !== 'unknown'
          ? `Suggested: ${target.categoryGuess}`
          : 'Uncategorized';
        for (const checkbox of $$('[data-target-profile]', row)) checkbox.checked = target.profiles.includes(checkbox.dataset.targetProfile);
        targetList.append(row);
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
    if (event.target.dataset.profile) await applyOverride(card, 'profile', event.target.dataset.profile, 'set');
    if (event.target.dataset.categoryAction) await applyOverride(card, 'category', 'streaming', event.target.dataset.categoryAction);
    if (event.target.dataset.serviceAction) {
      const service = event.target.closest('[data-service-id]').dataset.serviceId;
      await applyOverride(card, 'service', service, event.target.dataset.serviceAction);
    }
  } catch (error) {
    showNotice(error.message, true);
  } finally {
    event.target.disabled = false;
  }
});

$('#devices').addEventListener('change', async (event) => {
  if (!event.target.matches('[data-target-profile]')) return;
  const card = event.target.closest('.device-card');
  const row = event.target.closest('[data-target-key]');
  const profiles = $$('[data-target-profile]:checked', row).map((box) => box.dataset.targetProfile);
  event.target.disabled = true;
  try {
    await api(`/api/devices/${encodeURIComponent(card.dataset.deviceId)}/targets`, {
      method: 'PUT',
      body: { targetKey: row.dataset.targetKey, profiles },
    });
    showNotice(`${$('strong', row).textContent} profile assignment updated.`);
  } catch (error) {
    showNotice(error.message, true);
    await refreshAll();
  } finally {
    event.target.disabled = false;
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
