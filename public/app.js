const state = {
  csrf: null,
  me: null,
  devices: [],
  parents: [],
  setupRequired: false,
  lastInteractionAt: 0,
  automaticRefreshPending: false,
};
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
    ? 'Create the first parent account and a PIN for local device overrides. Welcome to ParentGate.'
    : 'Sign in to manage ParentGate focus controls.';
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
  applyPage();
}

function currentPage() {
  return location.hash === '#parents' ? 'parents' : 'devices';
}

function applyPage() {
  const page = currentPage();
  $('#devices-page').hidden = page !== 'devices';
  $('#parents-page').hidden = page !== 'parents';
  $('#parent-button').classList.toggle('primary', page === 'parents');
  $('#parent-button').classList.toggle('secondary', page !== 'parents');
}

function dashboardIsBusy() {
  const active = document.activeElement;
  const editing = active?.matches?.('input, textarea, select, [contenteditable="true"]');
  const dialogOpen = Boolean(document.querySelector('dialog[open]'));
  const recentlyActive = Date.now() - state.lastInteractionAt < 30000;
  return editing || dialogOpen || recentlyActive;
}

async function refreshAll({ automatic = false } = {}) {
  const requests = [api('/api/devices'), api('/api/audit')];
  if (currentPage() === 'parents') requests.push(api('/api/parents'));
  const [{ devices }, { events }, parentsResult] = await Promise.all(requests);
  state.devices = devices;
  if (parentsResult) state.parents = parentsResult.parents;
  if (automatic && dashboardIsBusy()) {
    state.automaticRefreshPending = true;
    return;
  }
  state.automaticRefreshPending = false;
  renderDevices();
  renderAudit(events);
  if (currentPage() === 'parents') renderParents();
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
    const versionState = device.clientVersion
      ? `v${device.clientVersion}${device.updateAvailable ? ` → v${device.latestClientVersion}` : ''}`
      : 'version unknown';
    $('.device-meta', card).textContent = `${device.platform} · ${versionState} · ${formatLastSeen(device)}`;
    $('.status-dot', card).classList.toggle('online', device.online);
    const pending = device.desiredRevision !== device.appliedRevision;
    const policyStatus = $('.policy-status', card);
    policyStatus.textContent = pending ? `Pending r${device.desiredRevision}` : `Confirmed r${device.appliedRevision}`;
    policyStatus.classList.toggle('pending', pending);
    for (const button of $$('[data-master-action]', card)) {
      button.classList.toggle('active', (button.dataset.masterAction === 'enable') === device.policy.masterEnabled);
    }
    const internetBlocked = Boolean(device.policy.internetBlocked);
    const supportsInternetPause = device.capabilities.includes('internet-pause-message');
    $('.internet-panel', card).hidden = device.platform === 'ios';
    const removeDevice = $('[data-remove-device]', card);
    removeDevice.disabled = internetBlocked;
    removeDevice.title = internetBlocked ? 'Restore internet access before removing this device.' : 'Remove this device from the dashboard.';
    const internetState = $('.internet-state', card);
    internetState.textContent = internetBlocked ? 'Paused' : supportsInternetPause ? 'Available' : 'Update required';
    internetState.classList.toggle('blocked', internetBlocked);
    $('.internet-paused', card).hidden = !internetBlocked;
    $('.internet-pause-form', card).hidden = internetBlocked || !supportsInternetPause;
    $('.internet-message', card).textContent = device.policy.internetMessage || 'Internet access is paused.';
    $('.executables-panel', card).hidden = device.platform !== 'windows';

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
        ? (device.policy.masterEnabled ? 'Blocked' : 'Selected · study mode off')
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
          ? (device.policy.masterEnabled ? 'Blocked' : 'Selected · study mode off')
          : 'Allowed';
        websiteState.classList.toggle('blocked', website.configuredBlocked);
        websiteList.append(row);
      }
    }

    const targets = device.availableTargets ?? [];
    const pathTargets = targets.filter((target) => target.source === 'parent-path');
    const discoveredTargets = targets.filter((target) => target.source !== 'parent-path');
    const executableList = $('.executable-list', card);
    if (pathTargets.length === 0) {
      executableList.innerHTML = '<p class="muted empty-list">No extra program paths yet.</p>';
    } else {
      for (const target of pathTargets) {
        const row = document.createElement('div');
        row.className = 'service-row executable-row';
        row.dataset.targetKey = target.key;
        const path = target.mapping?.paths?.[0] || target.mapping?.processes?.[0] || '';
        row.innerHTML = `
          <div><span class="service-name"></span><span class="service-state"></span><small class="executable-path"></small></div>
          <div class="service-actions">
            <button class="small allow" data-target-action="allow">Allow</button>
            <button class="small block" data-target-action="block">Block</button>
            <button class="small quiet" data-delete-executable>Remove</button>
          </div>`;
        $('.service-name', row).textContent = target.displayName;
        $('.executable-path', row).textContent = path;
        const executableState = $('.service-state', row);
        executableState.textContent = target.configuredBlocked
          ? (device.policy.masterEnabled ? 'Blocked' : 'Selected · study mode off')
          : 'Allowed';
        executableState.classList.toggle('blocked', target.configuredBlocked);
        executableList.append(row);
      }
    }

    const targetsByKey = new Map(targets.map((target) => [target.key, target]));
    $('.target-count', card).textContent = `(${discoveredTargets.length})`;
    const targetList = $('.targets-list', card);
    if (discoveredTargets.length === 0) {
      targetList.innerHTML = '<p class="muted">No candidate applications have been reported yet.</p>';
    } else {
      for (const target of discoveredTargets) {
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
          ? (device.policy.masterEnabled ? 'Blocked' : 'Selected · study mode off')
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

function renderParents() {
  const container = $('#parents-list');
  container.replaceChildren();
  const onlyParent = state.parents.length <= 1;
  for (const parent of state.parents) {
    const card = document.createElement('article');
    card.className = 'device-card parent-card';
    card.dataset.parentId = parent.id;
    card.innerHTML = `
      <header class="device-header">
        <div>
          <div class="device-title-row"><h2 class="parent-name"></h2></div>
          <p class="parent-username muted"></p>
          <p class="device-meta muted"></p>
        </div>
        <div class="device-header-actions">
          <span class="you-badge" hidden>You</span>
          <button class="small secondary" data-edit-parent>Edit</button>
          <button class="small quiet" data-remove-parent>Remove</button>
        </div>
      </header>`;
    $('.parent-name', card).textContent = parent.displayName;
    $('.parent-username', card).textContent = parent.username;
    $('.device-meta', card).textContent = parent.createdAt
      ? `Added ${new Date(parent.createdAt).toLocaleString()}`
      : '';
    $('.you-badge', card).hidden = !parent.isSelf;
    const remove = $('[data-remove-parent]', card);
    if (parent.isSelf) {
      remove.disabled = true;
      remove.title = 'Sign in as another parent before removing your own account.';
    } else if (onlyParent) {
      remove.disabled = true;
      remove.title = 'The last parent account cannot be removed.';
    } else {
      remove.title = 'Remove this parent account.';
    }
    container.append(card);
  }
}

function openParentDialog(parent = null) {
  const form = $('#parent-form');
  form.reset();
  $('#parent-error').textContent = '';
  const editing = Boolean(parent);
  form.dataset.parentId = parent?.id ?? '';
  $('#parent-dialog-title').textContent = editing ? 'Edit parent' : 'Add another parent';
  $('#parent-submit').textContent = editing ? 'Save changes' : 'Add parent';
  form.elements.password.required = !editing;
  form.elements.pin.required = !editing;
  form.elements.password.placeholder = editing ? 'Leave blank to keep' : '';
  form.elements.pin.placeholder = editing ? 'Leave blank to keep' : '';
  $('#parent-secret-help').hidden = !editing;
  if (parent) {
    form.elements.displayName.value = parent.displayName;
    form.elements.username.value = parent.username;
  }
  $('#parent-dialog').showModal();
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
    if (event.target.hasAttribute('data-remove-device')) {
      const name = $('.device-name', card).textContent;
      const confirmed = window.confirm(`Remove ${name} from the dashboard?\n\nThis revokes its enrollment but does not uninstall the local client. Run the client uninstaller on that device if it is still available.`);
      if (!confirmed) return;
      await api(`/api/devices/${encodeURIComponent(card.dataset.deviceId)}`, { method: 'DELETE' });
      showNotice(`${name} removed from the dashboard.`);
      await refreshAll();
    }
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
    if (event.target.hasAttribute('data-delete-executable')) {
      const target = event.target.closest('[data-target-key]').dataset.targetKey;
      await api(`/api/devices/${encodeURIComponent(card.dataset.deviceId)}/executables/${encodeURIComponent(target)}`, { method: 'DELETE' });
      showNotice('Program path removed.');
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
  if (event.target.matches('.executable-form')) {
    event.preventDefault();
    const card = event.target.closest('.device-card');
    const submit = $('button[type=submit]', event.target);
    submit.disabled = true;
    try {
      await api(`/api/devices/${encodeURIComponent(card.dataset.deviceId)}/executables`, {
        method: 'POST',
        body: Object.fromEntries(new FormData(event.target)),
      });
      showNotice('Program added and selected for blocking.');
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

$('#home-button').addEventListener('click', () => {
  if (location.hash) location.hash = '';
  else applyPage();
});
$('#parent-button').addEventListener('click', () => {
  if (location.hash === '#parents') {
    applyPage();
    refreshAll().catch((error) => showNotice(error.message, true));
  } else {
    location.hash = '#parents';
  }
});
$('#add-parent-button').addEventListener('click', () => openParentDialog());
$('#parents-list').addEventListener('click', async (event) => {
  const card = event.target.closest('.parent-card');
  if (!card || !event.target.matches('button')) return;
  const parent = state.parents.find((item) => item.id === card.dataset.parentId);
  if (!parent) return;
  if (event.target.hasAttribute('data-edit-parent')) {
    openParentDialog(parent);
    return;
  }
  if (!event.target.hasAttribute('data-remove-parent')) return;
  const confirmed = window.confirm(`Remove ${parent.displayName} from the dashboard?\n\nThey will no longer be able to sign in or use a local PIN.`);
  if (!confirmed) return;
  event.target.disabled = true;
  try {
    await api(`/api/parents/${encodeURIComponent(parent.id)}`, { method: 'DELETE' });
    showNotice(`${parent.displayName} removed.`);
    await refreshAll();
  } catch (error) {
    showNotice(error.message, true);
    event.target.disabled = false;
  }
});
$('#parent-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('#parent-error').textContent = '';
  const form = event.currentTarget;
  const values = Object.fromEntries(new FormData(form));
  const editing = Boolean(form.dataset.parentId);
  const body = {
    displayName: values.displayName,
    username: values.username,
  };
  if (values.password) body.password = values.password;
  if (values.pin) body.pin = values.pin;
  try {
    if (editing) {
      await api(`/api/parents/${encodeURIComponent(form.dataset.parentId)}`, { method: 'PUT', body });
      showNotice('Parent account updated.');
    } else {
      await api('/api/parents', { method: 'POST', body });
      showNotice('Parent account added. New PIN verifiers will sync to clients.');
    }
    $('#parent-dialog').close();
    form.reset();
    if (editing && form.dataset.parentId === state.me?.id) {
      state.me = await api('/api/me');
      state.csrf = state.me.csrfToken;
    }
    await refreshAll();
  } catch (error) {
    $('#parent-error').textContent = error.message;
  }
});
window.addEventListener('hashchange', () => {
  applyPage();
  if ($('#dashboard').hidden) return;
  refreshAll().catch((error) => showNotice(error.message, true));
});

document.addEventListener('click', (event) => {
  if (event.target.dataset.closeDialog) $(`#${event.target.dataset.closeDialog}`).close();
});

for (const eventName of ['pointerdown', 'keydown', 'input', 'change']) {
  document.addEventListener(eventName, (event) => {
    if (event.isTrusted && !$('#dashboard').hidden) state.lastInteractionAt = Date.now();
  }, { passive: true });
}
window.addEventListener('scroll', (event) => {
  if (event.isTrusted && !$('#dashboard').hidden) state.lastInteractionAt = Date.now();
}, { passive: true });

$('#refresh-button').addEventListener('click', () => refreshAll().catch((error) => showNotice(error.message, true)));
$('#logout-button').addEventListener('click', async () => {
  await api('/api/auth/logout', { method: 'POST', body: {} });
  state.csrf = null;
  state.me = null;
  showAuth(false);
});

window.setInterval(() => {
  if (!$('#dashboard').hidden) refreshAll({ automatic: true }).catch(() => {});
}, 10000);

initialize().catch((error) => {
  document.body.textContent = `Unable to start ParentGate: ${error.message}`;
});
