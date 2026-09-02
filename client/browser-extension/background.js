const endpoint = 'http://127.0.0.1:8765/browser-event';
let flushing = false;

function browserName() {
  const agent = navigator.userAgent;
  if (agent.includes('Edg/')) return 'Microsoft Edge';
  if (agent.includes('OPR/')) return 'Opera';
  if (agent.includes('Chrome/')) return 'Google Chrome';
  return 'Chromium browser';
}

async function pendingEvents() {
  const result = await chrome.storage.local.get({ pendingWebsiteEvents: [] });
  return result.pendingWebsiteEvents;
}

async function savePending(events) {
  await chrome.storage.local.set({ pendingWebsiteEvents: events.slice(-2000) });
}

async function queueVisit(domain, occurredAt) {
  const pending = await pendingEvents();
  pending.push({
    id: crypto.randomUUID(),
    domain,
    browser: browserName(),
    occurredAt,
  });
  await savePending(pending);
  await flushPending();
}

async function flushPending() {
  if (flushing) return;
  flushing = true;
  try {
    const pending = await pendingEvents();
    while (pending.length > 0) {
      const event = pending[0];
      let response;
      try {
        response = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(event),
        });
      } catch {
        break;
      }
      if (!response.ok) break;
      pending.shift();
      await savePending(pending);
    }
  } finally {
    flushing = false;
  }
}

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  try {
    const url = new URL(details.url);
    if (!['http:', 'https:'].includes(url.protocol)) return;
    const domain = url.hostname.toLowerCase().replace(/^\.+|\.+$/g, '');
    if (!domain.includes('.') || ['127.0.0.1', 'localhost'].includes(domain)) return;
    void queueVisit(domain, new Date(details.timeStamp).toISOString());
  } catch {
    // Ignore browser-internal and malformed navigation URLs.
  }
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create('flushWebsiteEvents', { periodInMinutes: 1 });
  void flushPending();
});
chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.create('flushWebsiteEvents', { periodInMinutes: 1 });
  void flushPending();
});
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'flushWebsiteEvents') void flushPending();
});
