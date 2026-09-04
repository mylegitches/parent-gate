# ParentGate browser extension

This unpacked Manifest V3 extension reports top-level website hostnames to the ParentGate Windows client at `http://127.0.0.1:8765`.

It reports only:

- hostname, such as `messages.google.com`;
- browser name;
- navigation timestamp;
- a random event ID used for retry deduplication.

It does not report page paths, query strings, searches, titles, page content, form input, or subframe/background requests.

## Install in Microsoft Edge

1. Open `edge://extensions`.
2. Turn on **Developer mode**.
3. Choose **Load unpacked**.
4. Select `C:\ProgramData\ParentGate\browser-extension` after installing or repairing the Windows client. From a source checkout, you can instead select this `client/browser-extension` directory.

## Install in Google Chrome

1. Open `chrome://extensions`.
2. Turn on **Developer mode**.
3. Choose **Load unpacked**.
4. Select `C:\ProgramData\ParentGate\browser-extension` after installing or repairing the Windows client. From a source checkout, you can instead select this `client/browser-extension` directory.

The extension queues up to 2,000 events in browser-local storage if the Windows client is temporarily unavailable. Incognito activity is not available unless a parent explicitly enables the extension in incognito mode.
