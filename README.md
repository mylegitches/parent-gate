# ParentGate

A self-hosted household focus dashboard. Parents flip simple switches on a phone-friendly web page ("block Discord", "pause YouTube until 8 PM", "pause the internet and show *Feed the dogs, then let us know*") and small clients on each Windows, Android and iOS device enforce them.

ParentGate is a guardrail, not spyware. It adds enough friction to interrupt habitual checking during homework, bedtime or family time. It does not record messages, read encrypted traffic, log keystrokes or try to defeat a determined administrator.

```
 Parent phone / browser
        │  HTTPS (session cookie + CSRF)
        ▼
 Nginx Proxy Manager (TLS)
        │
        ▼
 ParentGate dashboard + API  ── Docker on a home NAS
 Node.js 24 · built-in SQLite · zero npm dependencies
        ▲
        │  outbound HTTPS polling only (per-device bearer credential)
 ┌──────┴───────────┬──────────────────────┬─────────────────────┐
 Windows client      Android client          iOS client
 PowerShell agent    Kotlin, local VpnService Swift, Screen Time APIs
```

No controlled device ever accepts an inbound connection or needs a router port-forward.

## Status

| Component | State |
|---|---|
| Dashboard / API (Docker) | Working, deployed and used end to end |
| Windows client | Working, deployed, self-updating (v0.3.11) |
| Android client | Source complete; needs Android SDK 36 / JDK 17 to build and device-test |
| iOS client | Source foundation; needs macOS, Xcode and Apple's Family Controls entitlement |
| Browser extension (MV3) | Optional hostname reporting for the Windows client |
| Automated tests | 12 server tests (auth, policy resolution, API integration) passing via `node --test` |

## What parents can do

- See every enrolled device with online / last-seen state and whether it has confirmed the latest policy.
- Use a **master switch** per device that pauses or resumes all enforcement without forgetting individual selections.
- **Allow or block** each built-in service: Discord, Snapchat, Instagram, TikTok, Roblox, Netflix, YouTube, Hulu, Paramount+ and 11 more (21 total).
- **Paste any domain or URL** to block it on a device.
- **Block discovered apps** directly: clients report what is installed or running (name and process key only).
- Set changes **until changed** (the default) or for a fixed duration or until a time.
- **Pause internet and show a message** (Windows and Android). The device shows the parent's note and drops ordinary traffic until a parent taps *Restore internet*.
- **Capture screen** (Windows only, on demand): a parent can request one current desktop screenshot of a device. Nothing is captured on a schedule or in the background.
- Review an **audit history** of parent changes, enrollments and client results.

On each device, a parent can also enter a **local PIN** to make an immediate override that works even when the NAS is unreachable and syncs later.

## Engineering highlights

**Desired state instead of remote commands.** The server never sends "kill Discord now". It stores a versioned policy; each client reconciles toward it and reports which revision it applied. A missed message can't leave a device in the wrong state, and the API can't become a general remote-admin channel.

**The control channel always survives enforcement.** Before pausing the internet, the Windows client snapshots the firewall's outbound defaults and enabled allow rules, then permits only DNS, DHCP and its own dashboard connection. It immediately checks that the dashboard is still reachable and **rolls back automatically** if not. Temporary pauses carry a locally enforced expiration, so a dead NAS can never strand a device offline. Android excludes its own package from the local VPN for the same reason.

**Offline-first local overrides.** PIN overrides are idempotent operations (`operationId`) queued durably on the device. Conflicts are resolved by policy revision, not clocks, so a phone that was offline for days can't silently overwrite a newer dashboard decision.

**Safe self-updates.** The Windows agent installs only a newer per-device authenticated manifest, verifies every file by SHA-256, defers while internet pause is active and rolls back if the new agent doesn't report healthy.

**Recoverable by design.** An *Emergency Restore* shortcut (admin approval required) disables the agent and restores the exact saved firewall state, removing only ParentGate's own hosts-file section. The uninstaller uses the same saved state.

**Security basics done properly.** Parent passwords use scrypt with timing-safe comparison. Sessions are HttpOnly, SameSite cookies with CSRF tokens, and logins are rate limited. Device IDs are not secrets: each install gets a separate high-entropy credential, protected with DPAPI, Android Keystore or iOS Keychain. Enrollment codes are single-use and expire after ten minutes. PINs are stored only as slow-hash verifiers.

**Privacy-minimized telemetry.** App discovery reports a process/package key and display name, never window titles, documents or content. The optional browser extension reports top-level hostnames only (no paths, queries or page content). Activity is capped at 30 days and 5,000 events per device.

## Quick start (dashboard)

Requirements: Docker with Compose, and ideally a reverse proxy with a trusted TLS certificate.

```bash
git clone https://github.com/mylegitches/parent-gate.git
cd parent-gate
cp .env.example .env        # set APP_BASE_URL, HOUSEHOLD_TIMEZONE
docker compose up -d --build
```

Open the dashboard and complete first-run setup: a parent username/password plus a separate 4–8 digit local PIN. Then choose **Add device** to create a one-time enrollment code.

For local development without Docker: `npm start` (Node.js 24+), and `npm test` for the test suite.

## Documentation

- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md): NAS + Nginx Proxy Manager deployment, backups and updates
- [docs/CLIENTS.md](docs/CLIENTS.md): installing each client and per-platform limitations
- [docs/DESIGN.md](docs/DESIGN.md): the original design specification (requirements, tradeoffs, failure behavior and MVP acceptance criteria)

## Repository layout

```
src/                 dashboard server: HTTP API, auth, policy resolution, SQLite
public/              parent dashboard (vanilla JS, responsive)
tests/               node:test suites
client/windows/      PowerShell agent, installer, updater, repair/uninstall
client/android/      Kotlin client (foreground service + local VpnService)
client/ios/          Swift client (Family Controls, Managed Settings, Device Activity)
client/browser-extension/  optional MV3 hostname reporter
```

## Honest limitations

- Hosts-file website blocking is best effort: no wildcards, and providers change domains.
- Android blocks a selected app's network access but doesn't stop its window opening, and it conflicts with other VPN apps.
- iOS can't enumerate apps or run a background daemon; delivery depends on Apple's background scheduling, so the dashboard shows "requested" until the device confirms.
- Anyone with administrator rights on a device can remove the client. That is an intentional tradeoff for a household tool.
