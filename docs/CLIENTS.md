# Client installation and behavior

## Windows

### Install

On the controlled PC, download or copy the `client/windows` directory. Open PowerShell as Administrator and run:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Install.ps1 `
  -ServerUrl "https://focus.example.net" `
  -EnrollmentCode "ABCD-EFGH-JKLM" `
  -DeviceName "Daughter PC"
```

Version 0.3.0 or newer enables self-updating. After it is installed, the elevated agent checks the enrolled dashboard every five minutes. Normal target, website, timer, message, and policy changes are already data-driven and do not require a client release. For a runtime release, the client accepts only a newer per-device authenticated manifest, verifies every downloaded file by SHA-256, preserves enrollment, and rolls back if the replacement does not report healthy. Updates are deferred whenever whole-internet pause is active.

The installer:

- Enrolls the installation with its own device ID and credential.
- Protects the credential with Windows DPAPI.
- Creates a highest-privilege logon task for the current Windows user.
- Adds a public-desktop shortcut to the local parent page at `http://127.0.0.1:8765/`.

The parent page listens only on Windows loopback and is not reachable from another device. A parent enters their local PIN there to change this device immediately. The resulting operation is queued durably and synchronized to the NAS dashboard.

The client also places `Operation Crackdown Emergency Restore.cmd` on the public desktop. It requires Windows administrator approval, disables the client task without deleting enrollment, restores the exact saved firewall defaults and outbound allow rules, and removes only Operation Crackdown's managed hosts entries. After using it, restore the device in the dashboard and run `Repair.ps1` as Administrator to re-enable enforcement.

### Enforcement

- Known and admin-selected Windows process names are closed while blocked.
- Service domains are added to a clearly bounded, managed section of the Windows hosts file.
- The dashboard hostname is excluded from domain enforcement.
- Policies are polled every eight seconds and cached locally.
- Running visible applications are scanned every two minutes and reported as candidate targets without their window titles.

Hosts-file blocking is best effort and does not support wildcard domains. Service definitions will need maintenance as providers change endpoints.

### Uninstall

Run `Uninstall.ps1` as Administrator. It removes the scheduled task, desktop shortcut, client data, and only the hosts-file section owned by Operation Crackdown.

## Android

The Android project is under `client/android`. It targets Android API 36 and requires JDK 17 plus a current Android SDK.

The client:

- Enrolls through the same one-time-code API.
- Runs a foreground synchronization service.
- Uses Android's user-approved `VpnService` to route selected blocked packages into a local discard tunnel.
- Leaves the Operation Crackdown package outside that tunnel so dashboard polling survives.
- Reports launcher applications as available targets under Android package-visibility rules.
- Provides a local parent PIN screen.

Only one Android VPN can be active at a time. This client conflicts with commercial VPNs and VPN-based ad blockers. Android package blocking makes the selected app offline; it does not prevent the app window from opening.

The source is present but cannot be compiled in this Windows workspace because Android SDK 36 is not installed. Open `client/android` in a current Android Studio, sync Gradle, approve VPN access on the device, and device-test before household deployment.

## iOS and iPadOS

The iOS project sources are under `client/ios`. Read its platform-specific README before building.

Apple does not permit installed-app enumeration or a permanently listening background daemon. The client therefore:

- Uses Family Controls authorization through Apple Family Sharing.
- Uses Apple's local Family Activity picker for Discord and each streaming service.
- Stores opaque activity tokens only on the device.
- Applies Managed Settings shields for blocked selections.
- Reports only logical configured aliases to the dashboard.
- Uses foreground synchronization today; APNs-assisted background synchronization remains required for reliable remote delivery.

An Apple Developer account, approved Family Controls entitlement, signing profiles, macOS, and Xcode are mandatory. Until push synchronization and offline queue persistence are completed and device-tested, the iOS source should be considered a functional foundation rather than a production household client.
