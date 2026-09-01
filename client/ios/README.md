# iOS client build prerequisites

The iOS client uses Apple's Family Controls, Managed Settings, and Device Activity APIs. It cannot be compiled or permanently distributed from Windows.

1. Join the Apple Developer Program and request the Family Controls distribution entitlement for the application and extension identifiers.
2. On macOS, install Xcode 16 or later and XcodeGen.
3. Set `DEVELOPMENT_TEAM` in `project.yml` or in Xcode.
4. Run `xcodegen generate` in this directory.
5. Open `OperationCrackdown.xcodeproj`, confirm both targets use the Family Controls and App Group capabilities, and build to the child's device.
6. Authorize the application on the device through Apple Family Sharing.

The dashboard can request an immediate change, but iOS background delivery is best-effort. The dashboard must continue to distinguish requested from device-confirmed revisions.

