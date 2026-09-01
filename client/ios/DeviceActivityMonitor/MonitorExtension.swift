import DeviceActivity
import ManagedSettings

final class MonitorExtension: DeviceActivityMonitor {
    override func intervalDidStart(for activity: DeviceActivityName) {
        super.intervalDidStart(for: activity)
        // Synchronized schedules are materialized into ManagedSettings by the main app.
        // This extension is the execution point for schedule-specific shields in Phase 3.
    }

    override func intervalDidEnd(for activity: DeviceActivityName) {
        super.intervalDidEnd(for: activity)
    }
}

