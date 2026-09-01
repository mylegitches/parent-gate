package com.operationcrackdown.client

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Notification
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import org.json.JSONArray
import org.json.JSONObject
import java.io.FileInputStream
import java.util.concurrent.atomic.AtomicBoolean

class FocusVpnService : VpnService() {
    private val running = AtomicBoolean(false)
    private var tunnel: ParcelFileDescriptor? = null
    private var appliedPackages: Set<String> = emptySet()
    private var dropThread: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ensureNotificationChannel()
        val activityIntent = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Operation Crackdown")
            .setContentText("Focus controls are active")
            .setOngoing(true)
            .setContentIntent(activityIntent)
            .build()
        startForeground(NOTIFICATION_ID, notification)
        if (running.compareAndSet(false, true)) Thread(::policyLoop, "crackdown-policy").start()
        return START_STICKY
    }

    override fun onDestroy() {
        running.set(false)
        closeTunnel()
        super.onDestroy()
    }

    private fun policyLoop() {
        val api = ApiClient(this)
        var nextScan = 0L
        while (running.get()) {
            try {
                val policy = PolicyTools.activePolicy(api.syncPending() ?: api.getPolicy())
                val blocked = PolicyTools.blockedPackages(policy)
                applyPackages(blocked)
                api.postStatus(policy, "applied", blocked)
                if (System.currentTimeMillis() >= nextScan) {
                    api.postTargets(scanLauncherTargets())
                    nextScan = System.currentTimeMillis() + 120_000
                }
            } catch (error: Exception) {
                val cached = api.cachedPolicy()?.let(PolicyTools::activePolicy)
                if (cached != null) applyPackages(PolicyTools.blockedPackages(cached))
            }
            repeat(32) {
                if (!running.get()) return
                Thread.sleep(250)
            }
        }
    }

    @Synchronized
    private fun applyPackages(packages: Set<String>) {
        if (packages == appliedPackages) return
        closeTunnel()
        appliedPackages = packages
        if (packages.isEmpty()) return
        val builder = Builder()
            .setSession("Operation Crackdown focus filter")
            .setMtu(1500)
            .addAddress("10.254.0.1", 32)
            .addRoute("0.0.0.0", 0)
        var packageCount = 0
        for (packageName in packages) {
            try {
                builder.addAllowedApplication(packageName)
                packageCount += 1
            } catch (_: PackageManager.NameNotFoundException) { }
        }
        if (packageCount == 0) return
        tunnel = builder.establish()
        val descriptor = tunnel ?: return
        dropThread = Thread({
            val buffer = ByteArray(32767)
            try {
                FileInputStream(descriptor.fileDescriptor).use { input ->
                    while (running.get() && input.read(buffer) >= 0) { /* intentionally discard */ }
                }
            } catch (_: Exception) { }
        }, "crackdown-packet-dropper").also { it.start() }
    }

    @Synchronized
    private fun closeTunnel() {
        try { tunnel?.close() } catch (_: Exception) { }
        tunnel = null
        dropThread?.interrupt()
        dropThread = null
    }

    private fun scanLauncherTargets(): JSONArray {
        val result = JSONArray()
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        @Suppress("DEPRECATION")
        val activities = packageManager.queryIntentActivities(intent, 0)
        for (info in activities.distinctBy { it.activityInfo.packageName }) {
            val packageName = info.activityInfo.packageName
            if (packageName == this.packageName) continue
            val label = info.loadLabel(packageManager).toString()
            val combined = "$packageName $label".lowercase()
            val category = when {
                listOf("discord", "slack", "teams", "zoom", "signal", "telegram", "whatsapp", "messenger").any(combined::contains) -> "communication"
                listOf("netflix", "hulu", "paramount", "discovery", "youtube", "twitch", "spotify", "disney").any(combined::contains) -> "streaming"
                else -> "unknown"
            }
            result.put(
                JSONObject()
                    .put("key", "package:$packageName")
                    .put("displayName", label)
                    .put("kind", "package")
                    .put("categoryGuess", category)
                    .put("source", "android-launcher-scan")
                    .put("currentlyRunning", false)
                    .put("mapping", JSONObject().put("packages", JSONArray(listOf(packageName)))),
            )
        }
        return result
    }

    private fun ensureNotificationChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL_ID, "Focus client", NotificationManager.IMPORTANCE_LOW))
    }

    companion object {
        private const val CHANNEL_ID = "operation-crackdown-client"
        private const val NOTIFICATION_ID = 1782
    }
}
