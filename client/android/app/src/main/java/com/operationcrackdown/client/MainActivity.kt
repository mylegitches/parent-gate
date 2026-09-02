package com.operationcrackdown.client

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.ViewGroup
import android.widget.*
import org.json.JSONObject

class MainActivity : Activity() {
    private lateinit var api: ApiClient
    private lateinit var content: LinearLayout
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        api = ApiClient(this)
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(42, 48, 42, 48)
        }
        val scroll = ScrollView(this).apply { addView(content) }
        setContentView(scroll)
        render()
    }

    private fun render() {
        content.removeAllViews()
        heading("Operation Crackdown")
        if (!api.enrolled) renderEnrollment() else renderParentOverride()
    }

    private fun renderEnrollment() {
        paragraph("Enroll this Android device using the one-time code from the parent dashboard.")
        val server = field("Dashboard URL", InputType.TYPE_TEXT_VARIATION_URI)
        val code = field("Enrollment code")
        val name = field("Device name").apply { setText(Build.MODEL) }
        button("Enroll device") {
            status("Enrolling…")
            Thread {
                try {
                    api.enroll(server.text.toString(), code.text.toString(), name.text.toString())
                    runOnUiThread { requestVpnAndStart(); render() }
                } catch (error: Exception) { runOnUiThread { status(error.message ?: "Enrollment failed") } }
            }.start()
        }
        status = paragraph("")
    }

    private fun renderParentOverride() {
        paragraph("This device is enrolled as ${api.deviceId}. Local changes sync back to the dashboard.")
        status = paragraph("Loading current controls…")
        val pin = field("Parent PIN", InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD)
        val target = Spinner(this)
        val action = Spinner(this).apply { adapter = adapterOf(listOf("Allow", "Block")) }
        val duration = Spinner(this).apply { adapter = adapterOf(listOf("Until changed", "30 minutes", "1 hour", "2 hours")) }
        content.addView(target, matchWidth())
        content.addView(action, matchWidth())
        content.addView(duration, matchWidth())
        button("Apply on this device") {
            val policy = api.cachedPolicy()
            if (policy == null) { status("No policy has synchronized yet."); return@button }
            val parentKey = PolicyTools.parentForPin(policy, pin.text.toString())
            if (parentKey == null) { status("Incorrect parent PIN."); return@button }
            val selection = target.selectedItem as TargetChoice
            val selectedAction = selection.fixedAction ?: if (action.selectedItemPosition == 0) "allow" else "block"
            val minutes = intArrayOf(0, 30, 60, 120)[duration.selectedItemPosition]
            val operation = PolicyTools.localOperation(policy, parentKey, selection.type, selection.id, selectedAction, minutes)
            api.saveLocalOperation(operation)
            startFocusService()
            status("Applied locally; synchronization requested.")
            pin.text.clear()
        }
        button("Refresh from dashboard") { startFocusService(); loadPolicy(target) }
        requestVpnAndStart()
        loadPolicy(target)
    }

    private fun loadPolicy(target: Spinner) {
        Thread {
            try {
                val policy = api.getPolicy()
                val choices = mutableListOf(
                    TargetChoice("master", "blocking", "Turn master blocking on", "enable"),
                    TargetChoice("master", "blocking", "Turn master blocking off", "disable"),
                )
                val services = policy.optJSONArray("services")
                if (services != null) for (index in 0 until services.length()) {
                    val service = services.getJSONObject(index)
                    choices += TargetChoice("service", service.getString("id"), service.getString("displayName"))
                }
                runOnUiThread {
                    target.adapter = adapterOf(choices)
                    status("Master blocking: ${if (policy.optBoolean("masterEnabled", true)) "On" else "Off"}")
                }
            } catch (error: Exception) { runOnUiThread { status(error.message ?: "Unable to refresh") } }
        }.start()
    }

    private fun requestVpnAndStart() {
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 12)
        }
        val intent = VpnService.prepare(this)
        if (intent != null) startActivityForResult(intent, 11) else startFocusService()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 11 && resultCode == RESULT_OK) startFocusService()
    }

    private fun startFocusService() {
        startForegroundService(Intent(this, FocusVpnService::class.java))
    }

    private fun heading(value: String) = TextView(this).also {
        it.text = value; it.textSize = 28f; it.setTypeface(null, android.graphics.Typeface.BOLD); content.addView(it, matchWidth())
    }
    private fun paragraph(value: String) = TextView(this).also {
        it.text = value; it.textSize = 16f; it.setPadding(0, 18, 0, 18); content.addView(it, matchWidth())
    }
    private fun field(hint: String, inputType: Int = InputType.TYPE_CLASS_TEXT) = EditText(this).also {
        it.hint = hint; it.inputType = inputType; content.addView(it, matchWidth())
    }
    private fun button(label: String, action: () -> Unit) = Button(this).also {
        it.text = label; it.setOnClickListener { action() }; content.addView(it, matchWidth())
    }
    private fun status(value: String) { status.text = value }
    private fun matchWidth() = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
    private fun <T> adapterOf(values: List<T>) = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, values)

    data class TargetChoice(val type: String, val id: String, val label: String, val fixedAction: String? = null) { override fun toString() = label }
}
