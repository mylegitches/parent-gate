package com.operationcrackdown.client

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

class ApiClient(private val context: Context) {
    private val preferences = context.getSharedPreferences("operation-crackdown", Context.MODE_PRIVATE)

    val enrolled: Boolean get() = preferences.contains("credential")
    val serverUrl: String get() = preferences.getString("serverUrl", "")!!.trimEnd('/')
    val deviceId: String get() = preferences.getString("deviceId", "")!!

    fun enroll(server: String, code: String, name: String): JSONObject {
        val root = server.trimEnd('/')
        val response = request(
            "$root/api/client/v1/enroll",
            "POST",
            JSONObject()
                .put("enrollmentCode", code.uppercase())
                .put("name", name)
                .put("platform", "android")
                .put("osVersion", android.os.Build.VERSION.RELEASE)
                .put("clientVersion", BuildConfig.VERSION_NAME)
                .put("capabilities", JSONArray(listOf("package-vpn", "dns-vpn", "target-scan", "local-pin", "internet-pause-message"))),
            credential = null,
        )
        preferences.edit()
            .putString("serverUrl", response.optString("serverUrl", root).trimEnd('/'))
            .putString("deviceId", response.getString("deviceId"))
            .putString("credential", response.getString("credential"))
            .apply()
        return response
    }

    fun getPolicy(): JSONObject {
        val policy = request("$serverUrl/api/client/v1/policy", "GET")
        preferences.edit().putString("policy", policy.toString()).apply()
        return policy
    }

    fun cachedPolicy(): JSONObject? = preferences.getString("policy", null)?.let(::JSONObject)

    fun postStatus(policy: JSONObject, state: String, blockedPackages: Set<String>, error: String? = null) {
        val status = JSONObject()
            .put("state", state)
            .put("profile", policy.optString("profile"))
            .put("blockedPackages", JSONArray(blockedPackages.toList()))
            .put("internetBlocked", policy.optBoolean("internetBlocked", false))
        if (error != null) status.put("error", error)
        request(
            "$serverUrl/api/client/v1/status",
            "POST",
            JSONObject()
                .put("appliedRevision", policy.optInt("revision"))
                .put("clientVersion", BuildConfig.VERSION_NAME)
                .put("osVersion", android.os.Build.VERSION.RELEASE)
                .put("status", status),
        )
    }

    fun postTargets(targets: JSONArray) {
        request("$serverUrl/api/client/v1/targets", "POST", JSONObject().put("targets", targets))
    }

    fun postLocalOperation(operation: JSONObject): JSONObject =
        request("$serverUrl/api/client/v1/local-operations", "POST", operation)

    fun saveLocalOperation(operation: JSONObject) {
        val pending = pendingOperations()
        pending.put(operation)
        val editor = preferences.edit().putString("pendingOperations", pending.toString())
        cachedPolicy()?.let { editor.putString("policy", PolicyTools.applyLocal(it, operation).toString()) }
        editor.apply()
    }

    fun pendingOperations(): JSONArray = JSONArray(preferences.getString("pendingOperations", "[]"))

    fun syncPending(): JSONObject? {
        val pending = pendingOperations()
        if (pending.length() == 0) return null
        var latestPolicy: JSONObject? = null
        val remaining = JSONArray()
        for (index in 0 until pending.length()) {
            val operation = pending.getJSONObject(index)
            try {
                val response = postLocalOperation(operation)
                latestPolicy = response.optJSONObject("policy") ?: latestPolicy
            } catch (error: ApiException) {
                val conflictPolicy = error.body?.optJSONObject("policy")
                if (error.statusCode == 409 && conflictPolicy != null) {
                    latestPolicy = conflictPolicy
                } else {
                    remaining.put(operation)
                }
            }
        }
        preferences.edit().putString("pendingOperations", remaining.toString()).apply()
        latestPolicy?.let { preferences.edit().putString("policy", it.toString()).apply() }
        return latestPolicy
    }

    private fun request(url: String, method: String, body: JSONObject? = null, credential: String? = preferences.getString("credential", null)): JSONObject {
        val connection = URL(url).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = method
            connection.connectTimeout = 15_000
            connection.readTimeout = 15_000
            connection.setRequestProperty("Accept", "application/json")
            if (credential != null) connection.setRequestProperty("Authorization", "Bearer $credential")
            if (body != null) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val text = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
            val response = if (text.isBlank()) JSONObject() else JSONObject(text)
            if (status !in 200..299) throw ApiException(status, response.optString("error", "Request failed"), response)
            return response
        } finally {
            connection.disconnect()
        }
    }
}

class ApiException(val statusCode: Int, message: String, val body: JSONObject?) : Exception(message)
