package com.operationcrackdown.client

import android.util.Base64
import org.json.JSONObject
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

object PolicyTools {
    fun activePolicy(input: JSONObject): JSONObject {
        var policy = input
        repeat(20) {
            val expiry = policy.optString("nextExpiry")
            val fallback = policy.optJSONObject("afterExpiry")
            if (expiry.isBlank() || fallback == null) return policy
            if (java.time.Instant.parse(expiry).isAfter(java.time.Instant.now())) return policy
            policy = fallback
        }
        return policy
    }

    fun applyLocal(policy: JSONObject, operation: JSONObject): JSONObject {
        val local = JSONObject(policy.toString())
        val beforeOverride = JSONObject(policy.toString())
        val targetType = operation.getString("targetType")
        val targetId = operation.getString("targetId")
        val action = operation.getString("action")
        val services = local.optJSONArray("services")
        if (targetType == "profile") {
            local.put("profile", targetId)
            if (services != null) for (index in 0 until services.length()) {
                val service = services.getJSONObject(index)
                val blocked = when (targetId) {
                    "normal" -> false
                    "homework" -> service.optString("id") == "discord"
                    "deep-focus" -> service.optString("category") in setOf("social", "streaming")
                    else -> service.optBoolean("blocked")
                }
                service.put("blocked", blocked)
            }
            val custom = local.optJSONArray("customTargets")
            if (custom != null) for (index in 0 until custom.length()) {
                val target = custom.getJSONObject(index)
                val profiles = target.optJSONArray("profiles")
                var blocked = false
                if (profiles != null) for (profileIndex in 0 until profiles.length()) {
                    if (profiles.getString(profileIndex) == targetId) blocked = true
                }
                target.put("blocked", blocked)
            }
        } else if (services != null) {
            for (index in 0 until services.length()) {
                val service = services.getJSONObject(index)
                if (targetType == "category" && service.optString("category") == targetId) service.put("blocked", action == "block")
                if (targetType == "service" && service.optString("id") == targetId) service.put("blocked", action == "block")
            }
        }
        if (operation.has("effectiveUntil")) {
            val expiry = operation.getString("effectiveUntil")
            local.put("effectiveUntil", expiry)
            local.put("nextExpiry", expiry)
            local.put("afterExpiry", beforeOverride)
        }
        return local
    }

    fun blockedPackages(policy: JSONObject): Set<String> {
        val result = mutableSetOf<String>()
        val services = policy.optJSONArray("services")
        if (services != null) for (index in 0 until services.length()) {
            val service = services.getJSONObject(index)
            if (!service.optBoolean("blocked")) continue
            val packages = service.optJSONObject("android")?.optJSONArray("packages") ?: continue
            for (packageIndex in 0 until packages.length()) result += packages.getString(packageIndex)
        }
        val targets = policy.optJSONArray("customTargets")
        if (targets != null) for (index in 0 until targets.length()) {
            val target = targets.getJSONObject(index)
            if (!target.optBoolean("blocked")) continue
            val packages = target.optJSONObject("mapping")?.optJSONArray("packages") ?: continue
            for (packageIndex in 0 until packages.length()) result += packages.getString(packageIndex)
        }
        return result
    }

    fun parentForPin(policy: JSONObject, pin: String): String? {
        val verifiers = policy.optJSONArray("pinVerifiers") ?: return null
        for (index in 0 until verifiers.length()) {
            val parent = verifiers.getJSONObject(index)
            if (verifyPin(pin, parent.getString("verifier"))) return parent.getString("parentKeyId")
        }
        return null
    }

    fun localOperation(policy: JSONObject, parentKeyId: String, targetType: String, targetId: String, action: String, durationMinutes: Int): JSONObject {
        val operation = JSONObject()
            .put("operationId", UUID.randomUUID().toString())
            .put("deviceId", policy.optString("deviceId"))
            .put("baseRevision", policy.getInt("revision"))
            .put("source", "local-parent")
            .put("parentKeyId", parentKeyId)
            .put("targetType", targetType)
            .put("targetId", targetId)
            .put("action", action)
            .put("createdAt", java.time.Instant.now().toString())
        if (durationMinutes > 0) operation.put("effectiveUntil", java.time.Instant.now().plusSeconds(durationMinutes * 60L).toString())
        return operation
    }

    private fun verifyPin(pin: String, encoded: String): Boolean {
        return try {
            val parts = encoded.split('$')
            if (parts.size != 4 || parts[0] != "pbkdf2-sha256") return false
            val iterations = parts[1].toInt()
            val salt = decodeUrl(parts[2])
            val expected = decodeUrl(parts[3])
            val spec = PBEKeySpec(pin.toCharArray(), salt, iterations, expected.size * 8)
            val actual = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
            MessageDigest.isEqual(actual, expected)
        } catch (_: Exception) { false }
    }

    private fun decodeUrl(value: String): ByteArray = Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
}
