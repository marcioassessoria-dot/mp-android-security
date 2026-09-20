package br.com.mp.androidsecurity.scanner

import android.content.Context
import br.com.mp.androidsecurity.BuildConfig
import br.com.mp.androidsecurity.model.ScanResult
import org.json.JSONArray
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.UUID

class PortalNexAiClient(context: Context) {
    private val endpoint = "https://qblgoybdrkhfaskllokl.supabase.co/functions/v1/mp-security-ai"
    private val identity = PortalNexDeviceIdentity(context.applicationContext)

    fun analyze(result: ScanResult): String {
        val body = buildPayload(result)
        if (!identity.isRegistered()) registerDevice()
        return executeSigned(body, allowReRegister = true)
    }

    private fun registerDevice() {
        val root = JSONObject().apply {
            put("action", "register")
            put("deviceId", identity.deviceId())
            put("publicKey", identity.publicKeyBase64())
            put("appVersion", BuildConfig.VERSION_NAME)
        }
        val response = openConnection()
        try {
            response.requestMethod = "POST"
            response.doOutput = true
            response.setRequestProperty("Content-Type", "application/json")
            response.setRequestProperty("Accept", "application/json")
            OutputStreamWriter(response.outputStream, Charsets.UTF_8).use { it.write(root.toString()) }
            val code = response.responseCode
            val body = readResponse(response)
            if (code in 200..299 || code == 409) {
                identity.markRegistered(true)
                return
            }
            throw IllegalStateException("PortalNex autenticação HTTP $code: " + body.take(300))
        } finally {
            response.disconnect()
        }
    }

    private fun executeSigned(body: String, allowReRegister: Boolean): String {
        val timestamp = (System.currentTimeMillis() / 1000L).toString()
        val nonce = UUID.randomUUID().toString()
        val bodyHash = sha256Hex(body.toByteArray(Charsets.UTF_8))
        val canonical = listOf(
            "POST",
            "/functions/v1/mp-security-ai",
            timestamp,
            nonce,
            bodyHash
        ).joinToString("\n")
        val signature = identity.sign(canonical)

        val connection = openConnection()
        try {
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("x-mp-device-id", identity.deviceId())
            connection.setRequestProperty("x-mp-timestamp", timestamp)
            connection.setRequestProperty("x-mp-nonce", nonce)
            connection.setRequestProperty("x-mp-signature", signature)
            OutputStreamWriter(connection.outputStream, Charsets.UTF_8).use { it.write(body) }

            val code = connection.responseCode
            val responseBody = readResponse(connection)
            if (code in 200..299) {
                identity.markRegistered(true)
                return JSONObject(responseBody).optJSONObject("analysis")?.toString()
                    ?: throw IllegalStateException("PortalNex IA não retornou uma análise.")
            }

            if (code == 401 && allowReRegister) {
                identity.resetRegistration()
                registerDevice()
                return executeSigned(body, allowReRegister = false)
            }

            if (code == 429) {
                val retry = runCatching { JSONObject(responseBody).optInt("retryAfter", 0) }.getOrDefault(0)
                throw IllegalStateException(
                    if (retry > 0) "Limite da IA por dispositivo atingido. Tente novamente em ${retry}s."
                    else "Limite da IA por dispositivo atingido."
                )
            }

            throw IllegalStateException("PortalNex IA HTTP $code: " + responseBody.take(300))
        } finally {
            connection.disconnect()
        }
    }

    private fun buildPayload(result: ScanResult): String {
        val root = JSONObject()
        val d = result.diagnostics
        root.put("device", JSONObject().apply {
            put("manufacturer", d.manufacturer)
            put("model", d.model)
            put("androidVersion", d.androidVersion)
            put("sdk", d.sdk)
        })
        root.put("totals", JSONObject().apply {
            put("apps", result.apps.size)
            put("highRisk", result.highRiskCount)
            put("suspicious", result.suspiciousCount)
            put("attention", result.attentionCount)
            put("lowRisk", result.lowRiskCount)
            put("threatMatches", result.threatMatchCount)
            put("possibleAdware", result.possibleAdwareCount)
        })
        root.put("privateDns", JSONObject().apply {
            put("state", result.privateDns.state.label)
            put("provider", result.privateDns.provider ?: "")
            put("isAdGuard", result.privateDns.isAdGuard)
        })
        val apps = JSONArray()
        result.apps.filter { !it.isSystemApp }.take(80).forEach { a ->
            apps.put(JSONObject().apply {
                put("packageName", a.packageName)
                put("appName", a.appName)
                put("origin", a.origin.label)
                put("enabled", a.enabled)
                put("riskScore", a.riskScore)
                put("riskLevel", a.riskLevel.label)
                put("adwareScore", a.adwareScore)
                put("adwareLevel", a.adwareLevel.label)
                put("accessibilityEnabled", a.accessibilityEnabled)
                put("deviceAdminActive", a.deviceAdminActive)
                put("certificateSha256", a.certificateSha256 ?: "")
                put("apkSha256", a.apkSha256 ?: "")
                put("riskReasons", JSONArray(a.riskReasons.take(12)))
                put("threatMatches", JSONArray().apply {
                    a.threatMatches.take(8).forEach { m ->
                        put(JSONObject().apply {
                            put("threatName", m.threatName)
                            put("matchedOn", JSONArray(m.matchedOn))
                            put("evidence", JSONArray(m.evidence.take(8)))
                            put("confidence", m.confidence)
                        })
                    }
                })
                put("permissions", JSONArray().apply {
                    a.requestedPermissions.take(30).forEach { p ->
                        put(JSONObject().apply {
                            put("label", p.label)
                            put("granted", p.granted)
                            put("riskPoints", p.riskPoints)
                        })
                    }
                })
            })
        }
        root.put("apps", apps)
        return root.toString()
    }

    private fun openConnection(): HttpURLConnection =
        (URL(endpoint).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15000
            readTimeout = 60000
            setRequestProperty("Origin", "https://portalnex.app")
            setRequestProperty("x-mp-app-id", "br.com.mp.androidsecurity")
            setRequestProperty("x-mp-platform", "android")
            setRequestProperty("x-mp-origin", "mp-android-security")
            setRequestProperty("x-mp-app-version", BuildConfig.VERSION_NAME)
            setRequestProperty("User-Agent", "MPAndroidSecurity/" + BuildConfig.VERSION_NAME)
        }

    private fun readResponse(connection: HttpURLConnection): String =
        (if (connection.responseCode >= 400) connection.errorStream else connection.inputStream)
            ?.bufferedReader()?.use { it.readText() }.orEmpty()

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
}
