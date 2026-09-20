package br.com.mp.androidsecurity.scanner

import br.com.mp.androidsecurity.model.ScanResult
import org.json.JSONArray
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

class PortalNexAiClient {
    private val endpoint = "https://qblgoybdrkhfaskllokl.supabase.co/functions/v1/mp-security-ai"

    fun analyze(result: ScanResult): String {
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

        val connection = (URL(endpoint).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            connectTimeout = 15000
            readTimeout = 60000
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Accept", "application/json")
        }
        return try {
            OutputStreamWriter(connection.outputStream, Charsets.UTF_8).use { it.write(root.toString()) }
            val code = connection.responseCode
            val body = (if (code >= 400) connection.errorStream else connection.inputStream)
                ?.bufferedReader()?.use { it.readText() }.orEmpty()
            if (code !in 200..299) throw IllegalStateException("PortalNex IA HTTP $code: "+body.take(300))
            JSONObject(body).optJSONObject("analysis")?.toString()
                ?: throw IllegalStateException("PortalNex IA não retornou uma análise.")
        } finally {
            connection.disconnect()
        }
    }
}
