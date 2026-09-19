package br.com.mp.androidsecurity.threat

import android.content.Context
import br.com.mp.androidsecurity.model.ThreatCatalog
import br.com.mp.androidsecurity.model.ThreatIntel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

data class ThreatIntelState(
    val threats: List<ThreatIntel> = ThreatCatalog.threats,
    val version: Long = 0L,
    val updatedAt: String = ThreatCatalog.lastResearch,
    val syncing: Boolean = false,
    val source: String = "Catálogo local de fallback",
    val error: String? = null
)

class ThreatIntelRepository(private val context: Context, private val endpoint: String = DEFAULT_ENDPOINT) {
    private val store = ThreatIntelStore(context)

    fun cachedState(): ThreatIntelState {
        val cached = store.readLatest() ?: return ThreatIntelState()
        return ThreatIntelState(cached.threats, cached.version, cached.updatedAt, source = "Cache offline")
    }

    suspend fun sync(): ThreatIntelState = withContext(Dispatchers.IO) {
        val before = cachedState()
        if (endpoint.isBlank()) return@withContext before.copy(error = "Endpoint de Threat Intelligence não configurado.")

        val connection = (URL(endpoint).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 10_000
            readTimeout = 15_000
            setRequestProperty("Accept", "application/json")
            setRequestProperty("Cache-Control", "no-cache")
        }
        try {
            if (connection.responseCode !in 200..299)
                return@withContext before.copy(error = "Servidor de Threat Intelligence respondeu HTTP " + connection.responseCode + ".")
            val body = connection.inputStream.bufferedReader().use { it.readText() }
            val root = JSONObject(body)
            val version = root.getLong("version")
            val updatedAt = root.getString("updated_at")
            val threats = root.getJSONArray("threats").let { array ->
                (0 until array.length()).map { i ->
                    val o = array.getJSONObject(i)
                    ThreatIntel(o.getString("name"), o.getString("category"), o.getString("vectors"),
                        o.optString("behaviors"), o.optString("detectionFocus"), o.optString("updated"),
                        jsonList(o.optJSONArray("package_names")), jsonList(o.optJSONArray("certificate_sha256")), jsonList(o.optJSONArray("apk_sha256")))
                }
            }
            require(threats.isNotEmpty()) { "Feed vazio rejeitado." }
            if (version <= before.version) return@withContext before.copy(source = "Servidor (versão já em cache)", error = null)
            store.save(version, updatedAt, threats)
            ThreatIntelState(threats, version, updatedAt, source = "Servidor MP Threat Intelligence")
        } catch (t: Throwable) {
            before.copy(error = t.message ?: "Falha na sincronização.")
        } finally {
            connection.disconnect()
        }
    }

    private fun jsonList(a: org.json.JSONArray?): List<String> = a?.let { (0 until it.length()).mapNotNull { i -> it.optString(i).takeIf { s -> s.isNotBlank() } } } ?: emptyList()

    companion object {
        const val DEFAULT_ENDPOINT = "https://raw.githubusercontent.com/marcioassessoria-dot/mp-android-security/main/threat-intel/feed.json"
    }
}
