package br.com.mp.androidsecurity.scanner

import android.content.Context
import br.com.mp.androidsecurity.model.InstalledAppInfo
import kotlinx.coroutines.delay
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.DataOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

data class OnlineScanResult(
    val provider: String,
    val status: String,
    val verdict: String,
    val detected: Int?,
    val totalEngines: Int?,
    val sha256: String,
    val dataId: String? = null,
    val details: String = ""
)

class MetaDefenderScanner(private val context: Context) {
    private val baseUrl = "https://api.metadefender.com/v4"

    suspend fun scanInstalledApp(app: InstalledAppInfo, apiKey: String): OnlineScanResult {
        require(apiKey.isNotBlank()) { "Informe a API key do MetaDefender Cloud." }
        val source = context.packageManager.getApplicationInfo(app.packageName, 0).sourceDir
        val file = File(source)
        val sha256 = app.apkSha256 ?: throw IllegalStateException("Não foi possível calcular o SHA-256 do APK.")
        val lookup = request("GET", baseUrl + "/hash/" + sha256, apiKey)
        if (lookup.code in 200..299) return parseReport(lookup.body, sha256, null, "Resultado encontrado no histórico online.")
        if (lookup.code != 404) throw apiError("consulta do hash", lookup, apiKey)

        val upload = uploadFile(file, apiKey)
        if (upload.code !in 200..299) throw apiError("envio do APK", upload, apiKey)
        val dataId = JSONObject(upload.body).optString("data_id").takeIf { it.isNotBlank() }
            ?: throw IllegalStateException("MetaDefender não retornou data_id.")
        var last = ""
        repeat(24) {
            delay(2500)
            val report = request("GET", baseUrl + "/file/" + dataId, apiKey)
            last = report.body
            if (report.code !in 200..299) throw apiError("consulta da análise", report, apiKey)
            if (report.code in 200..299) {
                val progress = JSONObject(report.body).optJSONObject("scan_results")?.optInt("progress_percentage", 0) ?: 0
                if (progress >= 100) return parseReport(report.body, sha256, dataId, "Análise online concluída.")
            }
        }
        return OnlineScanResult("MetaDefender Cloud", "EM_ANALISE", "Análise ainda em processamento", null, null, sha256, dataId, last.take(500))
    }

    private fun parseReport(body: String, fallbackHash: String, dataId: String?, prefix: String): OnlineScanResult {
        val root = JSONObject(body)
        val results = root.optJSONObject("scan_results") ?: root.optJSONObject("scanResults")
        val detected = results?.optInt("total_detected_avs", -1)?.takeIf { it >= 0 }
        val total = results?.optInt("total_avs", -1)?.takeIf { it >= 0 }
        val resultCode = results?.optInt("scan_all_result_i", 5) ?: 5
        val verdict = when (resultCode) {
            0 -> "LIMPO"
            1 -> "AMEAÇA_DETECTADA"
            2 -> "SUSPEITO"
            3 -> "FALHA_NA_ANALISE"
            else -> if (detected == 0) "LIMPO" else "DESCONHECIDO"
        }
        val fileInfo = root.optJSONObject("file_info")
        val sha = fileInfo?.optString("sha256").takeIf { !it.isNullOrBlank() } ?: fallbackHash
        val engineText = (detected?.toString() ?: "?") + "/" + (total?.toString() ?: "?") + " engines."
        return OnlineScanResult("MetaDefender Cloud", "CONCLUIDO", verdict, detected, total, sha, dataId, prefix + " Resultado: " + engineText)
    }

    private fun apiError(operation: String, response: HttpResult, apiKey: String): IllegalStateException {
        val serverMessage = extractServerMessage(response.body)
        val rate = response.headers.entries.filter { it.key?.startsWith("X-RateLimit-", ignoreCase = true) == true }.joinToString(" | ") { entry -> entry.key + "=" + entry.value.joinToString(",") }
        val detail = buildString {
            append("MetaDefender recusou a " + operation + " (HTTP " + response.code + ").")
            if (serverMessage.isNotBlank()) append(" Servidor: " + serverMessage + ".")
            if (rate.isNotBlank()) append(" " + rate)
            when (response.code) {
                401 -> append(" A API key foi rejeitada. Verifique a chave configurada no GitHub Actions.")
                403 -> {
                    val diagnosis = diagnoseKey(apiKey)
                    if (diagnosis.isNotBlank()) append(" Diagnóstico: " + diagnosis)
                    else append(" A conta/chave não autorizou esta operação. Verifique os limites da conta MetaDefender.")
                }
                429 -> append(" Limite de requisições atingido. Aguarde o reset informado pelos cabeçalhos.")
            }
        }
        return IllegalStateException(detail)
    }

    private fun diagnoseKey(apiKey: String): String {
        return try {
            val info = request("GET", baseUrl + "/apikey/", apiKey)
            when {
                info.code in 200..299 -> "API key reconhecida pelo endpoint de informações da conta."
                info.code == 401 -> "API key rejeitada no endpoint de informações da conta."
                info.code == 403 -> "o endpoint de informações da conta também retornou 403."
                else -> "endpoint de informações retornou HTTP " + info.code + "."
            }
        } catch (t: Throwable) {
            "não foi possível consultar informações da conta: " + (t.message ?: "erro desconhecido")
        }
    }

    private fun extractServerMessage(body: String): String {
        if (body.isBlank()) return ""
        return runCatching {
            val root = JSONObject(body)
            val error = root.optJSONObject("error")
            when {
                error != null -> {
                    val messages = error.optJSONArray("messages")
                    if (messages != null && messages.length() > 0) (0 until messages.length()).joinToString("; ") { messages.optString(it) }
                    else error.optString("message").ifBlank { body.take(300) }
                }
                else -> root.optString("message").ifBlank { body.take(300) }
            }
        }.getOrElse { body.take(300) }
    }
    private fun request(method: String, url: String, apiKey: String): HttpResult {
        val c = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 15000
            readTimeout = 30000
            setRequestProperty("apikey", apiKey)
            setRequestProperty("Accept", "application/json")
            setRequestProperty("User-Agent", "MPAndroidSecurity")
        }
        return try { HttpResult(c.responseCode, readBody(c), c.headerFields.filterKeys { it != null }) } finally { c.disconnect() }
    }

    private fun uploadFile(file: File, apiKey: String): HttpResult {
        val boundary = "----MPAndroidSecurity" + System.currentTimeMillis()
        val c = (URL(baseUrl + "/file").openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            connectTimeout = 20000
            readTimeout = 30000
            setRequestProperty("apikey", apiKey)
            setRequestProperty("filename", file.name)
            setRequestProperty("samplesharing", "0")
            setRequestProperty("rule", "multiscan")
            setRequestProperty("Accept", "application/json")
            setRequestProperty("User-Agent", "MPAndroidSecurity")
            setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary)
        }
        DataOutputStream(c.outputStream).use { out ->
            out.writeBytes("--" + boundary + "\r\n")
            out.writeBytes("Content-Disposition: form-data; name=\"file\"; filename=\"" + file.name + "\"\r\n")
            out.writeBytes("Content-Type: application/vnd.android.package-archive\r\n\r\n")
            BufferedInputStream(file.inputStream()).use { input -> input.copyTo(out) }
            out.writeBytes("\r\n--" + boundary + "--\r\n")
        }
        return try { HttpResult(c.responseCode, readBody(c)) } finally { c.disconnect() }
    }

    private fun readBody(c: HttpURLConnection): String {
        val stream = if (c.responseCode >= 400) c.errorStream else c.inputStream
        return stream?.bufferedReader()?.use { it.readText() } ?: ""
    }

    private data class HttpResult(val code: Int, val body: String, val headers: Map<String?, List<String>>)
}
