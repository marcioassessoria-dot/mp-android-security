package br.com.mp.androidsecurity.scanner

import br.com.mp.androidsecurity.model.InstalledAppInfo

data class IntelligentRiskResult(
    val score: Int,
    val level: String,
    val localScore: Int,
    val onlineScore: Int,
    val detections: Int?,
    val engines: Int?,
    val permissionRisk: Int,
    val certificateSha256: String?,
    val apkSha256: String?,
    val reasons: List<String>
)

object IntelligentRiskEngine {
    fun evaluate(app: InstalledAppInfo, online: OnlineScanResult?): IntelligentRiskResult {
        val local = app.riskScore.coerceIn(0, 100)
        val permissionRisk = permissionComponent(app)
        val onlineScore = onlineComponent(online)
        val score = ((local * 0.60) + (permissionRisk * 0.10) + (onlineScore * 0.30)).toInt().coerceIn(0, 100)
        val reasons = buildList {
            add("Risco local: ${local}/100")
            add("Permissões sensíveis concedidas: ${app.requestedPermissions.count { it.granted }} de ${app.requestedPermissions.size}")
            if (online != null) {
                add("MetaDefender: ${online.detected ?: "?"}/${online.totalEngines ?: "?"} detecções")
                when (online.verdict) {
                    "AMEAÇA_DETECTADA" -> add("MetaDefender classificou o APK como ameaça")
                    "SUSPEITO" -> add("MetaDefender classificou o APK como suspeito")
                    "LIMPO" -> add("MetaDefender não registrou detecções")
                }
            } else add("Análise MetaDefender ainda não realizada")
            add(if (app.certificateSha256.isNullOrBlank()) "Certificado SHA-256 não identificado" else "Certificado SHA-256 identificado")
            add(if (app.apkSha256.isNullOrBlank()) "Hash SHA-256 do APK não identificado" else "Hash SHA-256 do APK identificado")
        }
        return IntelligentRiskResult(score, level(score), local, onlineScore, online?.detected, online?.totalEngines, permissionRisk, app.certificateSha256, app.apkSha256, reasons)
    }

    private fun permissionComponent(app: InstalledAppInfo): Int =
        if (app.requestedPermissions.isEmpty()) 0 else app.requestedPermissions.filter { it.granted }.sumOf { it.riskPoints }.coerceAtMost(100)

    private fun onlineComponent(result: OnlineScanResult?): Int {
        if (result == null) return 0
        val detected = result.detected ?: return when (result.verdict) {
            "AMEAÇA_DETECTADA" -> 80
            "SUSPEITO" -> 50
            else -> 0
        }
        val total = result.totalEngines ?: 0
        if (detected <= 0) return 0
        if (total <= 0) return (detected * 15).coerceAtMost(100)
        return ((detected.toDouble() / total.toDouble()) * 100.0).toInt().coerceIn(0, 100)
    }

    private fun level(score: Int): String = when {
        score >= 80 -> "ALTO"
        score >= 50 -> "ATENÇÃO"
        score >= 25 -> "MODERADO"
        else -> "BAIXO"
    }
}
