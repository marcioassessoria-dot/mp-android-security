package br.com.mp.androidsecurity.scanner

import br.com.mp.androidsecurity.model.*

object ThreatCorrelationEngine {
    fun correlate(app: InstalledAppInfo, threats: List<ThreatIntel>): List<ThreatMatch> =
        threats.mapNotNull { threat ->
            val matches = mutableListOf<String>()
            val evidence = mutableListOf<String>()
            if (threat.packageNames.any { it.equals(app.packageName, true) }) {
                matches += "package name"
                evidence += "Package " + app.packageName + " coincide com indicador publicado."
            }
            app.certificateSha256?.let { cert ->
                if (threat.certificateSha256.any { it.equals(cert, true) }) {
                    matches += "certificado"; evidence += "Certificado SHA-256 coincide com indicador publicado."
                }
            }
            app.apkSha256?.let { hash ->
                if (threat.apkSha256.any { it.equals(hash, true) }) {
                    matches += "hash APK"; evidence += "SHA-256 do APK coincide exatamente com indicador publicado."
                }
            }
            if (matches.isEmpty()) null else ThreatMatch(threat.name, matches, evidence, confidence(matches))
        }.sortedByDescending { it.confidence }
    private fun confidence(matches: List<String>) = when {
        "hash APK" in matches -> 100; "certificado" in matches -> 95; "package name" in matches -> 85; else -> 0
    }
}