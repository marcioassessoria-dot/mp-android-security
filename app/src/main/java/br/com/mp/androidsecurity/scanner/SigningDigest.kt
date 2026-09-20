package br.com.mp.androidsecurity.scanner

import android.content.pm.PackageInfo
import android.os.Build
import java.security.MessageDigest

object SigningDigest {
    fun sha256(pkg: PackageInfo): String? = runCatching {
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pkg.signingInfo?.apkContentsSigners.orEmpty()
        } else {
            @Suppress("DEPRECATION")
            pkg.signatures.orEmpty()
        }
        signatures.firstOrNull()?.toByteArray()?.let { bytes ->
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        }
    }.getOrNull()
}
