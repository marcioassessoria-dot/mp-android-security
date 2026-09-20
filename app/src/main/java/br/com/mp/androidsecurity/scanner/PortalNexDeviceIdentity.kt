package br.com.mp.androidsecurity.scanner

import android.content.Context
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.UUID

class PortalNexDeviceIdentity(context: Context) {
    companion object {
        private const val PREFS = "mp_security_ai_identity"
        private const val DEVICE_ID = "device_id"
        private const val REGISTERED = "registered"
        private const val KEY_ALIAS = "mp_security_ai_device_key_v1"
    }

    private val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    @Synchronized
    private fun ensureIdentity(): Pair<String, KeyPair> {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = if (store.containsAlias(KEY_ALIAS)) {
            val privateKey = store.getKey(KEY_ALIAS, null) as? java.security.PrivateKey
            val publicKey = store.getCertificate(KEY_ALIAS)?.publicKey
            if (privateKey != null && publicKey != null) KeyPair(publicKey, privateKey) else null
        } else null

        if (existing != null) {
            val id = prefs.getString(DEVICE_ID, null)
            if (!id.isNullOrBlank()) return id to existing
        }

        val generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
        generator.initialize(
            android.security.keystore.KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                android.security.keystore.KeyProperties.PURPOSE_SIGN
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(android.security.keystore.KeyProperties.DIGEST_SHA256)
                .build()
        )
        val pair = generator.generateKeyPair()
        val id = UUID.randomUUID().toString()
        prefs.edit().putString(DEVICE_ID, id).putBoolean(REGISTERED, false).apply()
        return id to pair
    }

    fun deviceId(): String = ensureIdentity().first

    fun publicKeyBase64(): String {
        val pair = ensureIdentity().second
        return Base64.getEncoder().encodeToString(pair.public.encoded)
    }

    fun sign(message: String): String {
        val pair = ensureIdentity().second
        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(pair.private)
            update(message.toByteArray(StandardCharsets.UTF_8))
        }.sign()
        return Base64.getEncoder().encodeToString(signature)
    }

    fun isRegistered(): Boolean = prefs.getBoolean(REGISTERED, false)

    fun markRegistered(value: Boolean) {
        prefs.edit().putBoolean(REGISTERED, value).apply()
    }

    fun resetRegistration() {
        markRegistered(false)
    }
}
