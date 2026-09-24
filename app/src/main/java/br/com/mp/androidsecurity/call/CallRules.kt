package br.com.mp.androidsecurity.call

import android.content.Context

object CallRules {
    private const val PREFS = "call_rules"
    private fun p(c: Context) = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    fun get(c: Context, key: String, default: Boolean) = p(c).getBoolean(key, default)
    fun set(c: Context, key: String, value: Boolean) = p(c).edit().putBoolean(key, value).apply()
    fun list(c: Context, key: String): Set<String> = p(c).getStringSet(key, emptySet()) ?: emptySet()
    fun add(c: Context, key: String, value: String) { p(c).edit().putStringSet(key, list(c, key) + value).apply() }
    fun remove(c: Context, key: String, value: String) { p(c).edit().putStringSet(key, list(c, key) - value).apply() }
    fun normalize(value: String) = value.filter { it.isDigit() || it == '+' }
    fun hasPin(c: Context) = p(c).getString("pin", null) != null
    fun setPin(c: Context, pin: String) = p(c).edit().putString("pin", pin).apply()
    fun removePin(c: Context) = p(c).edit().remove("pin").apply()
    fun logs(c: Context): Set<String> = p(c).getStringSet("logs", emptySet()) ?: emptySet()
    fun addLog(c: Context, value: String) = p(c).edit().putStringSet("logs", logs(c) + value).apply()
    fun clearLogs(c: Context) = p(c).edit().remove("logs").apply()
}
