package br.com.mp.androidsecurity.threat

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import br.com.mp.androidsecurity.model.ThreatIntel
import org.json.JSONArray
import org.json.JSONObject

data class CachedThreatIntel(val version: Long, val updatedAt: String, val threats: List<ThreatIntel>)

class ThreatIntelStore(context: Context) : SQLiteOpenHelper(context.applicationContext, "mp_threat_intel.db", null, 1) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("CREATE TABLE snapshots(version INTEGER PRIMARY KEY, updated_at TEXT NOT NULL, payload TEXT NOT NULL, saved_at INTEGER NOT NULL)")
    }
    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit

    fun readLatest(): CachedThreatIntel? {
        readableDatabase.rawQuery("SELECT version, updated_at, payload FROM snapshots ORDER BY version DESC LIMIT 1", null).use { c ->
            if (!c.moveToFirst()) return null
            return runCatching {
                CachedThreatIntel(c.getLong(0), c.getString(1), parseThreats(JSONArray(c.getString(2))))
            }.getOrNull()
        }
    }

    fun save(version: Long, updatedAt: String, threats: List<ThreatIntel>) {
        val payload = JSONArray().apply {
            threats.forEach { t ->
                put(JSONObject().apply {
                    put("name", t.name); put("category", t.category); put("vectors", t.vectors)
                    put("behaviors", t.behaviors); put("detectionFocus", t.detectionFocus); put("updated", t.updated)
                    put("package_names", JSONArray(t.packageNames))
                    put("certificate_sha256", JSONArray(t.certificateSha256))
                    put("apk_sha256", JSONArray(t.apkSha256))
                })
            }
        }.toString()
        writableDatabase.insertWithOnConflict("snapshots", null, android.content.ContentValues().apply {
            put("version", version); put("updated_at", updatedAt); put("payload", payload); put("saved_at", System.currentTimeMillis())
        }, SQLiteDatabase.CONFLICT_REPLACE)
        writableDatabase.execSQL("DELETE FROM snapshots WHERE version NOT IN (SELECT version FROM snapshots ORDER BY version DESC LIMIT 3)")
    }

    private fun jsonList(a: JSONArray?): List<String> = a?.let { (0 until it.length()).mapNotNull { i -> it.optString(i).takeIf { s -> s.isNotBlank() } } } ?: emptyList()

    private fun parseThreats(array: JSONArray): List<ThreatIntel> = (0 until array.length()).map { i ->
        val o = array.getJSONObject(i)
        ThreatIntel(o.getString("name"), o.getString("category"), o.getString("vectors"),
            o.optString("behaviors"), o.optString("detectionFocus"), o.optString("updated"), jsonList(o.optJSONArray("package_names")), jsonList(o.optJSONArray("certificate_sha256")), jsonList(o.optJSONArray("apk_sha256")) )
    }
}
