package dev.stelgen.reverseray.net

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/** Краткая инфо о сети телефона: внешний IP, страна, оператор. */
data class NetInfo(
    val ip: String,
    val country: String?,
    val countryCode: String?,
    val isp: String?,
    // v0.8.1: какой источник ответил (канон честности — показываем в UI)
    val source: String = "",
) {
    /** Флаг-эмодзи по ISO-коду страны (regional indicators). */
    fun flagEmoji(): String {
        val cc = countryCode?.uppercase() ?: return ""
        if (cc.length != 2 || cc.any { it !in 'A'..'Z' }) return ""
        return String(
            charArrayOf(
                (0x1F1E6 + (cc[0] - 'A')).toChar(),
                (0x1F1E6 + (cc[1] - 'A')).toChar(),
            )
        )
    }
}

/**
 * Получает инфо о сети телефона напрямую (не через туннель): внешний IP,
 * страна (с флагом) и оператор. Источники по порядку, первый успешный:
 *   1. https://ipwho.is/   (ip, country, country_code, flag.emoji, connection.isp)
 *   2. https://ipapi.co/json/ (ip, country_name, country_code, org)
 *   3. https://api.ipify.org (только ip)
 *
 * v0.8.1: каждый ответ помечается источником (NetInfo.source) — пользователь
 * всегда видит, КУДА именно мы ходили за данными (статус + «О сети»).
 */
object NetInfoFetcher {

    /** Все внешние источники, к которым приложение может ходить за IP/страной
     *  (v0.8.1: показываем пользователю в «О сети» — канон честности). */
    val SOURCES = listOf("https://ipwho.is/", "https://ipapi.co/json/", "https://api.ipify.org")

    fun fetch(timeoutMs: Int = 8_000): NetInfo? {
        fetchIpWhoIs(timeoutMs)?.let { return it }
        fetchIpApiCo(timeoutMs)?.let { return it }
        return fetchIpifyOnly(timeoutMs)
    }

    private fun get(url: String, timeoutMs: Int): String? = try {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = timeoutMs
        conn.readTimeout = timeoutMs
        conn.setRequestProperty("User-Agent", "reverseray-android")
        if (conn.responseCode != 200) {
            conn.disconnect()
            null
        } else {
            conn.inputStream.use { it.bufferedReader().readText() }
        }
    } catch (_: Exception) {
        null
    }

    private fun fetchIpWhoIs(timeoutMs: Int): NetInfo? {
        return try {
            val body = get("https://ipwho.is/", timeoutMs) ?: return null
            val j = JSONObject(body)
            if (!j.optBoolean("success", true)) return null
            val ip = j.optString("ip", "")
            if (ip.isEmpty()) return null
            val cc = j.optString("country_code", "").ifEmpty { null }
            val isp = j.optJSONObject("connection")?.optString("isp", "").orEmpty().ifEmpty { null }
            NetInfo(
                ip,
                j.optString("country", "").ifEmpty { null },
                cc,
                isp,
                "ipwho.is",
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun fetchIpApiCo(timeoutMs: Int): NetInfo? {
        return try {
            val body = get("https://ipapi.co/json/", timeoutMs) ?: return null
            val j = JSONObject(body)
            val ip = j.optString("ip", "")
            if (ip.isEmpty() || j.has("error")) return null
            val cc = j.optString("country_code", "").ifEmpty { null }
            NetInfo(
                ip,
                j.optString("country_name", "").ifEmpty { null },
                cc,
                j.optString("org", "").ifEmpty { null },
                "ipapi.co",
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun fetchIpifyOnly(timeoutMs: Int): NetInfo? {
        val ip = get("https://api.ipify.org", timeoutMs)?.trim().orEmpty()
        return if (ip.isNotEmpty()) NetInfo(ip, null, null, null, "api.ipify.org") else null
    }

    // ---------- утилиты ----------

    /** "DE" → "🇩🇪". */
    fun emojiOf(countryCode: String?): String? {
        val cc = countryCode?.uppercase() ?: return null
        if (cc.length != 2 || cc.any { it !in 'A'..'Z' }) return null
        return String(
            charArrayOf(
                (0x1F1E6 + (cc[0] - 'A')).toChar(),
                (0x1F1E6 + (cc[1] - 'A')).toChar(),
            )
        )
    }
}
