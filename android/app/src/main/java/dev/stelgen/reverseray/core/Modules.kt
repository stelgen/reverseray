package dev.stelgen.reverseray.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * Модули ReverseRay (v0.8) — ЕДИНЫЙ манифест APK ↔ сервер.
 *
 * Канон: APK — тонкий движок (как ПО POS-терминала), общая логика живёт в
 * обновляемых модулях. Kotlin парсит ТОТ ЖЕ modules.json, что и сервер
 * (server/internal/modules), правила одинаковые:
 *  - schema ≠ 1 → отвергается;
 *  - id протокола [a-z0-9]{1,16}; rrp1 обязателен (фундамент);
 *  - мусорный манифест НИКОГДА не применяется (фоллбек на встроенный);
 *  - даунгрейд версии запрещён; скачивание только при изменении
 *    версии ИЛИ хеша тела.
 *
 * Протоколы из манифеста применяются в RrpProtocols (согласование в
 * рукопожатии, смена с PROBE-валидацией). Так новый протокол, добавленный
 * на сервере, появляется в APK без переустановки.
 */
object Modules {

    const val DEFAULT_URL =
        "https://raw.githubusercontent.com/stelgen/reverseray/main/modules/modules.json"

    class ManifestException(message: String) : Exception(message)

    data class ProtocolEntry(
        val id: String,
        val name: String,
        val enabled: Boolean,
        val default: Boolean,
    )

    data class Manifest(
        val version: String,
        val protocols: List<ProtocolEntry>,
        val probeTarget: String?,
        val dnsProbeNames: List<String>,
    ) {
        fun enabledProtocolIds(): List<String> = protocols.filter { it.enabled }.map { it.id }
    }

    /** [a-z0-9]{1,16} — зеркало rrp.NormalizeID. */
    fun normalizeId(raw: String): String {
        val s = raw.trim().lowercase()
        if (s.isEmpty() || s.length > 16) return ""
        return if (s.all { it in 'a'..'z' || it in '0'..'9' }) s else ""
    }

    /** Семвер-сравнение: >0 если a новее b (числовые сегменты, как в APK SemVer). */
    fun versionCompare(a: String, b: String): Int {
        val pa = a.trim().removePrefix("v").split('.').map { it.toIntOrNull() ?: 0 }
        val pb = b.trim().removePrefix("v").split('.').map { it.toIntOrNull() ?: 0 }
        val n = maxOf(pa.size, pb.size)
        for (i in 0 until n) {
            val x = pa.getOrElse(i) { 0 }
            val y = pb.getOrElse(i) { 0 }
            if (x != y) return x.compareTo(y)
        }
        return 0
    }

    /** Парс + валидация манифеста. Мусор — исключение, НИКОГДА не применяется. */
    fun parse(body: String): Manifest {
        val root = try {
            JSONObject(body)
        } catch (e: Exception) {
            throw ManifestException("манифест не JSON: ${e.message}")
        }
        if (root.optInt("schema", 0) != 1) {
            throw ManifestException("schema не 1")
        }
        val version = root.optString("version", "").trim()
        if (version.isEmpty() || !version.matches(Regex("^v?[0-9]+\\.[0-9]+(\\.[0-9]+)?$"))) {
            throw ManifestException("версия не семвер: $version")
        }
        val arr = root.optJSONArray("protocols") ?: throw ManifestException("нет реестра протоколов")
        val out = mutableListOf<ProtocolEntry>()
        val seen = mutableSetOf<String>()
        var hasRrp1 = false
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            val id = normalizeId(o.optString("id", ""))
            if (id.isEmpty()) throw ManifestException("мусорный id протокола")
            if (!seen.add(id)) throw ManifestException("дубликат протокола $id")
            val enabled = if (o.has("enabled")) o.optBoolean("enabled", true) else true
            if (id == RrpProtocols.DEFAULT) hasRrp1 = true
            out.add(ProtocolEntry(id, o.optString("name", id), enabled, o.optBoolean("default", false)))
        }
        if (!hasRrp1) throw ManifestException("реестр без rrp1 запрещён")
        val policy = root.optJSONObject("policy")
        var probe: String? = null
        val dnsNames = mutableListOf<String>()
        if (policy != null) {
            probe = policy.optString("probe_default_target", "").ifEmpty { null }
            probe?.let {
                val host = it.substringBeforeLast(':')
                val port = it.substringAfterLast(':', "").toIntOrNull()
                if (host.isEmpty() || port == null || port !in 1..65535) {
                    throw ManifestException("битый probe_default_target: $it")
                }
            }
            val names = policy.optJSONArray("dns_probe_names")
            if (names != null) {
                for (i in 0 until names.length()) {
                    val s = names.optString(i, "").trim()
                    if (s.isNotEmpty()) dnsNames.add(s)
                }
            }
        }
        return Manifest(version, out, probe, dnsNames)
    }

    /** Применяет реестр протоколов манифеста (включённые → RrpProtocols). */
    fun apply(m: Manifest) {
        val ids = m.enabledProtocolIds()
        RrpProtocols.applyRegistry(ids, m.version)
    }
}