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
        // v0.8.1: публичная версия протокола ("1", "2.0"). Пусто = версии нет:
        // нигде не показываем. Мусор чистится sanitizeVer (не ошибка).
        val ver: String,
        val enabled: Boolean,
        val default: Boolean,
    )

    /** v0.8.2: секция camouflage манифеста — модуль камуфляжа «API Mask». */
    data class Camouflage(
        val id: String,
        val name: String,
        val ver: String,
        val enabled: Boolean,
        val minIntervalSec: Int,
        val maxIntervalSec: Int,
        val maxBytesPerDay: Int,
    )

    data class Manifest(
        val version: String,
        val protocols: List<ProtocolEntry>,
        val probeTarget: String?,
        val dnsProbeNames: List<String>,
        /** null — секции нет: модуль выключен (решение за манифестом). */
        val camouflage: Camouflage?,
    ) {
        fun enabledProtocolIds(): List<String> = protocols.filter { it.enabled }.map { it.id }

        /** id → метка (v0.8.1, для статусов/кнопок; метка несёт версию). */
        fun protocolLabels(): Map<String, String> =
            protocols.associate { it.id to it.name }.filterKeys { it.isNotEmpty() }

        /** id → публичная версия (v0.8.1; пусто = версии нет). */
        fun protocolVers(): Map<String, String> =
            protocols.associate { it.id to sanitizeVer(it.ver) }
    }

    /** Версия протокола: печатные символы без пробелов, ≤16; мусор → "". */
    fun sanitizeVer(raw: String?): String {
        val s = raw?.trim().orEmpty()
        if (s.isEmpty() || s.length > 16) return ""
        return if (s.all { c ->
                c in '0'..'9' || c in 'a'..'z' || c in 'A'..'Z' ||
                    c == '.' || c == '-' || c == '_' || c == '+' || c == '/'
            }
        ) s else ""
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
            out.add(
                ProtocolEntry(
                    id,
                    o.optString("name", id).trim().ifEmpty { id },
                    sanitizeVer(o.optString("ver", "")),
                    enabled,
                    o.optBoolean("default", false),
                )
            )
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
        // v0.8.2: секция camouflage — опциональна; битый id = битый манифест
        var camo: Camouflage? = null
        val camoObj = root.optJSONObject("camouflage")
        if (camoObj != null) {
            val camoId = normalizeId(camoObj.optString("id", ""))
            if (camoId.isEmpty()) throw ManifestException("мусорный id модуля camouflage")
            camo = Camouflage(
                id = camoId,
                name = camoObj.optString("name", camoId).trim().ifEmpty { camoId },
                ver = sanitizeVer(camoObj.optString("ver", "")),
                enabled = if (camoObj.has("enabled")) camoObj.optBoolean("enabled", true) else true,
                minIntervalSec = camoObj.optInt("min_interval_sec", 0),
                maxIntervalSec = camoObj.optInt("max_interval_sec", 0),
                maxBytesPerDay = camoObj.optInt("max_bytes_per_day", 0),
            )
        }
        return Manifest(version, out, probe, dnsNames, camo)
    }

    /**
     * Применяет реестр протоколов манифеста (включённые → RrpProtocols).
     * v0.8.1: метки и публичные версии едут вместе с реестром — статусы,
     * кнопки и логи показывают то же, что сервер (один манифест).
     */
    fun apply(m: Manifest) {
        val ids = m.enabledProtocolIds()
        RrpProtocols.applyRegistryFull(ids, m.version, m.protocolLabels(), m.protocolVers())
        // v0.8.2: камуфляж из того же манифеста (или «выкл», если секции нет)
        val c = m.camouflage
        RrpProtocols.applyCamouflage(
            if (c == null) Apimask.Config.disabled()
            else Apimask.Config(c.id, c.name, c.ver, c.enabled, c.minIntervalSec, c.maxIntervalSec, c.maxBytesPerDay),
        )
    }
}