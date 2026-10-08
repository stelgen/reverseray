package dev.stelgen.reverseray.core

/**
 * Реестр протоколов туннеля — ЕДИНСТВЕННЫЙ источник правды для APK.
 * Зеркало server/internal/rrp/protocol.go: идентификаторы, дефолт,
 * толерантная нормализация (мусор/пустота → дефолт, никогда не ошибка).
 *
 * v0.8: реестр динамический — модули (Modules.apply) применяют манифест,
 * общий с сервером. Встроенные: rrp1 (фундамент, всегда) + mtproto2.
 * Старые серверы/клиенты, не знающие mtproto2, автоматически фоллбечатся
 * на общий протокол при согласовании.
 */
object RrpProtocols {

    /** Самый стабильный протокол, имплементирован и клиентом, и сервером. */
    const val DEFAULT = "rrp1"

    /** Встроенные (манифест может расширить/выключить — кроме rrp1). */
    val BUNDLED: List<String> = listOf(DEFAULT, MtProto.PROTO_ID)

    // ---- динамический реестр (манифест модулей) ----

    @Volatile
    private var registryIds: List<String> = BUNDLED

    @Volatile
    private var registryVersion: String = ""

    /**
     * Применяет реестр из манифеста модулей. Гарантии (зеркало SetRegistry
     * сервера): rrp1 остаётся; пустой список НЕ применяется; мусорные id
     * отбрасываются; rrp1 всегда дефолт.
     */
    fun applyRegistry(ids: List<String>, version: String) {
        val clean = ids.map { Modules.normalizeId(it) }.filter { it.isNotEmpty() }.toMutableList()
        if (!clean.contains(DEFAULT)) return // реестр без фундамента не применяем
        synchronized(this) {
            registryIds = LinkedHashSet(clean).toList()
            registryVersion = version
        }
    }

    /** Версия активного реестра ("" — встроенный). */
    fun registryVersion(): String = registryVersion

    /** Толерантная нормализация любого значения (ссылка/сервер/пользователь). */
    fun normalize(raw: String?): String {
        if (raw == null) return DEFAULT
        val s = raw.trim().trim('"', '\'', '`', '«', '»', '“', '”', '„', '‘', '’')
            .lowercase().trim()
        return if (s in registryIds || isKnown(s)) s else DEFAULT
    }

    /** Известен ли id (учитываем и реестр, полученный от сервера). */
    @Volatile
    private var serverKnown: Set<String> = emptySet()

    /** Запоминает реестр протоколов, присланный сервером (HELLO_OK/READY). */
    fun rememberServerProtocols(ids: List<String>) {
        if (ids.isNotEmpty()) {
            serverKnown = ids.map { it.trim().lowercase() }.filter { it.isNotEmpty() }.toSet()
        }
    }

    fun serverProtocols(): List<String> = serverKnown.toList()

    /** Полный список для UI: серверный реестр ∪ активный локальный. */
    fun displayList(): List<String> {
        val out = LinkedHashSet(registryIds)
        out.addAll(serverKnown)
        return out.toList()
    }

    private fun isKnown(s: String): Boolean = serverKnown.contains(s)

    /** Человекочитаемое имя для UI. */
    fun displayName(id: String): String = when (id) {
        DEFAULT -> "RRP/1 · стабильный"
        MtProto.PROTO_ID -> "MTProto/2 · шифрование payload"
        else -> id
    }
}