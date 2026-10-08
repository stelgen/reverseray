package dev.stelgen.reverseray.core

/**
 * Реестр протоколов туннеля — ЕДИНСТВЕННЫЙ источник правды для APK.
 * Зеркало server/internal/rrp/protocol.go: идентификаторы, дефолт,
 * толерантная нормализация (мусор/пустота → дефолт, никогда не ошибка).
 *
 * Архитектура рассчитана на много протоколов: сервер присылает свой реестр
 * в HELLO_OK/READY (protocols), APK показывает список и переключает сессию
 * с валидацией реального трафика (PROBE) перед коммитом.
 */
object RrpProtocols {

    /** Самый стабильный протокол, имплементирован и клиентом, и сервером. */
    const val DEFAULT = "rrp1"

    /** Протоколы, встроенные в APK (сервер может прислать свой больший список). */
    val BUNDLED: List<String> = listOf(DEFAULT)

    /** Толерантная нормализация любого значения (ссылка/сервер/пользователь). */
    fun normalize(raw: String?): String {
        if (raw == null) return DEFAULT
        val s = raw.trim().trim('"', '\'', '`', '«', '»', '“', '”', '„', '‘', '’')
            .lowercase().trim()
        return if (s in BUNDLED || isKnown(s)) s else DEFAULT
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

    /** Полный список для UI: серверный реестр ∪ встроенные. */
    fun displayList(): List<String> {
        val out = LinkedHashSet(BUNDLED)
        out.addAll(serverKnown)
        return out.toList()
    }

    private fun isKnown(s: String): Boolean = serverKnown.contains(s)

    /** Человекочитаемое имя для UI. */
    fun displayName(id: String): String = when (id) {
        DEFAULT -> "RRP/1 · стабильный"
        else -> id
    }
}
