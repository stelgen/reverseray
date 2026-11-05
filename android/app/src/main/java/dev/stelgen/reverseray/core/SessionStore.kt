package dev.stelgen.reverseray.core

/**
 * Хранилище профилей/сессий мульти-серверного ядра (v1.5.0 «Multi-Server Core»).
 *
 * Профиль = одна rrp://-ссылка (канон) + метаданные. Физически живёт в одном
 * ключе prefs (JSON-массив) + отдельном ключе активного PRIMARY-профиля.
 *
 * КАНОНЫ v1.5.0:
 *  - МИГРАЦИЯ v1.3→v1.5 одноразовая и обязательная: существующий KEY_CONFIG
 *    становится профилем №1 (enabled, PRIMARY, activePrimaryId). Потеря
 *    токена/пина/хоста недопустима — сырая ссылка сохраняется даже если
 *    парсер её не понял (канон «мусор не ломает стек», честное хранение).
 *  - ОБРАТНАЯ СОВМЕСТИМОСТЬ: канон URI активного PRIMARY-профиля ВСЕГДА
 *    зеркалится в старый KEY_CONFIG — BootReceiver, пикер протокола,
 *    switchProtocol и весь legacy-код продолжают работать без изменений.
 *  - Чистый Kotlin (org.json — часть платформы Android, зависимостей нет).
 *
 * Потокобезопасно: все мутации под одним локом; хранение — через Backend
 * (в APK — SharedPreferences, в тестах — in-memory карта).
 */
class SessionStore(private val backend: Backend) {

    /** Абстракция prefs-хранилища (pure-Kotlin тестируемость). */
    interface Backend {
        fun getString(key: String): String?
        fun putString(key: String, value: String)
        fun remove(key: String)
        fun contains(key: String): Boolean
    }

    /** Профиль сессии (сервера). */
    data class Profile(
        val id: String,
        val name: String,
        /** Каноническая rrp://-ссылка (источник правды, как в v1.3.0). */
        val uri: String,
        /** false — сессия не поднимается при старте туннеля (PRIMARY — всегда поднимается). */
        val enabled: Boolean,
        val createdAt: Long,
        /** Последнее известное состояние (для восстановления дашборда; текст). */
        val lastState: String = "",
    )

    companion object {
        /** Ключ prefs: JSON-массив профилей. */
        const val KEY_SESSIONS = "sessions"
        /** Ключ prefs: id активного PRIMARY-профиля. */
        const val KEY_ACTIVE = "active_session"

        /** Хард-лимит числа профилей — guardrail против мусорного JSON (сессий одновременно ≤4 — ConnectionManager). */
        const val MAX_PROFILES = 16

        private fun newId(): String {
            val rnd = java.security.SecureRandom()
            val bytes = ByteArray(8)
            rnd.nextBytes(bytes)
            return bytes.joinToString("") { "%02x".format(it) }
        }
    }

    private val lock = Any()

    // ---------------------------------------------------------------- чтение

    /** Список профилей в порядке создания. Битый JSON → пустой список (не исключение). */
    fun profiles(): List<Profile> = synchronized(lock) { readProfiles() }

    /** Профиль по id (null — нет такого). */
    fun byId(id: String?): Profile? = profiles().firstOrNull { it.id == id }

    /** id активного PRIMARY-профиля (null — нет). */
    fun activeId(): String? = synchronized(lock) { backend.getString(KEY_ACTIVE)?.takeIf { it.isNotBlank() } }

    /** Активный PRIMARY-профиль (null — нет). */
    fun active(): Profile? = byId(activeId())

    // ---------------------------------------------------------------- мутации

    /**
     * МИГРАЦИЯ v1.3→v1.5 (первый старт). Идемпотентна: если [KEY_SESSIONS]
     * уже существует — ничего не делает (никогда не затирает добавленные
     * профили). Существующий legacy-конфиг становится профилем №1:
     * enabled=true, активный PRIMARY. Legacy-конфиг НЕ трогается (зеркало).
     *
     * @param legacyConfig значение prefs KEY_CONFIG (может быть null/пусто).
     * @return созданный профиль (null — миграция не потребовалась/ссылки не было).
     */
    fun migrateLegacy(legacyConfig: String?): Profile? = synchronized(lock) {
        if (backend.contains(KEY_SESSIONS)) return@synchronized null
        val legacy = legacyConfig?.takeIf { it.isNotBlank() }
        if (legacy == null) {
            // чистая установка: пустой список, PRIMARY нет
            backend.putString(KEY_SESSIONS, "[]")
            return@synchronized null
        }
        // канонизируем, но при ошибке парсера СОХРАНЯЕМ сырьё (потеря недопустима)
        val canonical = try {
            RrpUri.parse(legacy).serialize()
        } catch (_: Exception) {
            legacy
        }
        val cfg = try {
            RrpUri.parse(canonical)
        } catch (_: Exception) {
            null
        }
        val name = cfg?.name?.takeIf { it.isNotBlank() } ?: cfg?.host ?: "server-1"
        val p = Profile(newId(), name, canonical, enabled = true, createdAt = System.currentTimeMillis())
        backend.putString(KEY_SESSIONS, "[" + toJson(p) + "]")
        backend.putString(KEY_ACTIVE, p.id)
        p
    }

    /**
     * Добавить профиль из ссылки (канонизируется). По умолчанию выключен
     * (канон v1.5.0: все новые профили выключены — владелец включает явно).
     * Возвращает null, если ссылка невалидна.
     */
    fun add(rawUri: String, name: String? = null, enabled: Boolean = false): Profile? {
        val canonical = try {
            RrpUri.parse(rawUri).serialize()
        } catch (_: Exception) {
            return null
        }
        val cfg = try {
            RrpUri.parse(canonical)
        } catch (_: Exception) {
            null
        }
        val resolvedName = name?.takeIf { it.isNotBlank() }
            ?: cfg?.name?.takeIf { it.isNotBlank() }
            ?: cfg?.host
            ?: "server"
        return synchronized(lock) {
            val list = readProfiles().toMutableList()
            if (list.size >= MAX_PROFILES) return@synchronized null
            val p = Profile(newId(), resolvedName, canonical, enabled, System.currentTimeMillis())
            list.add(p)
            writeProfiles(list)
            p
        }
    }

    /** Заменить профиль целиком (id сохраняется). false — нет такого id. */
    fun update(profile: Profile): Boolean = synchronized(lock) {
        val list = readProfiles().toMutableList()
        val idx = list.indexOfFirst { it.id == profile.id }
        if (idx < 0) return@synchronized false
        list[idx] = profile
        writeProfiles(list)
        true
    }

    /** Переименовать (без канона ссылки). false — нет такого id. */
    fun rename(id: String, name: String): Boolean {
        if (name.isBlank()) return false
        val p = byId(id) ?: return false
        return update(p.copy(name = name.trim()))
    }

    /** Включить/выключить профиль. false — нет такого id. */
    fun setEnabled(id: String, enabled: Boolean): Boolean {
        val p = byId(id) ?: return false
        return update(p.copy(enabled = enabled))
    }

    /**
     * Удалить профиль. Если удалили активный PRIMARY — PRIMARY становится
     * первый ВКЛЮЧЁННЫЙ оставшийся профиль (иначе null, KEY_CONFIG
     * НЕ трогаем: пустое зеркало честнее мусора).
     */
    fun remove(id: String): Boolean = synchronized(lock) {
        val list = readProfiles().toMutableList()
        val victim = list.firstOrNull { it.id == id } ?: return@synchronized false
        list.removeAll { it.id == id }
        writeProfiles(list)
        if (activeId() == id) {
            val next = list.firstOrNull { it.enabled }?.id
            setActiveInternal(next)
        }
        true
    }

    /**
     * Сменить активный PRIMARY-профиль. null/несуществующий — PRIMARY нет
     * (зеркало KEY_CONFIG очищается — честный «нет конфига»).
     */
    fun setActive(id: String?): Boolean = synchronized(lock) {
        if (id != null && byId(id) == null) return@synchronized false
        setActiveInternal(id)
        true
    }

    /** Сохранить lastState профиля (дашборд восстанавливает после recreate). */
    fun setLastState(id: String, state: String): Boolean {
        val p = byId(id) ?: return false
        return update(p.copy(lastState = state))
    }

    // ---------------------------------------------------------------- зеркало

    /**
     * Зеркалирование: канон URI активного PRIMARY-профиля → legacy KEY_CONFIG.
     * Вызывается после каждой мутации, затрагивающей PRIMARY. Ошибка парсера
     * канона — зеркалим сырьё (потеря конфига недопустима).
     */
    private fun setActiveInternal(id: String?) {
        if (id == null) {
            backend.putString(KEY_ACTIVE, "")
            backend.remove(mirrorKey())
            return
        }
        backend.putString(KEY_ACTIVE, id)
        val p = byId(id) ?: return
        val canonical = try {
            RrpUri.parse(p.uri).serialize()
        } catch (_: Exception) {
            p.uri
        }
        backend.putString(mirrorKey(), canonical)
    }

    /** Ключ зеркала — по умолчанию legacy KEY_CONFIG ("config"). */
    var mirrorKey: () -> String = { "config" }

    // ---------------------------------------------------------------- JSON

    /**
     * Сериализация профиля — БЕЗ org.json: в JVM unit-тестах Gradle
     * android.jar-заглушки org.json бросают «not mocked», а core обязан
     * быть чистым (прецедент — RrpFrame: «pure Kotlin, без org.json»).
     */
    private fun toJson(p: Profile): String = buildString {
        append('{')
        // MiniJson (RrpFrame) — общий pure-Kotlin JSON-хелпер core-слоя
        append("\"id\":").append(MiniJson.q(p.id)).append(',')
        append("\"name\":").append(MiniJson.q(p.name)).append(',')
        append("\"uri\":").append(MiniJson.q(p.uri)).append(',')
        append("\"enabled\":").append(p.enabled).append(',')
        append("\"createdAt\":").append(p.createdAt).append(',')
        append("\"lastState\":").append(MiniJson.q(p.lastState))
        append('}')
    }

    private fun fromMap(m: Map<String, Any?>): Profile? {
        val id = (m["id"] as? String) ?: return null
        val uri = (m["uri"] as? String) ?: return null
        if (id.isBlank() || uri.isBlank()) return null
        val createdAt = (m["createdAt"] as? Long)
            ?: ((m["createdAt"] as? Double)?.toLong())
            ?: 0L
        return Profile(
            id = id,
            name = (m["name"] as? String) ?: "",
            uri = uri,
            enabled = m["enabled"] == true,
            createdAt = createdAt,
            lastState = (m["lastState"] as? String) ?: "",
        )
    }

    private fun readProfiles(): List<Profile> {
        val raw = backend.getString(KEY_SESSIONS) ?: return emptyList()
        if (raw.isBlank()) return emptyList()
        return try {
            val parsed = SessionJson.parse(raw)
            (parsed as? List<*>)?.mapNotNull { (it as? Map<*, *>)?.let { m -> fromMap(m as Map<String, Any?>) } }
                ?: emptyList()
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun writeProfiles(list: List<Profile>) {
        backend.putString(KEY_SESSIONS, list.joinToString(",", "[", "]") { toJson(it) })
    }

}

/**
 * Минималистичный JSON-парсер (pure Kotlin, без org.json — канон core):
 * только то, что нужно SessionStore — объекты/массивы/строки/числа/bool/null.
 * Битые входы бросают IllegalArgumentException — вызывающий ловит.
 * Поддерживает экранирование \" \\ / b f n r t uXXXX.
 */
internal object SessionJson {

    fun parse(s: String): Any? {
        val p = Parser(s)
        p.ws()
        val v = p.value()
        return v
    }

    private class Parser(val s: String) {
        var i = 0

        fun ws() {
            while (i < s.length && s[i].isWhitespace()) i++
        }

        fun value(): Any? {
            ws()
            if (i >= s.length) throw IllegalArgumentException("eof")
            return when (s[i]) {
                '{' -> obj()
                '[' -> arr()
                '"' -> str()
                't' -> { expect("true"); true }
                'f' -> { expect("false"); false }
                'n' -> { expect("null"); null }
                else -> num()
            }
        }

        fun expect(w: String) {
            if (!s.startsWith(w, i)) throw IllegalArgumentException("at $i")
            i += w.length
        }

        fun obj(): Map<String, Any?> {
            i++ // {
            val m = LinkedHashMap<String, Any?>()
            ws()
            if (i < s.length && s[i] == '}') { i++; return m }
            while (true) {
                ws()
                val k = str()
                ws()
                if (i >= s.length || s[i] != ':') throw IllegalArgumentException("at $i")
                i++
                m[k] = value()
                ws()
                if (i >= s.length) throw IllegalArgumentException("at $i")
                when (s[i]) {
                    ',' -> i++
                    '}' -> { i++; return m }
                    else -> throw IllegalArgumentException("at $i")
                }
            }
        }

        fun arr(): List<Any?> {
            i++ // [
            val l = ArrayList<Any?>()
            ws()
            if (i < s.length && s[i] == ']') { i++; return l }
            while (true) {
                l.add(value())
                ws()
                if (i >= s.length) throw IllegalArgumentException("at $i")
                when (s[i]) {
                    ',' -> i++
                    ']' -> { i++; return l }
                    else -> throw IllegalArgumentException("at $i")
                }
            }
        }

        fun str(): String {
            if (i >= s.length || s[i] != '"') throw IllegalArgumentException("at $i")
            i++
            val sb = StringBuilder()
            while (true) {
                if (i >= s.length) throw IllegalArgumentException("eof in string")
                val c = s[i]
                when {
                    c == '"' -> { i++; return sb.toString() }
                    c == '\\' -> { i++; sb.append(esc()) }
                    else -> { sb.append(c); i++ }
                }
            }
        }

        fun esc(): Char {
            if (i >= s.length) throw IllegalArgumentException("eof in escape")
            val c = s[i]
            i++
            return when (c) {
                'n' -> '\n'
                't' -> '\t'
                'r' -> '\r'
                'b' -> '\b'
                'f' -> ''
                '/' -> '/'
                '\\' -> '\\'
                '"' -> '"'
                'u' -> {
                    if (i + 4 > s.length) throw IllegalArgumentException("eof in uXXXX")
                    val hex = s.substring(i, i + 4)
                    i += 4
                    hex.toInt(16).toChar()
                }
                else -> c
            }
        }

        fun num(): Any {
            val start = i
            while (i < s.length &&
                (s[i].isDigit() || s[i] == '-' || s[i] == '+' || s[i] == '.' || s[i] == 'e' || s[i] == 'E')
            ) i++
            val t = s.substring(start, i)
            if (t.isEmpty()) throw IllegalArgumentException("at $start")
            return if (t.contains('.') || t.contains('e') || t.contains('E')) {
                t.toDouble()
            } else {
                t.toLong()
            }
        }
    }
}
