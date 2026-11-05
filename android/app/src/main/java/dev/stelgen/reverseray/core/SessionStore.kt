package dev.stelgen.reverseray.core

import org.json.JSONArray
import org.json.JSONObject

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
            backend.putString(KEY_SESSIONS, JSONArray().toString())
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
        backend.putString(KEY_SESSIONS, JSONArray().put(toJson(p)).toString())
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

    private fun toJson(p: Profile): JSONObject = JSONObject()
        .put("id", p.id)
        .put("name", p.name)
        .put("uri", p.uri)
        .put("enabled", p.enabled)
        .put("createdAt", p.createdAt)
        .put("lastState", p.lastState)

    private fun fromJson(o: JSONObject): Profile? {
        val id = o.optString("id")
        val uri = o.optString("uri")
        if (id.isBlank() || uri.isBlank()) return null
        return Profile(
            id = id,
            name = o.optString("name"),
            uri = uri,
            enabled = o.optBoolean("enabled", false),
            createdAt = o.optLong("createdAt", 0L),
            lastState = o.optString("lastState"),
        )
    }

    private fun readProfiles(): List<Profile> {
        val raw = backend.getString(KEY_SESSIONS) ?: return emptyList()
        if (raw.isBlank()) return emptyList()
        return try {
            val arr = JSONArray(raw)
            (0 until arr.length()).mapNotNull { fromJson(arr.getJSONObject(it)) }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun writeProfiles(list: List<Profile>) {
        val arr = JSONArray()
        for (p in list) arr.put(toJson(p))
        backend.putString(KEY_SESSIONS, arr.toString())
    }
}
