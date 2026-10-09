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
 *
 * v0.8.1: у каждого протокола есть ИМЯ (label, содержит публичную версию —
 * "RRP/1", "MTProto/2") и ОТДЕЛЬНАЯ публичная версия ("1", "2.0").
 * Они приходят из манифеста модулей (общего с сервером) и пробрасываются
 * во весь стек: статусы, логи, кнопки, вкладки. Если публичной версии
 * в природе нет — пусто: нигде ничего не приписываем.
 */
object RrpProtocols {

    /** Самый стабильный протокол, имплементирован и клиентом, и сервером. */
    const val DEFAULT = "rrp1"

    /** Встроенные (манифест может расширить/выключить — кроме rrp1). */
    val BUNDLED: List<String> = listOf(DEFAULT, MtProto.PROTO_ID)

    /**
     * v0.9.2: протоколы, которые КЛИЕНТ УМЕЕТ ИСПОЛНЯТЬ (код конвертов
     * payload'ов/обмена ключами в этой сборке). Реестр (манифест ∪ сервер)
     * шире — он «реклама» для списков/пикера: новый протокол из модуля
     * виден в GUI ВСЕГДА, но коннектится только когда обе стороны умеют его
     * исполнять (зеркало server/internal/rrp: Negotiate смотрит только
     * исполняемые). Будущая реализация протокола добавляет себя сюда.
     */
    val EXECUTABLE: List<String> = listOf(DEFAULT, MtProto.PROTO_ID)

    /** Умеет ли клиент исполнять протокол (не только показывать в GUI). */
    fun isExecutable(id: String?): Boolean {
        val clean = Modules.normalizeId(id ?: "")
        return EXECUTABLE.contains(clean)
    }

    /**
     * Исполняемая нормализация для подключения: неизвестный/неисполняемый
     * id → дефолт (никогда не ошибка; канон «мусор не ломает стек»).
     * Отображаемая нормализация (normalize) при этом оставляет заявленный id —
     * GUI честно показывает протокол из модуля, даже если исполняется rrp1.
     */
    fun normalizeExecutable(raw: String?): String {
        val shown = normalize(raw)
        return if (isExecutable(shown)) shown else DEFAULT
    }

    /** Встроенные метки/версии — зеркало modules/modules.json (v0.8.1). */
    val BUNDLED_LABELS: Map<String, String> = mapOf(DEFAULT to "RRP/1", MtProto.PROTO_ID to "MTProto/2")
    val BUNDLED_VERS: Map<String, String> = mapOf(DEFAULT to "1", MtProto.PROTO_ID to "2.0")

    // ---- динамический реестр (манифест модулей) ----

    /** v0.9.2: слушатель обновления реестра — GUI перерисовывает списки
     * протоколов СРАЗУ (модуль прилетел / сервер прислал реестр), не дожидаясь
     * очередного статуса. Вызывается на чужом потоке — подписчик сам
     * переключается на UI-поток. */
    @Volatile
    var onRegistryChanged: (() -> Unit)? = null

    @Volatile
    private var registryIds: List<String> = BUNDLED

    @Volatile
    private var registryVersion: String = ""

    @Volatile
    private var registryLabels: Map<String, String> = BUNDLED_LABELS

    @Volatile
    private var registryVers: Map<String, String> = BUNDLED_VERS

    // v0.8.2: модуль камуфляжа «API Mask» из того же манифеста (секция camouflage).
    @Volatile
    private var camouflage: Apimask.Config = Apimask.Config.disabled()

    /**
     * Применяет реестр из манифеста модулей. Гарантии (зеркало SetRegistry
     * сервера): rrp1 остаётся; пустой список НЕ применяется; мусорные id
     * отбрасываются; rrp1 всегда дефолт. labels/vers — метки и публичные
     * версии протоколов (v0.8.1).
     */
    fun applyRegistry(ids: List<String>, version: String) {
        applyRegistryFull(ids, version, emptyMap(), emptyMap())
    }

    /** Полная форма: с метками и версиями из манифеста (мусор → пусто/дефолт). */
    fun applyRegistryFull(ids: List<String>, version: String, labels: Map<String, String>, vers: Map<String, String>) {
        val clean = ids.map { Modules.normalizeId(it) }.filter { it.isNotEmpty() }.toMutableList()
        if (!clean.contains(DEFAULT)) return // реестр без фундамента не применяем
        synchronized(this) {
            registryIds = LinkedHashSet(clean).toList()
            registryVersion = version
            val l = mutableMapOf<String, String>()
            val v = mutableMapOf<String, String>()
            for (id in registryIds) {
                val label = labels[id]?.trim().orEmpty()
                l[id] = if (label.isEmpty()) BUNDLED_LABELS[id] ?: id else label
                // v0.8.1: мусорная версия = «версии нет» (чистим, не ошибка)
                val ver = Modules.sanitizeVer(vers[id])
                v[id] = if (ver.isEmpty()) BUNDLED_VERS[id] ?: "" else ver
            }
            registryLabels = l
            registryVers = v
        }
        // v0.9.2: реестр обновлён (модуль прилетел) — GUI немедленно перерисует
        // списки протоколов (вызывается с фонового потока — подписчик сам
        // переключается на UI-поток).
        onRegistryChanged?.invoke()
    }

    /** Версия активного реестра ("" — встроенный). */
    fun registryVersion(): String = registryVersion

    /**
     * Применяет секцию camouflage манифеста (v0.8.2). Мусорные значения
     * сводятся к дефолтам — канон «мусор не ломает стек».
     */
    fun applyCamouflage(c: Apimask.Config) {
        val lo = if (c.minIntervalSec in 1..3600) c.minIntervalSec else 300
        val hi = if (c.maxIntervalSec in lo..21600) c.maxIntervalSec else 900
        val budget = if (c.maxBytesPerDay in 1..(1024 * 1024)) c.maxBytesPerDay else 256 * 1024
        camouflage = c.copy(
            id = Modules.normalizeId(c.id).ifEmpty { Apimask.FEATURE },
            name = c.name.trim().ifEmpty { "API Mask" },
            ver = Modules.sanitizeVer(c.ver),
            minIntervalSec = lo,
            maxIntervalSec = hi,
            maxBytesPerDay = budget,
        )
    }

    /** Активная конфигурация камуфляжа (выкл по умолчанию — решает манифест). */
    fun camouflageConfig(): Apimask.Config = camouflage

    /** Метка модуля с версией ("API Mask (v1)"); выключен — пусто. */
    fun camouflageLabel(): String = Apimask.labelOf(camouflage)

    /** Толерантная нормализация любого значения (ссылка/сервер/пользователь). */
    fun normalize(raw: String?): String {
        if (raw == null) return DEFAULT
        val s = raw.trim().trim('\"', '\'', '`', '«', '»', '“', '”', '„', '‘', '’')
            .lowercase().trim()
        return if (s in registryIds || isKnown(s)) s else DEFAULT
    }

    /** Известен ли id (учитываем и реестр, полученный от сервера). */
    @Volatile
    private var serverKnown: Set<String> = emptySet()

    /** Запоминает реестр протоколов, присланный сервером (HELLO_OK/READY). */
    fun rememberServerProtocols(ids: List<String>) {
        if (ids.isNotEmpty()) {
            val next = ids.map { it.trim().lowercase() }.filter { it.isNotEmpty() }.toSet()
            val changed = next != serverKnown
            serverKnown = next
            // v0.9.2: сервер прислал реестр (HELLO_OK/READY) — новый протокол
            // немедленно появляется в GUI (пикер/строки протокола).
            if (changed) {
                onRegistryChanged?.invoke()
            }
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

    /**
     * Короткая метка протокола ("RRP/1", "MTProto/2") — из реестра манифеста,
     * одинаковая с сервером. Неизвестный id → сам id (без версии — «пусто»).
     */
    fun label(id: String): String {
        val clean = Modules.normalizeId(id)
        registryLabels[clean]?.let { return it }
        return clean.ifEmpty { id }
    }

    /**
     * Публичная версия протокола ("1", "2.0") или "" — версии нет,
     * нигде не показываем (канон v0.8.1).
     */
    fun ver(id: String): String {
        val clean = Modules.normalizeId(id)
        return registryVers[clean] ?: ""
    }

    /** Строка статуса: "MTProto/2 (v2.0)" или просто "Future/1" без версии. */
    fun labelWithVer(id: String): String {
        val l = label(id)
        val v = ver(id)
        return if (v.isEmpty()) l else "$l (v$v)"
    }

    /** Человекочитаемое имя для UI-переключателя (кнопка = метка + версия). */
    fun displayName(id: String): String = when (id) {
        DEFAULT -> labelWithVer(id) + Msgs.LABEL_STABLE.t()
        MtProto.PROTO_ID -> labelWithVer(id) + Msgs.LABEL_PAYLOAD_ENC.t()
        else -> labelWithVer(id)
    }
}
