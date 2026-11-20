package dev.stelgen.reverseray.core

/**
 * v1.8.4: уровни журнала — канон проф. систем (syslog / Bootstrap / Android Log):
 *
 *  TRACE   — протокольная беготня (кадр за кадром, hex-дампы);
 *  DEBUG   — детали хендшейков, паркинг, пер-стрим решения;
 *  INFO    — обычный ход (диал, UDP, счётчики);
 *  NOTICE  — важное уведомление без проблемы (что-то включено/сменено);
 *  OK      — успешный исход (соединено/готово/актуально) — зелёный;
 *  WARN    — предупреждение (сеть дрогнула, потери, лимит близко);
 *  ERROR   — ошибка операции (диал сорвался, конверт битый);
 *  PANIC   — фатальное для процесса/туннеля (падение, закрытие всего).
 *
 * severity монотонно растёт — фильтр LogStore.minLevel отсекает всё «тише»
 * выбранного уровня (настройка «Уровень журнала» на вкладке настроек).
 */
enum class LogKind(val severity: Int) {
    TRACE(0),
    DEBUG(1),
    INFO(2),
    NOTICE(3),
    OK(4),
    WARN(5),
    ERROR(6),
    PANIC(7);

    companion object {
        /** Разбор id настройки («trace».."panic"); null — неизвестно. */
        fun from(id: String?): LogKind? =
            entries.firstOrNull { it.name.equals(id, ignoreCase = true) }
    }
}

/**
 * ЕДИНЫЙ ЛОГ-ЦЕНТР APK (v0.9.6, ревизия v1.8.4).
 *
 * Всё, что приложение пишет в журнал, попадает сюда — в ОДИН большой
 * кольцевой лог. Отдельные окна НЕ имеют своих журналов: они берут из
 * LogStore сообщения СВОЕЙ части (фильтрация по экрану):
 *
 *  - Screen.HOME   — канал STATUS: статусы туннеля;
 *  - Screen.UPDATE — канал UPDATE: журнал автообновления APK и модулей;
 *  - Screen.LOG    — без фильтра: ВСЁ без исключения (вкладка «Лог»).
 *
 * v1.8.4: порог minLevel отсекает записи «тише» уровня ещё на входе —
 * кольцо (и UI) не расходуются на трассировку, пока она не включена.
 *
 * Цвета строк задаёт StatusConsole.roleOf(LogKind) — единственная точка
 * маппинга, одинаковая на всех экранах.
 *
 * Канон приватности: лог живёт ТОЛЬКО в памяти процесса (ни файловых
 * записей, ни телеметрии), делится «Поделиться» владельцем явно.
 *
 * Потокобезопасно: пишут сервис/клиент/апдейтер с разных потоков, читает UI.
 */
object LogStore {

    /** Канал сообщения — какое окно его показывает. */
    enum class Channel { STATUS, UPDATE }

    /** Экраны приложения, потребляющие лог (фильтрация «своей части»). */
    enum class Screen { HOME, UPDATE, LOG }

    /** Строка лога с цветовой ролью, каналом и тегом сессии (v1.5.0). */
    class Entry(
        val text: String,
        val kind: LogKind = LogKind.INFO,
        val channel: Channel = Channel.STATUS,
        val ts: Long = System.currentTimeMillis(),
        /** v1.5.0: имя сессии ("" — общая строка приложения, не сессия). */
        val session: String = "",
    )

    /** Вместимость кольца: «один большой лог» — не 300, а 2000 строк. */
    const val CAPACITY = 2000

    /**
     * v1.8.4: минимальный записываемый уровень (настройка «Уровень журнала»).
     * По умолчанию INFO — пользовательский режим; TRACE/DEBUG включаются
     * осознанно (диагностика протокола). Всё «тише» порога не попадает
     * в кольцо и на экраны.
     */
    @Volatile
    var minLevel: LogKind = LogKind.INFO

    private val ring = ArrayDeque<Entry>(CAPACITY)

    /** Слушатель новых строк (реалтайм-обновления окон; UI сам переключает поток). */
    @Volatile var onEntry: ((Entry) -> Unit)? = null

    /**
     * Запись в единый лог — ЕДИНСТВЕННАЯ точка входа для всего приложения.
     * v1.8.4: записи тише minLevel отбрасываются на входе (до кольца).
     */
    fun push(
        text: String,
        kind: LogKind = LogKind.INFO,
        channel: Channel = Channel.STATUS,
        session: String = "",
    ) {
        if (kind.severity < minLevel.severity) return
        val e = Entry(text, kind, channel, System.currentTimeMillis(), session)
        synchronized(ring) {
            ring.addLast(e)
            while (ring.size > CAPACITY) ring.removeFirst()
        }
        onEntry?.invoke(e)
    }

    /** Канал, который показывает экран (LOG = null — без фильтра, всё). */
    fun channelFor(screen: Screen): Channel? = when (screen) {
        Screen.HOME -> Channel.STATUS
        Screen.UPDATE -> Channel.UPDATE
        Screen.LOG -> null
    }

    /**
     * Снимок лога для экрана: Screen.LOG — ВСЁ (полный лог); иначе — только
     * свой канал. Новые сверху (канон консолей приложения).
     */
    fun snapshotFor(screen: Screen, sessionFilter: String? = null): List<Entry> =
        snapshot(channelFor(screen), sessionFilter)

    /** v1.5.0: имена сессий, встречающиеся в кольце (для фильтра на экране LOG). */
    fun knownSessions(): List<String> = synchronized(ring) {
        ring.map { it.session }.filter { it.isNotBlank() }.distinct()
    }

    /**
     * Снимок лога: channel = null — ВСЁ (полный лог); иначе — только свой
     * канал. Новые сверху (канон консолей приложения).
     */
    fun snapshot(channel: Channel? = null, sessionFilter: String? = null): List<Entry> =
        synchronized(ring) {
            val out = ArrayList<Entry>(ring.size)
            for (e in ring) {
                if (channel != null && e.channel != channel) continue
                if (sessionFilter != null && e.session != sessionFilter) continue
                out.add(e)
            }
            out.asReversed()
        }

    /** Текстовый дамп (кнопка «Поделиться» / отладка). */
    fun dumpText(): String = snapshot().joinToString("\n") { it.text }

    /** Очистка кольца (тесты; между сессиями лог и так пуст — память процесса). */
    fun clear() = synchronized(ring) { ring.clear() }
}
