package dev.stelgen.reverseray.core

/**
 * Цветовая роль строки журнала (канон v0.9.7 «централизованное логирование»):
 * OK — зелёный (соединение установлено, версия актуальна, лимит не достигнут),
 * WARN — тёмно-жёлтый (подключение/реконнект/важное уведомление),
 * ERR — красный (ошибка/отключение), INFO — обычная «беготня».
 */
enum class LogKind { INFO, OK, WARN, ERR }

/**
 * ЕДИНЫЙ ЛОГ-ЦЕНТР APK (v0.9.6, ревизия v0.9.7 — канон владельца).
 *
 * Всё, что приложение пишет в журнал, попадает сюда — в ОДИН большой
 * кольцевой лог. Отдельные окна НЕ имеют своих журналов: они берут из
 * LogStore сообщения СВОЕЙ части (фильтрация по экрану, v0.9.7):
 *
 *  - Screen.HOME   — канал STATUS: статусы туннеля (старт/подключение/
 *    подключено/отключение/реконнект/ошибка/сеть/лимит);
 *  - Screen.UPDATE — канал UPDATE: журнал автообновления APK и модулей;
 *  - Screen.LOG    — без фильтра: ВСЁ без исключения (вкладка «Лог»).
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

    /** Строка лога с цветовой ролью и каналом. */
    class Entry(
        val text: String,
        val kind: LogKind = LogKind.INFO,
        val channel: Channel = Channel.STATUS,
        val ts: Long = System.currentTimeMillis(),
    )

    /** Вместимость кольца: «один большой лог» — не 300, а 2000 строк. */
    const val CAPACITY = 2000

    private val ring = ArrayDeque<Entry>(CAPACITY)

    /** Слушатель новых строк (реалтайм-обновления окон; UI сам переключает поток). */
    @Volatile var onEntry: ((Entry) -> Unit)? = null

    /** Запись в единый лог — ЕДИНСТВЕННАЯ точка входа для всего приложения. */
    fun push(text: String, kind: LogKind = LogKind.INFO, channel: Channel = Channel.STATUS) {
        val e = Entry(text, kind, channel)
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
    fun snapshotFor(screen: Screen): List<Entry> = snapshot(channelFor(screen))

    /**
     * Снимок лога: channel = null — ВСЁ (полный лог); иначе — только свой
     * канал. Новые сверху (канон консолей приложения).
     */
    fun snapshot(channel: Channel? = null): List<Entry> = synchronized(ring) {
        val out = ArrayList<Entry>(ring.size)
        for (e in ring) {
            if (channel == null || e.channel == channel) out.add(e)
        }
        out.asReversed()
    }

    /** Текстовый дамп (кнопка «Поделиться» / отладка). */
    fun dumpText(): String = snapshot().joinToString("\n") { it.text }

    /** Очистка кольца (тесты; между сессиями лог и так пуст — память процесса). */
    fun clear() = synchronized(ring) { ring.clear() }
}
