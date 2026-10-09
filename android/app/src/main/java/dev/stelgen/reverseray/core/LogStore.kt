package dev.stelgen.reverseray.core

/**
 * Цветовая роль строки журнала — цвет в консолях приложения (канон v0.8):
 * OK — зелёный (подключено), ERR — красный (ошибка/отключено),
 * WARN — тёмно-жёлтый (подключение/реконнект), INFO — обычная строка.
 */
enum class LogKind { INFO, OK, WARN, ERR }

/**
 * ЕДИНЫЙ ЛОГ-ЦЕНТР APK (v0.9.6, канон владельца).
 *
 * Всё, что приложение пишет в журнал, попадает сюда — в ОДИН большой
 * кольцевой лог. Отдельные окна (главный экран, обновление, полный лог)
 * НЕ имеют своих журналов: они берут из LogStore сообщения СВОЕГО канала:
 *
 *  - STATUS — статусы туннеля: старт/подключение/подключено/отключение/
 *    переподключение/ошибка/сеть (главный экран красит их цветами:
 *    подключено — зелёный, ошибка/отключено — красный,
 *    подключение/реконнект — тёмно-жёлтый);
 *  - UPDATE — журнал автообновления APK (вкладка «Обновление»);
 *  - полный лог (channel = null) — всё без исключения (вкладка «Лог»).
 *
 * Канон приватности: лог живёт ТОЛЬКО в памяти процесса (ни файловых
 * записей, ни телеметрии), делится «Поделиться» владельцем явно.
 *
 * Потокобезопасно: пишут сервис/клиент/апдейтер с разных потоков, читает UI.
 */
object LogStore {

    /** Канал сообщения — какое окно его показывает. */
    enum class Channel { STATUS, UPDATE }

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
}
