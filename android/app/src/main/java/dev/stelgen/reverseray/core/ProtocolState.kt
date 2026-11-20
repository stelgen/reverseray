package dev.stelgen.reverseray.core

/**
 * v1.8.6: ЕДИНЫЙ ИСТОЧНИК ПРАВДЫ «текущий протокол» — одно место, за которым
 * идут ВСЕ вкладки, процессы и логи клиента (канон «никакой разношерсти»).
 *
 * Пишет состояние ТОЛЬКО TunnelService (наследник прежнего рассыпанного
 * состояния: TunnelService.lastNegotiatedProto + MainActivity.lastNegotiatedProto
 * + currentProto()/claimedProto() из зеркала ссылки — читатели могли видеть
 * разные значения после фоллбека: в пикере bittorrent, в строке соединения
 * wireguard). Теперь: сервис — единственный писатель, UI/логи — только читатели.
 *
 * Модель (v1.5.0: профиль — источник правды):
 *  - [claimed]  — заявленный протокол ссылки активного профиля ("" = AUTO);
 *  - [negotiated] — АКТУАЛЬНО согласованный протокол живой сессии ("" — нет
 *    сессии): фиксирует фоллбек сервера «просили bittorrent, согласован
 *    wireguard» — и все читатели видят именно согласованное значение;
 *  - [mode] — режим выбора: FIXED (из ссылки) / AUTO (пусто в ссылке) /
 *    ROTATE (ротация по расписанию).
 *
 * Потоки: @Volatile поля + CopyOnWriteArrayList слушателей; слушатель
 * вызывается с чужого потока — подписчик сам переключается на UI-поток.
 */
object ProtocolState {

    /** Режим выбора протокола (v1.8.0). */
    enum class Mode { FIXED, AUTO, ROTATE }

    /** Постоянные отображения без пояснений (канон «как WS» — просто имя). */
    const val AUTO = "AUTO"
    const val ROTATE = "ROTATE"

    @Volatile
    var mode: Mode = Mode.FIXED
        private set

    /** Актуально согласованный протокол живой сессии ("" — сессии нет). */
    @Volatile
    var negotiated: String = ""
        private set

    /** Заявленный протокол активного профиля ("" = AUTO). */
    @Volatile
    var claimed: String = ""
        private set

    private val listeners = java.util.concurrent.CopyOnWriteArrayList<() -> Unit>()

    /** Подписка на изменения состояния (для перерисовки строк/пикеров). */
    fun onChange(listener: () -> Unit) {
        listeners.add(listener)
    }

    fun removeListener(listener: () -> Unit) {
        listeners.remove(listener)
    }

    /**
     * Единственная точка записи (вызывает только TunnelService).
     * null-аргументы «не трогать»; при любом реальном изменении — слушатели.
     */
    fun update(negotiated: String? = null, claimed: String? = null, mode: Mode? = null) {
        var changed = false
        negotiated?.takeIf { it != this.negotiated }?.let { this.negotiated = it; changed = true }
        claimed?.takeIf { it != this.claimed }?.let { this.claimed = it; changed = true }
        mode?.takeIf { it != this.mode }?.let { this.mode = it; changed = true }
        if (changed) listeners.forEach { it() }
    }

    /**
     * v1.8.6: единый пересчёт claimed/mode из ссылки активного профиля и
     * флага ротации. Вызывают ТОЛЬКО писатели конфига (TunnelService,
     * Dialogs) сразу после записи ссылки; читатели сами ничего не считают.
     */
    fun sync(link: String, rotateEnabled: Boolean) {
        val claimed = try {
            RrpUri.parse(link).proto.trim()
        } catch (_: Exception) {
            ""
        }
        val mode = when {
            rotateEnabled -> Mode.ROTATE
            claimed.isBlank() -> Mode.AUTO
            else -> Mode.FIXED
        }
        update(claimed = claimed, mode = mode)
    }

    /** Актуальный протокол (id): согласованный сессией, иначе заявленный из ссылки. */
    fun actual(): String {
        negotiated.takeIf { it.isNotBlank() }?.let { return it }
        return RrpProtocols.normalizeExecutable(claimed)
    }

    /** Режим с учётом живой сессии: пока сессия есть — показываем её фактический протокол. */
    fun displayMode(): Mode = when {
        negotiated.isNotBlank() -> Mode.FIXED // сессия жива — факты важнее режима
        mode == Mode.ROTATE -> Mode.ROTATE
        claimed.isBlank() -> Mode.AUTO
        else -> Mode.FIXED
    }

    /** Короткое имя протокола для UI БЕЗ пояснений (канон «как WS»). */
    fun plainName(id: String): String = RrpProtocols.label(id)

    /** Отображение текущего протокола для строк «Соединение: …» (просто имя). */
    fun display(): String {
        negotiated.takeIf { it.isNotBlank() }?.let { return plainName(it) }
        return when (displayMode()) {
            Mode.ROTATE -> ROTATE
            Mode.AUTO -> AUTO
            else -> plainName(actual())
        }
    }
}
