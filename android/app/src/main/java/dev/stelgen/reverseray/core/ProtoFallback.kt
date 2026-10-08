package dev.stelgen.reverseray.core

/**
 * v0.8.1: Клиентский фоллбек протоколов (модули).
 *
 * Канон: новый протокол приехал модулем, сервер его уже применял — но
 * клиентская реализация/связка сломана. Клиент ОБЯЗАН откатиться на
 * предыдущий рабочий протокол (rrp1 — фундамент), чтобы туннель продолжил
 * работать до обновления сервера/фикса.
 *
 * СЕРВЕР НЕ ФОЛЛБЕЧИТ никогда: иначе получаем цикл фоллбеков — обновления
 * клиента и сервера рассинхронизированы по времени, а авто-обновление может
 * быть вообще отключено (модули заморожены в версиях). Единственный, кто
 * умеет откатываться — клиент, и только локально.
 */
object ProtoFallback {

    /** Сколько неудачных подключений подряд → фоллбек. */
    const val THRESHOLD = 3

    /** Фундамент, на который откатываемся. */
    const val BASE = RrpProtocols.DEFAULT

    /**
     * Нужно ли откатиться на фундамент.
     * @param proto протокол, на котором падаем (уже согласованный/желаемый)
     * @param consecutiveFailures подряд идущие неудачные попытки ПОДКЛЮЧЕНИЯ
     *        именно с этим протоколом (успех обнуляет)
     */
    fun shouldFallback(proto: String, consecutiveFailures: Int): Boolean {
        val p = Modules.normalizeId(proto)
        // фундамент не фоллбечит сам на себя; протокол без нормализации — мусор
        if (p.isEmpty() || p == BASE) return false
        return consecutiveFailures >= THRESHOLD
    }

    /**
     * Строка для журнала при откате. Канон честности: объясняем ПОЧЕМУ и
     * ЧТО делать (ждать обновления сервера/модулей).
     */
    fun fallbackReason(brokenProto: String): String {
        return Msgs.FALLBACK_NOTICE.t(
            RrpProtocols.labelWithVer(brokenProto),
            THRESHOLD,
            RrpProtocols.labelWithVer(BASE),
        )
    }
}
