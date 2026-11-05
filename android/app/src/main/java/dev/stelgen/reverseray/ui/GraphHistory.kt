package dev.stelgen.reverseray.ui

/**
 * v1.5.1: ЕДИНАЯ история главного графика трафика — пишется ВСЕГДА.
 *
 * Источники сэмплов (кто последний — тот и пишет):
 *  - туннель: ACTION_STATS из TunnelService (rx/tx payload'ов туннеля);
 *  - без туннеля: общесистемные скорости интерфейсов (TrafficStats) —
 *    покоящийся туннель больше НЕ обнуляет график: линия продолжается.
 *
 * Singleton (companion-объект процесса): переживает recreate Activity —
 * restore главного графика больше не зависит от живого сервиса.
 * Чистый Kotlin, вызовы из любых потоков (пишем под локом).
 */
object GraphHistory {

    /** Ёмкость окна (сэмплов). 240 × 500 мс = 2 минуты. */
    const val CAPACITY = 240

    /** Мс тишины от сервиса, после которой включается системный сэмплер. */
    const val SERVICE_SILENCE_MS = 2_500L

    private val lock = Any()
    private val rx = FloatArray(CAPACITY)
    private val tx = FloatArray(CAPACITY)
    private var head = 0
    private var valid = 0

    /** EMA среднего (по тикам, ~500 мс) и пик текущего окна — для подписи. */
    @Volatile var avgRxEma: Float = 0f
        private set
    @Volatile var avgTxEma: Float = 0f
        private set
    @Volatile var peak: Float = 0f
        private set

    /** Сэмплы максимум за последние SERVICE_SILENCE_MS — рисуем в «системном» режиме. */
    @Volatile var lastServiceSampleMs: Long = 0

    /** Пуш сэмпла (байт/с). fromService=true — живой сервис, сбрасывает тишину. */
    fun push(rxRate: Float, txRate: Float, fromService: Boolean) {
        if (fromService) lastServiceSampleMs = System.currentTimeMillis()
        synchronized(lock) {
            head = (head + 1) % CAPACITY
            rx[head] = rxRate.coerceAtLeast(0f)
            tx[head] = txRate.coerceAtLeast(0f)
            if (valid < CAPACITY) valid++
            // EMA 20% нового / 80% истории — сглаживание подписи avg
            avgRxEma = avgRxEma * 0.8f + rxRate.coerceAtLeast(0f) * 0.2f
            avgTxEma = avgTxEma * 0.8f + txRate.coerceAtLeast(0f) * 0.2f
            var p = peak
            for (i in 0 until valid) {
                if (rx[i] > p) p = rx[i]
                if (tx[i] > p) p = tx[i]
            }
            peak = p
        }
    }

    /** Снимок истории: (rx-кольцо, tx-кольцо, head, valid). */
    fun snapshot(): Quad = synchronized(lock) {
        Quad(rx.copyOf(), tx.copyOf(), head, valid)
    }

    /** Снимки avg/peak. */
    fun stats(): Pair<Float, Float> = avgRxEma to peak

    /** Восстановление после recreate (из снимка). */
    fun restore(rxBuf: FloatArray, txBuf: FloatArray, headIdx: Int, validN: Int) {
        if (rxBuf.size != CAPACITY || txBuf.size != CAPACITY) return
        synchronized(lock) {
            System.arraycopy(rxBuf, 0, rx, 0, CAPACITY)
            System.arraycopy(txBuf, 0, tx, 0, CAPACITY)
            head = headIdx.coerceIn(0, CAPACITY - 1)
            valid = validN.coerceIn(0, CAPACITY)
            var p = 0f
            for (i in 0 until valid) {
                if (rx[i] > p) p = rx[i]
                if (tx[i] > p) p = tx[i]
            }
            peak = p
        }
    }

    /** Полный сброс (только по явному требованию UI, сервис НЕ трогает). */
    fun reset() = synchronized(lock) {
        rx.fill(0f); tx.fill(0f); head = 0; valid = 0
        avgRxEma = 0f; avgTxEma = 0f; peak = 0f
    }

    /** кортеж без зависимостей. */
    class Quad(val rx: FloatArray, val tx: FloatArray, val head: Int, val valid: Int)
}
