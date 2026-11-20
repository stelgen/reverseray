package dev.stelgen.reverseray.core

/**
 * v1.8.3: очередь паркинга бесшовной смены протокола (0x2C) — канон v1.3.0
 * «буфер в RAM без дропов, backpressure». Payload-кадры (DATA/UDP_DATA)
 * копятся во время перехендшейка и уходят новым конвертом после снятия
 * паркинга. Переполнение окна ставит отправителя на паузу (offer блокируется
 * до снятия паркинга или смерти сессии), а не дропает — «ноль потерь».
 *
 * Чистая логика без IO и логов (логирует клиент по PSW_FLUSHED) — тестируема
 * юнит-тестами без соединения. Потокобезопасно: park/offer/unpark/close из
 * разных потоков (помпы стримов/UDP, reader-диспетчер).
 *
 * v1.8.8: ReentrantLock+Condition вместо synchronized+wait/notify на
 * java.lang.Object (Kotlin-канон: java.lang.Object в Kotlin не рекомендован).
 */
internal class SwitchParking(private val max: Int) {

    private val mutex = java.util.concurrent.locks.ReentrantLock()
    private val notFull: java.util.concurrent.locks.Condition = mutex.newCondition()
    private val queue = java.util.ArrayDeque<RrpFrame>()
    @Volatile private var parked = false
    @Volatile private var closed = false

    /** Паркинг активен (кадры копятся в очередь). */
    fun isParked(): Boolean = parked

    /** Включить паркинг (после ok от сервера; до перехендшейка). */
    fun park() {
        mutex.lock()
        try { parked = true } finally { mutex.unlock() }
    }

    /**
     * Поставить payload-кадр в очередь паркинга.
     * @return true — кадр заквирован (уйдёт после unpark);
     *         false — паркинг снят, кадр уходит обычным путём.
     * @throws RrpClientException сессия умерла при ожидании места в очереди.
     */
    fun offer(frame: RrpFrame, isAlive: () -> Boolean): Boolean {
        mutex.lock()
        try {
            if (closed) throw RrpClientException(Msgs.NO_CONNECTION.t())
            if (!parked) return false
            while (queue.size >= max) {
                if (!isAlive()) throw RrpClientException(Msgs.NO_CONNECTION.t())
                notFull.await(PARK_BLOCK_POLL_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
                if (closed) throw RrpClientException(Msgs.NO_CONNECTION.t()) // сессия мертва
                if (!parked) return false // свитч завершился — обычный путь
            }
            queue.add(frame)
            return true
        } finally {
            mutex.unlock()
        }
    }

    /**
     * Снять паркинг и вернуть накопленное (отправка — на клиенте, уже новым
     * конвертом). Пустой список — паркинг не был включён.
     */
    fun unpark(): List<RrpFrame> {
        mutex.lock()
        try {
            if (!parked) return emptyList()
            parked = false
            val q = ArrayList(queue)
            queue.clear()
            notFull.signalAll() // разбудить backpressure-отправителей
            return q
        } finally {
            mutex.unlock()
        }
    }

    /** Смерть сессии: очередь очищена, заблокированные отправители выходят с ошибкой. */
    fun close() {
        mutex.lock()
        try {
            closed = true
            parked = false
            queue.clear()
            notFull.signalAll()
        } finally {
            mutex.unlock()
        }
    }

    companion object {
        /** v1.8.3: такт блокированного отправителя при полном окне паркинга. */
        const val PARK_BLOCK_POLL_MS = 1000L
    }
}
