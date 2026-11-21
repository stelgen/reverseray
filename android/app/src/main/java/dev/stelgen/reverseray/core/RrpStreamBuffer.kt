package dev.stelgen.reverseray.core

/**
 * Канон Buffer/1 (docs/spec/buffer.md) — зеркало Go server/internal/buf.Buffer.
 * Клиентская мода MODE_FAIL: один производитель (pumpOutgoing), push не
 * блокируется — `false` при переполнении. Байты, прочитанные из сокета цели,
 * но не ушедшие в мёртвый транспорт, дропаться не имеют права: OPEN_RESUME
 * досылает буфер первым (FIFO). Меняешь канон — обновляй ОБЕ стороны.
 */
internal class RrpStreamBuffer(private val cap: Int = CAP) {

    companion object {
        /** Верхняя граница буфера, байт (256 КиБ — синхронно с Go buf.Cap). */
        const val CAP = 256 * 1024

        /** Максимальный чанк одного push, байт (16 КиБ — синхронно с Go buf.MaxChunk). */
        const val MAX_CHUNK = 16 * 1024
    }

    private val chunks = ArrayDeque<ByteArray>()
    private var n = 0

    /** FIFO-хвост: копия чанка; false при переполнении (канон CAP). */
    @Synchronized
    fun push(chunk: ByteArray): Boolean {
        if (n + chunk.size > cap) return false
        chunks.addLast(chunk.copyOf())
        n += chunk.size
        return true
    }

    /** FIFO-голова (null — пуст). */
    @Synchronized
    fun poll(): ByteArray? {
        val c = chunks.removeFirstOrNull() ?: return null
        n -= c.size
        return c
    }

    /** Возврат чанка в голову (повторная попытка при провале отправки). */
    @Synchronized
    fun pushFront(chunk: ByteArray) {
        chunks.addFirst(chunk)
        n += chunk.size
    }

    /** Байтов в буфере. */
    @Synchronized
    fun len(): Int = n

    /** Очистка (окончательное закрытие стрима). */
    @Synchronized
    fun clear() {
        chunks.clear()
        n = 0
    }
}
