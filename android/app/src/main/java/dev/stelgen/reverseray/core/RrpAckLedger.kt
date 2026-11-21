// v1.9.8 Buffer/2 (docs/spec/ack.md): LEDGER — send-side реестр отправленных-
// и-неподтверждённых чанков с кумулятивным вытеснением. Зеркало
// server/internal/buf/ledger.go (канон обязывает менять ОБЕ стороны вместе).
//
// Направление p→c (телефон — отправитель): pumpOutgoing кладёт каждый
// отправленный чанк под абсолютным оффсетом; сервер-читатель шлёт
// кумулятивный ACK(0x2F) → evictTo. При потере транспорта LEDGER переживает
// паркинг (ParkedSock) и досылается при OPEN_RESUME: полностью
// подтверждённое отсекается, straddle подрезается — ноль потерь, ноль дублей.
//
// Потокобезопасность: все методы под @synchronized (Go-версия — под mutex).
// Политики как в Go-каноне:
//   - оффсеты абсолютные (base = подтверждённая граница);
//   - evictTo(k < base) — no-op (назад не отматываем);
//   - setBase(k) только на пустом LEDGER (resume-нумерация, K из OPEN_OK);
//   - чанки копируются при append (вызывающий волен переиспользовать буфер).
package dev.stelgen.reverseray.core

internal class RrpAckLedger {
    class Chunk(val offset: Long, val bytes: ByteArray)

    private val chunks = ArrayDeque<Chunk>()

    /** Кумулятивно подтверждено получателем (всё < base выкинуто). */
    var base: Long = 0L
        private set

    /** Абсолютный конец LEDGER: base + объём очереди (Go-канон без next —
     *  setBase на пустом LEDGER автоматически продолжает нумерацию с K). */
    val end: Long
        get() = synchronized(this) { base + queuedBytes() }

    fun size(): Int = chunks.size

    private fun queuedBytes(): Int = chunks.sumOf { it.bytes.size }

    /** setBase — нумерация resume-стрима продолжается с K (K из расширенного
     *  OPEN_OK); только на пустом LEDGER, иначе no-op (Go-семантика). */
    fun setBase(k: Long) {
        synchronized(this) {
            if (chunks.isEmpty()) base = k
        }
    }

    /** Копирует чанк, назначает оффсет (base + очередь), возвращает его. */
    fun append(bytes: ByteArray): Long {
        synchronized(this) {
            val off = base + queuedBytes()
            chunks.addLast(Chunk(off, bytes.copyOf()))
            return off
        }
    }

    /** Кумулятивное вытеснение: всё < k выкидывается, straddle — подрезается. */
    fun evictTo(k: Long) {
        synchronized(this) {
            if (k <= base) return // назад не отматываем
            base = k
            while (chunks.isNotEmpty()) {
                val head = chunks.first()
                val headEnd = head.offset + head.bytes.size
                when {
                    headEnd <= base -> chunks.removeFirst()            // полностью подтверждён
                    head.offset < base -> {                             // straddle — хвост остаётся
                        val cut = (base - head.offset).toInt()
                        chunks.removeFirst()
                        chunks.addFirst(Chunk(base, head.bytes.copyOfRange(cut, head.bytes.size)))
                        return
                    }
                    else -> return                                      // голова уже за базой
                }
            }
        }
    }

    /** Досыл при RESUME: неподтверждённый хвост с оффсетов ≥ k, straddle подрезан. */
    fun replayFrom(k: Long): List<Chunk> {
        synchronized(this) {
            val floor = maxOf(k, base)
            val out = ArrayList<Chunk>(chunks.size)
            for (c in chunks) {
                val cEnd = c.offset + c.bytes.size
                if (cEnd <= floor) continue                    // получатель уже имеет
                val start = maxOf(c.offset, floor)
                val cut = (start - c.offset).toInt()
                out.add(Chunk(start, if (cut == 0) c.bytes else c.bytes.copyOfRange(cut, c.bytes.size)))
            }
            return out
        }
    }

    /** Снимок неподтверждённого хвоста (для паркинга и отладки). */
    fun snapshot(): List<Chunk> {
        synchronized(this) { return chunks.toList() }
    }

    /*
     * KAT (docs/spec/ack.md, векторы общие с Go):
     *   append("0011")→0; append("2233")→2; append("445566")→4
     *   snapshot → base=0, ["0011","2233","445566"]
     *   evictTo(5) → base=5, ["5566"]   (голова подрезана)
     *   evictTo(7) → base=7, []
     *   evictTo(2) → без изменений
     *   replayFrom(5) → ["5566"]; replayFrom(7) → []
     */
}
