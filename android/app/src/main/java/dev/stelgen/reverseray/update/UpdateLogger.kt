package dev.stelgen.reverseray.update

import dev.stelgen.reverseray.core.LogKind
import dev.stelgen.reverseray.core.LogStore

/**
 * Журнал обновлений (v0.9.6): СВОИХ строк больше нет — всё пишется в
 * единый лог-центр LogStore каналом UPDATE. Окно «Обновление» берёт
 * из LogStore сообщения своего канала; полный лог видит и это тоже.
 */
object UpdateLogger {

    /** Слушатель для UI (реалтайм; UI сам решает поток). */
    @Volatile var onLine: ((LogStore.Entry) -> Unit)? = null

    fun add(line: String, kind: LogKind = LogKind.INFO) {
        val e = LogStore.Entry(line, kind, LogStore.Channel.UPDATE)
        LogStore.push(line, kind, LogStore.Channel.UPDATE)
        onLine?.invoke(e)
    }

    /** Снимок канала UPDATE из единого лога (новые сверху). */
    fun snapshot(): List<LogStore.Entry> = LogStore.snapshot(LogStore.Channel.UPDATE)
}
