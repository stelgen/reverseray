package dev.stelgen.reverseray.update

import dev.stelgen.reverseray.core.LogKind
import dev.stelgen.reverseray.core.LogStore

/**
 * Журнал обновлений (v0.9.6→v0.9.7): СВОИХ строк нет — всё пишется в
 * единый лог-центр LogStore каналом UPDATE. Окно «Обновление» берёт
 * из LogStore сообщения своего канала; полный лог видит и это тоже.
 */
object UpdateLogger {

    fun add(line: String, kind: LogKind = LogKind.INFO) {
        LogStore.push(line, kind, LogStore.Channel.UPDATE)
    }

    /** Снимок канала UPDATE из единого лога (новые сверху). */
    fun snapshot(): List<LogStore.Entry> = LogStore.snapshot(LogStore.Channel.UPDATE)
}
