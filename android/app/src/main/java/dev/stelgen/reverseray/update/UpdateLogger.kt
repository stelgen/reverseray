package dev.stelgen.reverseray.update

import dev.stelgen.reverseray.service.LogKind

/**
 * Технический журнал обновлений для вкладки «Обновление» (то же окно и
 * формат, что и лог туннеля на главной). v0.8.2:
 *  - строки несут цветовую роль (как в едином консольном окне);
 *  - слушатель onLine отдаёт строку СРАЗУ в консоль (реалтайм), а не
 *    только при следующем полном перерендере вкладки.
 */
object UpdateLogger {

    class Line(val text: String, val kind: LogKind = LogKind.INFO)

    private val lines = ArrayDeque<Line>()

    /** Слушатель для UI (вызывается на добавление строки; UI сам решает поток). */
    @Volatile var onLine: ((Line) -> Unit)? = null

    fun add(line: String, kind: LogKind = LogKind.INFO) {
        val l = Line(line, kind)
        synchronized(lines) {
            lines.addFirst(l)
            while (lines.size > 200) lines.removeLast()
        }
        onLine?.invoke(l)
    }

    fun snapshot(): List<Line> = synchronized(lines) { lines.toList() }
}
