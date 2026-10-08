package dev.stelgen.reverseray.update

import android.content.Intent

/**
 * Технический журнал обновлений для вкладки «Обновление» (то же окно, что
 * и лог трафика на главной, — только про обновление: ссылки, версии, ошибки).
 */
object UpdateLogger {

    private val lines = ArrayDeque<String>()

    /** Слушатель для UI (вызывается на добавление строки). */
    @Volatile var onLine: ((String) -> Unit)? = null

    fun add(line: String) {
        synchronized(lines) {
            lines.addFirst(line)
            while (lines.size > 200) lines.removeLast()
        }
        onLine?.invoke(line)
    }

    fun snapshot(): List<String> = synchronized(lines) { lines.toList() }
}
