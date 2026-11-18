package dev.stelgen.reverseray.core

/**
 * v1.8.0: end-to-end пробник полезной нагрузки сквозь туннель.
 *
 * Проблема: PING-потери/EWMA-RTT/PROBE живут ВНУТРИ сессии (контрольные кадры).
 * При сигнатурной блокировке (ТСПУ/DPI режет payload-кадры DATA) сокет,
 * пинги и серверный PROBE могут выглядеть живыми, а полезный трафик — режется.
 *
 * Пробник проверяет СКВОЗНОЙ путь «телефон → туннель → egress сервера → цель»:
 * OPEN через туннель → маленький HTTP-запрос → чтение ответа с таймаутом.
 *
 * Исходы ([classify]):
 *  - [Outcome.Ok]          — ответ с маркером получен за разумное время;
 *  - [Outcome.ReadTimeout] — ответа нет в откалиброванный таймаут → payload
 *                            режется: МЁРТВЫЙ путь (в балансер как deadLoss);
 *  - [Outcome.Rst]         — соединение сброшено без данных (EOF/Close/ошибка
 *                            записи): МЁРТВЫЙ путь;
 *  - [Outcome.Throttle]    — ответ получен, но время >> RTT-базлайна (резкое
 *                            падение скорости) — деградация через обычный
 *                            гистерезис балансера.
 *
 * Таймаут калибруется от RTT-базлайна (failure detector = таймер: слишком
 * длинный таймаут даёт ложно-живые соединения):
 * `timeout = clamp(rttEwma × rttFactor + baseMs, minTimeoutMs, maxTimeoutMs)`.
 *
 * Чистая логика без Android/сети — классификатор и калибровка тестируются
 * юнит-ами (A/B против старого детекта на одних fixture-снимках); исполнение
 * (кадры/сокетпейр) — в RrpClient.
 */
object E2eProbe {

    /** Пороги классификации/таймаутов (инъекция для тестов). */
    data class Cfg(
        /** Таймаут = rttEwma × rttFactor + baseMs. */
        val rttFactor: Long = 6,
        val baseMs: Long = 2_000,
        val minTimeoutMs: Long = 3_000,
        val maxTimeoutMs: Long = 12_000,
        /** Троттлинг: elapsed > max(rttEwma × throttleFactor, throttleFloorMs). */
        val throttleFactor: Long = 8,
        val throttleFloorMs: Long = 6_000,
        /** Маркер успеха в ответе (HTTP-статус generate_204). */
        val marker: String = " 204",
    )

    /** Исход сквозной попытки. */
    sealed class Outcome {
        /** Успех: маркер найден за разумное время. */
        data class Ok(val elapsedMs: Long, val bytes: Int) : Outcome() {
            override fun toString(): String = "ok(${elapsedMs}ms,${bytes}B)"
        }

        /** Соединение сброшено без полезных данных. */
        object Rst : Outcome() {
            override fun toString(): String = "rst"
        }

        /** Ответа нет в таймаут: payload режется (мёртвый путь). */
        object ReadTimeout : Outcome() {
            override fun toString(): String = "read-timeout"
        }

        /** Ответ получен, но скорость резко упала (elapsed >> базлайна). */
        data class Throttle(val elapsedMs: Long, val baselineMs: Long) : Outcome() {
            override fun toString(): String = "throttle(${elapsedMs}ms>${baselineMs}ms)"
        }

        /** Мёртвый исход: полный обрыв полезного трафика (deadLoss балансера). */
        val isDead: Boolean
            get() = this is ReadTimeout || this is Rst
    }

    /** Наблюдение одной попытки чтения (исполнение — RrpClient). */
    data class ReadResult(
        val elapsedMs: Long,
        val bytes: Int,
        /** EOF от цели/пути до маркера (Connection: close — норма при matched). */
        val eof: Boolean,
        /** Таймаут чтения. */
        val timedOut: Boolean,
        /** Маркер найден в прочитанном. */
        val matched: Boolean,
    )

    /** Таймаут пробника от RTT-базлайна (failure detector = таймер). */
    fun timeoutFor(rttEwmaMs: Long, cfg: Cfg = Cfg()): Long =
        (rttEwmaMs * cfg.rttFactor + cfg.baseMs).coerceIn(cfg.minTimeoutMs, cfg.maxTimeoutMs)

    /** Классификация исхода попытки. */
    fun classify(read: ReadResult, rttEwmaMs: Long, cfg: Cfg = Cfg()): Outcome = when {
        read.timedOut -> Outcome.ReadTimeout
        read.bytes <= 0 && read.eof -> Outcome.Rst
        read.matched -> {
            val baseline = maxOf(rttEwmaMs * cfg.throttleFactor, cfg.throttleFloorMs)
            if (read.elapsedMs > baseline) Outcome.Throttle(read.elapsedMs, baseline)
            else Outcome.Ok(read.elapsedMs, read.bytes)
        }
        // данные без маркера / обрыв посреди ответа — путь ломаный
        else -> Outcome.Rst
    }
}
