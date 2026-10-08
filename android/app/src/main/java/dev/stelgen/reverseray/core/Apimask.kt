package dev.stelgen.reverseray.core

import java.util.Random

/**
 * Модуль камуфляжа «API Mask» (v0.8.2, module id: apimask) — клиентская
 * сторона. Туннельный трафик дополняется низкообъёмным фоновым обменом,
 * неотличимым по форме/ритму от API бизнес-приложения: периодические
 * JSON-запросы (телеметрия/синхронизация/очередь) со случайными размерами
 * и джиттером интервала; сервер отвечает API-подобными JSON-ответами.
 *
 * Канон:
 *  - НОЛЬ внешних запросов: шум ходит ТОЛЬКО внутри приватного туннеля
 *    (клиент ↔ сервер), никакого реального egress и внешних хостов;
 *  - НИЧЕГО НЕ ПРЯЧЕМ: каждый обмен честно пишется в консоль, объём виден
 *    в графике трафика и учитывается счётчиком (лимит — король);
 *  - БЮДЖЕТ: max_bytes_per_day из манифеста; исчерпан — шум затихает;
 *  - СОВМЕСТИМОСТЬ: клиент шлёт NOISE (кадр 0x26) только если сервер в
 *    READY заявил features=["apimask"] — старые серверы поле не присылают,
 *    клиент молчит; старые клиенты кадра не знают и от сервера его не
 *    получают (сервер отвечает только на полученный NOISE).
 *
 * Pure Kotlin (без android.*) — тот же класс работает в JVM-тестах.
 */
object Apimask {

    /** Маркер возможности в READY.features (S→C). */
    const val FEATURE = "apimask"

    /** Рабочие пределы тел (зеркало server/internal/apimasq). */
    const val MIN_REQUEST_SIZE = 120
    const val MAX_REQUEST_SIZE = 700

    /** Конфиг модуля из общего манифеста modules.json (секция camouflage). */
    data class Config(
        val id: String,
        val name: String,
        val ver: String,
        val enabled: Boolean,
        val minIntervalSec: Int,
        val maxIntervalSec: Int,
        val maxBytesPerDay: Int,
    ) {
        companion object {
            fun disabled() = Config(FEATURE, "API Mask", "1", false, 300, 900, 256 * 1024)
        }
    }

    /** Метка модуля с версией ("API Mask (v1)") — канон версий по всему стеку. */
    fun labelOf(cfg: Config): String =
        if (!cfg.enabled) "" else if (cfg.ver.isNotEmpty()) "${cfg.name} (v${cfg.ver})" else cfg.name

    /** Интервал до следующего шума: [min;max] сек с равномерным джиттером. */
    fun intervalMs(cfg: Config, rnd: Random): Long {
        val lo = cfg.minIntervalSec.coerceIn(1, 3600)
        val hi = cfg.maxIntervalSec.coerceIn(lo, 6 * 3600)
        return (lo + rnd.nextInt(hi - lo + 1)).toLong() * 1000L
    }

    /**
     * Тело API-запроса: ротация трёх форм, случайные идентификаторы и
     * счётчики; размер держится в [MIN_REQUEST_SIZE;MAX_REQUEST_SIZE] —
     * как у обычных мобильных API-вызовов.
     */
    fun request(rnd: Random, nowMs: Long): String {
        val target = MIN_REQUEST_SIZE + rnd.nextInt(MAX_REQUEST_SIZE - MIN_REQUEST_SIZE + 1)
        val head = "{\"app\":\"" + APPS[rnd.nextInt(APPS.size)] +
            "\",\"v\":\"" + VERS[rnd.nextInt(VERS.size)] +
            "\",\"did\":\"" + hex(rnd, 8 + rnd.nextInt(8)) +
            "\",\"ts\":" + nowMs +
            ",\"kind\":\"" + KINDS[rnd.nextInt(KINDS.size)] + "\","
        val sb = StringBuilder(target + 64)
        sb.append(head)
        when (rnd.nextInt(3)) {
            0 -> { // телеметрия: батч событий
                sb.append("\"events\":[")
                var i = 1
                while (sb.length < target && i <= 64) {
                    if (i > 1) sb.append(',')
                    sb.append("{\"t\":\"").append(TYPES[rnd.nextInt(TYPES.size)])
                        .append("\",\"n\":").append(rnd.nextInt(10000))
                        .append(",\"ms\":").append(20 + rnd.nextInt(900))
                        .append(",\"id\":\"").append(hex(rnd, 6 + rnd.nextInt(6)))
                        .append("\",\"seq\":").append(i).append('}')
                    i++
                }
                sb.append("]}")
            }
            1 -> { // синхронизация конфига: карта опций
                sb.append("\"cursor\":\"").append(hex(rnd, 8 + rnd.nextInt(8))).append("\",\"flags\":{")
                var i = 0
                while (sb.length < target && i <= 64) {
                    if (i > 0) sb.append(',')
                    sb.append("\"opt").append(rnd.nextInt(1000)).append("\":")
                    when (rnd.nextInt(3)) {
                        0 -> sb.append(if (rnd.nextBoolean()) "true" else "false")
                        1 -> sb.append(rnd.nextInt(5000))
                        else -> sb.append('"').append(hex(rnd, 5 + rnd.nextInt(5))).append('"')
                    }
                    i++
                }
                sb.append("}}")
            }
            else -> { // отложенная очередь + подтверждение
                sb.append("\"ack\":").append(rnd.nextInt(100000)).append(",\"items\":[")
                var i = 1
                while (sb.length < target && i <= 64) {
                    if (i > 1) sb.append(',')
                    sb.append("{\"t\":\"").append(TYPES[rnd.nextInt(TYPES.size)])
                        .append("\",\"n\":").append(rnd.nextInt(10000))
                        .append(",\"id\":\"").append(hex(rnd, 6 + rnd.nextInt(6)))
                        .append("\",\"seq\":").append(i).append('}')
                    i++
                }
                sb.append("]}")
            }
        }
        return sb.toString()
    }

    /**
     * Политика шума для RrpClient: движок (конфиг+бюджет) и шаблон честной
     * строки лога — локализуется вызывающей стороной (язык приложения).
     */
    class NoisePolicy(
        val engine: Engine,
        val logLine: (bytes: Int, usedToday: Long, budgetPerDay: Int) -> String,
    )

    /**
     * Движок: конфиг + суточный бюджет. Создаётся TunnelService на сессию,
     * передаётся в RrpClient (расписание + тела + честные строки лога).
     */
    class Engine(val cfg: Config, rnd: Random = Random()) {
        private val rnd = rnd
        private var budgetDay: Long = dayOf(System.currentTimeMillis())
        private var budgetUsed: Long = 0

        /** Задержка до следующего шума (джиттер по манифесту). */
        fun nextDelayMs(): Long = intervalMs(cfg, rnd)

        /**
         * Следующее тело запроса или null — суточный бюджет исчерпан
         * (шум затихает до завтра, туннель не трогаем).
         */
        fun nextRequest(): String? {
            rollBudget()
            if (budgetUsed >= cfg.maxBytesPerDay) return null
            return request(rnd, System.currentTimeMillis())
        }

        /** Учёт отправленных байт шума (считается и в общий трафик телефона). */
        fun onSent(bytes: Int) {
            rollBudget()
            budgetUsed += bytes.toLong()
        }

        /** Израсходовано шума за текущие сутки (для честной строки лога). */
        fun usedToday(): Long {
            rollBudget()
            return budgetUsed
        }

        private fun rollBudget() {
            val d = dayOf(System.currentTimeMillis())
            if (d != budgetDay) {
                budgetDay = d
                budgetUsed = 0
            }
        }

        private fun dayOf(ms: Long): Long = ms / 86_400_000L
    }

    private val APPS = arrayOf("com.acme.workspace", "com.acme.suite", "com.acme.fieldops")
    private val VERS = arrayOf("3.4.1", "3.4.2", "3.5.0")
    private val KINDS = arrayOf("telemetry.batch", "config.sync", "queue.flush")
    private val TYPES = arrayOf("sync", "beat", "metrics", "cache")

    private fun hex(rnd: Random, n: Int): String {
        val chars = "0123456789abcdef"
        val sb = StringBuilder(n * 2)
        for (i in 0 until n * 2) sb.append(chars[rnd.nextInt(chars.length)])
        return sb.toString()
    }
}
