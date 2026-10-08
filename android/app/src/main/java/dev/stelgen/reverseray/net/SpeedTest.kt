package dev.stelgen.reverseray.net

import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL

/**
 * Короткий спидтест приложения (v0.8): ровно до 5 секунд скачивания,
 * результат — средняя скорость. Правило канона: выполняется ТОЛЬКО если
 * лимит трафика не достигнут; при достигнутом лимите — ноль байт наружу,
 * спидтест не запускается.
 *
 * v0.8.1:
 *  - отдельно проверяет наличие интернета по HTTP (лёгкий GET, код ответа
 *    и задержка);
 *  - отдельно измеряет «пинг» — TCP-коннект до 1.1.1.1:443 (ICMP без root
 *    недоступен — честно называем вещи TCP-пингом);
 *  - ВСЁ, куда ходили, возвращается в отчёте (endpoints) — канон «ничего
 *    не прячем»: статус-окно показывает каждый внешний хост.
 */
object SpeedTest {

    const val DURATION_MS = 5_000L
    const val URL = "https://speed.cloudflare.com/__down?bytes=25000000"
    const val HTTP_CHECK_URL = "https://speed.cloudflare.com/__down?bytes=0"
    const val PING_HOST = "1.1.1.1"
    const val PING_PORT = 443
    private const val MAX_BYTES = 25 * 1024 * 1024L

    data class Result(
        val ok: Boolean,
        val bytesPerSec: Long,
        val totalBytes: Long,
        val durationMs: Long,
        val error: String? = null,
        // v0.8.1: честные телеметрические факты для статус-окна
        val httpOk: Boolean = false,
        val httpMs: Long = 0,
        val pingMs: Long = 0,
        val endpoints: List<String> = emptyList(),
    )

    /** Куда ходит спидтест (для честного статуса ДО запуска). */
    fun plan(): List<String> = listOf(
        "HTTP-проверка интернета ← $HTTP_CHECK_URL (HTTPS)",
        "TCP-пинг → $PING_HOST:$PING_PORT",
        "скачивание 25 МБ ← ${URL.substringBefore('?')} (HTTPS)",
    )

    /** Блокирующий тест (вызывать из фонового потока). Лимит — байт трафика ровно столько, сколько реально скачалось. */
    fun run(): Result {
        val endpoints = mutableListOf<String>()
        val start = System.currentTimeMillis()
        var total = 0L

        // 1) HTTP-проверка наличия интернета (+ задержка)
        val http = httpCheck()
        endpoints.add(if (http.first) "HTTP $HTTP_CHECK_URL → 200 за ${http.second} мс" else "HTTP $HTTP_CHECK_URL → недоступен")
        // нет интернета — дальше не ходим (ноль байт бессмысленного трафика)
        if (!http.first) {
            return Result(false, 0, 0, System.currentTimeMillis() - start, "интернета нет (HTTP-проверка не прошла)", false, http.second, 0, endpoints)
        }

        // 2) TCP-пинг (ICMP без root недоступен — это честный TCP-пинг)
        val ping = tcpPing()
        endpoints.add("TCP-пинг $PING_HOST:$PING_PORT → ${if (ping > 0) "$ping мс" else "нет ответа"}")

        // 3) скачивание
        return try {
            val dlStart = System.currentTimeMillis()
            val conn = URL(URL).openConnection() as HttpURLConnection
            conn.connectTimeout = 3000
            conn.readTimeout = 6000
            conn.setRequestProperty("User-Agent", "ReverseRay-SpeedTest/0.8.1")
            conn.connect()
            val input = conn.inputStream
            val buf = ByteArray(32 * 1024)
            while (total < MAX_BYTES) {
                val elapsed = System.currentTimeMillis() - dlStart
                if (elapsed >= DURATION_MS) break
                val n = input.read(buf, 0, buf.size)
                if (n < 0) break
                total += n
            }
            input.close()
            conn.disconnect()
            endpoints.add("скачивание ${URL.substringBefore('?')} → ${total} Б")
            val duration = (System.currentTimeMillis() - dlStart).coerceAtLeast(1)
            Result(
                ok = total > 0,
                bytesPerSec = total * 1000 / duration,
                totalBytes = total,
                durationMs = duration,
                httpOk = http.first,
                httpMs = http.second,
                pingMs = ping,
                endpoints = endpoints,
            )
        } catch (e: Exception) {
            Result(false, 0, total, System.currentTimeMillis() - start, e.message ?: "?", http.first, http.second, ping, endpoints)
        }
    }

    /** HTTP-проверка интернета: GET маленького ресурса, [ok, задержка мс]. */
    fun httpCheck(url: String = HTTP_CHECK_URL, timeoutMs: Int = 3000): Pair<Boolean, Long> {
        val t0 = System.currentTimeMillis()
        return try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.setRequestProperty("User-Agent", "ReverseRay-Check/0.8.1")
            conn.instanceFollowRedirects = false
            val code = conn.responseCode
            conn.inputStream?.use { it.read(ByteArray(64)) }
            conn.disconnect()
            (code in 200..299) to (System.currentTimeMillis() - t0)
        } catch (_: Exception) {
            false to (System.currentTimeMillis() - t0)
        }
    }

    /** TCP-пинг: время установки TCP-соединения (мс), 0 — не удалось. */
    fun tcpPing(host: String = PING_HOST, port: Int = PING_PORT, timeoutMs: Int = 2000): Long {
        val t0 = System.currentTimeMillis()
        return try {
            Socket().use { s ->
                s.connect(InetSocketAddress(host, port), timeoutMs)
                System.currentTimeMillis() - t0
            }
        } catch (_: Exception) {
            0
        }
    }
}
