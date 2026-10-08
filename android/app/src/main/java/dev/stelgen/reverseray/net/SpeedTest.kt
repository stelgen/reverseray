package dev.stelgen.reverseray.net

import java.net.HttpURLConnection
import java.net.URL

/**
 * Короткий спидтест приложения (v0.8): ровно до 5 секунд скачивания,
 * результат — средняя скорость. Правило канона: выполняется ТОЛЬКО если
 * лимит трафика не достигнут; при достигнутом лимите — ноль байт наружу,
 * спидтест не запускается.
 */
object SpeedTest {

    const val DURATION_MS = 5_000L
    const val URL = "https://speed.cloudflare.com/__down?bytes=25000000"
    private const val MAX_BYTES = 25 * 1024 * 1024L

    data class Result(
        val ok: Boolean,
        val bytesPerSec: Long,
        val totalBytes: Long,
        val durationMs: Long,
        val error: String? = null,
    )

    /** Блокирующий тест (вызывать из фонового потока). Лимит — байт трафика ровно столько, сколько реально скачалось. */
    fun run(): Result {
        val start = System.currentTimeMillis()
        var total = 0L
        return try {
            val conn = URL(URL).openConnection() as HttpURLConnection
            conn.connectTimeout = 3000
            conn.readTimeout = 6000
            conn.setRequestProperty("User-Agent", "ReverseRay-SpeedTest/0.8")
            conn.connect()
            val input = conn.inputStream
            val buf = ByteArray(32 * 1024)
            while (total < MAX_BYTES) {
                val elapsed = System.currentTimeMillis() - start
                if (elapsed >= DURATION_MS) break
                val n = input.read(buf, 0, buf.size)
                if (n < 0) break
                total += n
            }
            input.close()
            conn.disconnect()
            val duration = (System.currentTimeMillis() - start).coerceAtLeast(1)
            Result(
                ok = total > 0,
                bytesPerSec = total * 1000 / duration,
                totalBytes = total,
                durationMs = duration,
            )
        } catch (e: Exception) {
            Result(false, 0, total, System.currentTimeMillis() - start, e.message ?: "?")
        }
    }
}