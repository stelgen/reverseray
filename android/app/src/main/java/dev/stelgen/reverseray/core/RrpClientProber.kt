@file:Suppress("MatchingDeclarationName") // файл держит также top-level-хелперы рядом с главным типом
// v1.8.0: зона исполнения пробников вынесена из RrpClient.kt (дробление по
// зонам ответственности): валидационный PROBE (кадр запроса серверу) и
// end-to-end пробник полезной нагрузки (E2eProbe, сквозь DATA-кадры).
// Pure refactor: private → internal у задетых членов, поведение не менялось.
package dev.stelgen.reverseray.core

import java.io.IOException
import java.net.Socket
import java.util.concurrent.Semaphore

// ------------------------------------------------------------------ PROBE

/** Результат PROBE-валидации egress. */
internal data class ProbeResult(val ok: Boolean, val err: String)

/**
 * Отправляет PROBE и ждёт ответ (единичный, без ретраев — ретраи и
 * откат делает владелец). null — таймаут/нет ответа.
 */
internal fun RrpClient.probeOnce(target: String, timeoutMs: Long): ProbeResult? {
    if (state != RrpClient.State.READY) return null
    probeResp = null
    return try {
        sendFrame(RrpFrame.ProbeReq(target, timeoutMs))
        val deadline = System.currentTimeMillis() + timeoutMs + 1_000
        while (System.currentTimeMillis() < deadline) {
            probeResp?.let { return ProbeResult(it.ok, it.err) }
            try { Thread.sleep(50) } catch (_: InterruptedException) { return null }
        }
        null
    } catch (e: IOException) {
        log(Msgs.PROBE_SEND_FAILED.t(e.message))
        null
    }
}

// ------------------------------------------------- E2E probe (v1.8.0)

/**
 * E2E-пробник полезной нагрузки: OPEN через туннель → маленький HTTP-запрос
 * (DATA-кадры) → чтение ответа из сокетпейра. Отличается от PROBE (кадр
 * запроса серверу): проверяет именно СКВОЗНОЙ payload-путь, который режет
 * ТСПУ по сигнатурам при живых контрольных кадрах.
 * null — пробник неприменим (не READY / сервер не смог диалить цель —
 * это НЕ признак мёртвого пути, его ловит серверный PROBE).
 */
internal fun RrpClient.e2eProbeOnce(target: String, timeoutMs: Long): E2eProbe.Outcome? {
    if (state != RrpClient.State.READY) return null
    val host = target.substringBeforeLast(':')
    val port = target.substringAfterLast(':').toIntOrNull() ?: return null
    // v1.8.1: socketpair-стрим регистрируется в колбэке ДО отправки OPEN —
    // единый источник id (sendOpen, ЧЁТНЫЙ: серверные нечётные), входящие DATA
    // не промахнутся. v1.8.0-баг: id аллокировался дважды (sendOpen — свой,
    // стрим — свой, к тому же нечётный) → сессия рвалась сервером каждые ~5 с.
    val pair = localSocketPair() ?: return null
    var stRef: RrpClient.Stream? = null
    val err = sendOpen(host, port) { id ->
        val window = tunnelWindow.coerceIn(1, Int.MAX_VALUE.toLong()).toInt()
        stRef = RrpClient.Stream(id, pair.first, Semaphore(window))
        streams[id] = stRef // incoming DATA → handleData → pair.first; читаем pair.second
    }.get()
    if (err != RrpClient.ERR_OK || stRef == null) {
        closeQuietly(pair.first)
        closeQuietly(pair.second)
        return null
    }
    val st = stRef!!
    val id = st.id
    return try {
        val t0 = System.currentTimeMillis()
        sendFrame(RrpFrame.Data(id, 0, RrpClient.E2E_REQUEST)) // IOException → Rst
        val input = pair.second.getInputStream()
        val buf = ByteArray(2048)
        var read = 0
        var eof = false
        var timedOut = false
        try {
            pair.second.soTimeout = timeoutMs.toInt()
            val deadline = t0 + timeoutMs
            while (read < buf.size) {
                if (System.currentTimeMillis() > deadline) { timedOut = true; break }
                val n = input.read(buf, read, buf.size - read)
                if (n < 0) { eof = true; break }
                read += n
                if (String(buf, 0, read, Charsets.ISO_8859_1).contains(RrpClient.E2E_MARKER)) break
            }
        } catch (_: java.net.SocketTimeoutException) {
            timedOut = true
        }
        val elapsed = System.currentTimeMillis() - t0
        val matched = read > 0 && String(buf, 0, read, Charsets.ISO_8859_1).contains(RrpClient.E2E_MARKER)
        E2eProbe.classify(E2eProbe.ReadResult(elapsed, read, eof, timedOut, matched), rttEwmaMs)
    } catch (e: IOException) {
        E2eProbe.Outcome.Rst
    } finally {
        streams.remove(id)
        st.closed.set(true)
        closeQuietly(pair.first)
        closeQuietly(pair.second)
        sendFrameQuiet(RrpFrame.Close(id, RrpClient.ERR_OK))
    }
}

/** Локальный сокетпейр (loopback) — pure JVM, без Android API. */
private fun RrpClient.localSocketPair(): Pair<Socket, Socket>? = try {
    val ss = java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())
    val a = Socket()
    a.connect(ss.localSocketAddress, 1_000)
    a.tcpNoDelay = true
    val b = ss.accept()
    ss.close()
    a to b
} catch (_: Exception) {
    null
}
