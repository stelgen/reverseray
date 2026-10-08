package dev.stelgen.reverseray.core

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * WebSocket-транспорт RRP/1 (v0.7): RFC 6455 binary-only поверх уже
 * установленного TLS (BC-TlsClientProtocol). Используется для обхода
 * DPI-ограничений портов: туннель выглядит как обычный WebSocket-апгрейд.
 *
 * Клиент маскирует исходящие кадры (требование RFC), серверные читает
 * как есть. Одна запись = одно binary-сообщение = один кадр RRP/1.
 * Чтение складывает payload'ы binary-сообщений во внутренний буфер;
 * ping/pong/close протокола WS обрабатываются прозрачно.
 */
class WsStream(
    private val input: InputStream,
    private val output: OutputStream,
    private val host: String,
    private val port: Int,
    private val rnd: SecureRandom = SecureRandom(),
) : InputStream() {

    private var pending: ByteArray = EMPTY
    private var pos = 0

    /** Выполняет HTTP-апгрейд. Бросает RrpClientException при не-101. */
    fun handshake() {
        val keyB = ByteArray(16).also { rnd.nextBytes(it) }
        val key = Base64.getEncoder().encodeToString(keyB)
        val request = buildString {
            append("GET /rrp HTTP/1.1\r\n")
            append("Host: ").append(host).append(':').append(port).append("\r\n")
            append("Upgrade: websocket\r\n")
            append("Connection: Upgrade\r\n")
            append("Sec-WebSocket-Key: ").append(key).append("\r\n")
            append("Sec-WebSocket-Version: 13\r\n")
            append("\r\n")
        }
        output.write(request.toByteArray(Charsets.US_ASCII))
        output.flush()
        val response = readHttpResponse()
        if (!response.startsWith("HTTP/1.1 101") && !response.startsWith("HTTP/1.0 101")) {
            throw RrpClientException(
                Msgs.WS_UPGRADE_REJECTED.t(response.lineSequence().firstOrNull() ?: Msgs.WS_EMPTY_RESPONSE.t())
            )
        }
        // Sec-WebSocket-Accept — защита от фальшивого 101 (MITM на пути).
        // Имя заголовка ищем без учёта регистра, но значение (base64 — регистрозависимо)
        // сравниваем точно.
        val expected = Base64.getEncoder().encodeToString(
            MessageDigest.getInstance("SHA-1")
                .digest((key + WS_GUID).toByteArray(Charsets.US_ASCII))
        )
        val marker = "sec-websocket-accept:"
        val idx = response.lowercase().indexOf(marker)
        if (idx < 0) {
            throw RrpClientException(Msgs.WS_NO_ACCEPT.t())
        }
        val actual = response.substring(idx + marker.length)
            .lineSequence().firstOrNull()?.trim().orEmpty()
        if (actual != expected) {
            throw RrpClientException(Msgs.WS_BAD_ACCEPT.t())
        }
    }

    /** Читает HTTP-ответ целиком (до CRLFCRLF), лимит 8 КБ. */
    private fun readHttpResponse(): String {
        val sb = StringBuilder()
        while (sb.length < MAX_HEADER) {
            val b = input.read()
            if (b < 0) throw EOFException(Msgs.WS_READ_INTERRUPTED.t())
            sb.append(b.toChar())
            if (sb.endsWith("\r\n\r\n")) return sb.toString()
        }
        throw IOException(Msgs.WS_UPGRADE_TOO_LONG.t(sb.length))
    }

    // ------------------ InputStream (кадры сервера) ------------------

    override fun read(): Int {
        val b = ByteArray(1)
        val n = read(b, 0, 1)
        return if (n < 0) -1 else (b[0].toInt() and 0xFF)
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        while (pos >= pending.size) {
            if (!fill()) return -1
        }
        val n = minOf(len, pending.size - pos)
        System.arraycopy(pending, pos, b, off, n)
        pos += n
        return n
    }

    /** Читает следующее binary-сообщение в pending. false = EOF (close/обрыв). */
    private fun fill(): Boolean {
        while (true) {
            val hdr = ByteArray(2)
            readFully(hdr)
            val opcode = hdr[0].toInt() and 0x0F
            val masked = (hdr[1].toInt() and 0x80) != 0
            var len = (hdr[1].toInt() and 0x7F).toLong()
            when (len) {
                126L -> {
                    val ext = ByteArray(2)
                    readFully(ext)
                    len = getU16(ext, 0).toLong()
                }
                127L -> {
                    val ext = ByteArray(8)
                    readFully(ext)
                    val v = getU64(ext)
                    if (v > MAX_MESSAGE) throw RrpFrameException(Msgs.WS_MSG_TOO_BIG.t(v, MAX_MESSAGE))
                    len = v
                }
            }
            if (masked) {
                // сервер не должен маскировать; терпимо пропускаем ключ
                skipFully(4)
            }
            when (opcode) {
                0x2, 0x0 -> { // binary / continuation
                    pending = ByteArray(len.toInt())
                    readFully(pending)
                    pos = 0
                    return true
                }
                0x9 -> { // ping → pong (маскированный)
                    val payload = ByteArray(len.toInt())
                    readFully(payload)
                    writeFrame(0xA, payload)
                }
                0xA -> skipFully(len) // pong
                0x8 -> return false // close
                else -> throw RrpFrameException(Msgs.WS_BAD_OPCODE.t(opcode.toString(16)))
            }
        }
    }

    private fun getU64(b: ByteArray): Long {
        var v = 0L
        for (x in b) v = (v shl 8) or (x.toLong() and 0xFF)
        return v
    }

    private fun skipFully(n: Long) {
        var left = n
        val skip = ByteArray(4096)
        while (left > 0) {
            val r = input.read(skip, 0, minOf(skip.size.toLong(), left).toInt())
            if (r < 0) throw EOFException(Msgs.WS_SKIP_INTERRUPTED.t())
            left -= r
        }
    }

    private fun readFully(dst: ByteArray) {
        var off = 0
        while (off < dst.size) {
            val n = input.read(dst, off, dst.size - off)
            if (n < 0) throw EOFException(Msgs.WS_TRUNCATED.t(dst.size - off))
            off += n
        }
    }

    // ------------------ запись ------------------

    /** Отправляет одно binary-сообщение (маскированное, FIN). */
    fun writeMessage(payload: ByteArray) {
        writeFrame(0x2, payload)
        output.flush()
    }

    fun closeFrame() {
        try {
            writeFrame(0x8, ByteArray(0))
        } catch (_: Exception) {
        }
    }

    private fun writeFrame(opcode: Int, payload: ByteArray) {
        val mask = ByteArray(4).also { rnd.nextBytes(it) }
        val head = java.io.ByteArrayOutputStream(14)
        head.write(0x80 or opcode)
        val n = payload.size
        when {
            n < 126 -> head.write(0x80 or n)
            n <= 0xFFFF -> {
                head.write(0x80 or 126)
                head.write((n ushr 8) and 0xFF)
                head.write(n and 0xFF)
            }
            else -> {
                head.write(0x80 or 127)
                for (i in 7 downTo 0) head.write(((n.toLong() ushr (8 * i)).toInt() and 0xFF))
            }
        }
        head.write(mask)
        // маскируем в копию: payload может быть буфером encode(), который ещё используется
        val masked = ByteArray(n)
        for (i in 0 until n) masked[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
        synchronized(output) {
            output.write(head.toByteArray())
            if (n > 0) output.write(masked)
        }
    }

    override fun close() {
        closeFrame()
    }

    companion object {
        const val WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        const val MAX_HEADER = 8 * 1024
        const val MAX_MESSAGE = 1L shl 20

        private val EMPTY = ByteArray(0)
    }
}
