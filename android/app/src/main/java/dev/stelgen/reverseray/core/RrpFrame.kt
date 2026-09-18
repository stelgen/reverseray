package dev.stelgen.reverseray.core

import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * RRP/1 frame codec (pure Kotlin, no Android deps).
 * Header (big-endian, 12 bytes):
 *   [u8 version=1][u8 type][u16 flags][u32 stream_id][u32 payload_len]
 */
object RrpFrame {
    const val VERSION: Int = 1
    const val HEADER_LEN = 12

    const val TYPE_HELLO = 0x01
    const val TYPE_HELLO_OK = 0x02
    const val TYPE_AUTH = 0x03
    const val TYPE_READY = 0x04
    const val TYPE_OPEN = 0x10
    const val TYPE_DATA = 0x11
    const val TYPE_CLOSE = 0x12
    const val TYPE_WINDOW = 0x13
    const val TYPE_PING = 0x14
    const val TYPE_PONG = 0x15
    const val TYPE_OPEN_OK = 0x17
    const val TYPE_STATS = 0x20
    const val TYPE_ERROR = 0x7F

    const val MAX_DATA_PAYLOAD = 64 * 1024
    const val MAX_CONTROL_PAYLOAD = 4096

    fun maxPayloadFor(type: Int): Int =
        if (type == TYPE_DATA) MAX_DATA_PAYLOAD else MAX_CONTROL_PAYLOAD

    class Frame(
        val type: Int,
        val flags: Int,
        val streamId: Long,
        val payload: ByteArray
    ) {
        override fun toString(): String =
            "Frame(type=0x%02x, flags=0x%04x, stream=%d, len=%d)"
                .format(type, flags, streamId, payload.size)
    }

    /** Reads one frame; enforces version and per-type payload limits. */
    @Throws(IOException::class)
    fun read(input: InputStream): Frame {
        val hdr = readFully(input, HEADER_LEN)
        val version = hdr[0].toInt() and 0xFF
        if (version != VERSION) throw IOException("bad RRP version $version")
        val type = hdr[1].toInt() and 0xFF
        val flags = ((hdr[2].toInt() and 0xFF) shl 8) or (hdr[3].toInt() and 0xFF)
        val streamId = u32(hdr, 4)
        val len = u32(hdr, 8).toInt()
        val limit = maxPayloadFor(type)
        if (len > limit) throw IOException("frame too large: type=$type len=$len limit=$limit")
        val payload = if (len > 0) readFully(input, len) else ByteArray(0)
        return Frame(type, flags, streamId, payload)
    }

    @Throws(IOException::class)
    fun write(out: OutputStream, type: Int, flags: Int, streamId: Long, payload: ByteArray) {
        if (payload.size > maxPayloadFor(type)) throw IOException("payload too large for type")
        val hdr = ByteArray(HEADER_LEN)
        hdr[0] = VERSION.toByte()
        hdr[1] = type.toByte()
        hdr[2] = ((flags shr 8) and 0xFF).toByte()
        hdr[3] = (flags and 0xFF).toByte()
        putU32(hdr, 4, streamId)
        putU32(hdr, 8, payload.size.toLong())
        out.write(hdr)
        if (payload.isNotEmpty()) out.write(payload)
        out.flush()
    }

    fun u32(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 4) v = (v shl 8) or (b[off + i].toLong() and 0xFF)
        return v
    }

    fun putU32(b: ByteArray, off: Int, v: Long) {
        b[off] = ((v shr 24) and 0xFF).toByte()
        b[off + 1] = ((v shr 16) and 0xFF).toByte()
        b[off + 2] = ((v shr 8) and 0xFF).toByte()
        b[off + 3] = (v and 0xFF).toByte()
    }

    fun putU16(b: ByteArray, off: Int, v: Int) {
        b[off] = ((v shr 8) and 0xFF).toByte()
        b[off + 1] = (v and 0xFF).toByte()
    }

    fun readFully(input: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = input.read(out, off, n - off)
            if (r < 0) throw EOFException("stream ended at $off/$n")
            off += r
        }
        return out
    }

    fun encodeOpen(atyp: Int, addr: ByteArray, port: Int): ByteArray {
        val p = ByteArrayOutputStream()
        p.write(atyp)
        if (atyp == ATYP_DOMAIN) p.write(addr.size)
        p.write(addr)
        p.write((port shr 8) and 0xFF)
        p.write(port and 0xFF)
        return p.toByteArray()
    }

    const val ATYP_IPV4 = 1
    const val ATYP_DOMAIN = 3
    const val ATYP_IPV6 = 4
}
