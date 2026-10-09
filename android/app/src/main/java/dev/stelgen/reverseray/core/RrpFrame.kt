package dev.stelgen.reverseray.core

import java.io.ByteArrayInputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream

/** Ошибка кодека кадров RRP/1 (битый заголовок, превышение лимитов, неизвестный тип). */
class RrpFrameException(message: String, cause: Throwable? = null) : IOException(message, cause)

// --- u16/u32 BE-хелперы (используются также RrpAddress/RrpUri) ---

internal fun putU16(dst: ByteArray, off: Int, v: Int) {
    dst[off] = ((v ushr 8) and 0xFF).toByte()
    dst[off + 1] = (v and 0xFF).toByte()
}

internal fun putU32(dst: ByteArray, off: Int, v: Long) {
    for (i in 0 until 4) {
        dst[off + i] = ((v ushr (8 * (3 - i))) and 0xFFL).toByte()
    }
}

internal fun getU16(src: ByteArray, off: Int): Int =
    ((src[off].toInt() and 0xFF) shl 8) or (src[off + 1].toInt() and 0xFF)

internal fun getU32(src: ByteArray, off: Int): Long =
    ((src[off].toLong() and 0xFF) shl 24) or ((src[off + 1].toLong() and 0xFF) shl 16) or
        ((src[off + 2].toLong() and 0xFF) shl 8) or (src[off + 3].toLong() and 0xFF)

/**
 * Кадр RRP/1: 12 байт BE-заголовка [u8 ver=1][u8 type][u16 flags][u32 stream_id][u32 payload_len].
 *
 * Pure Kotlin: ни одного android.* импорта — кодек собирается и в plain JVM-тестах.
 * Лимиты payload по типам: DATA ≤ 65535, контрольные ≤ 4096.
 */
sealed class RrpFrame(val type: Int) {

    open val streamId: Long get() = 0L
    open val flags: Int get() = 0

    protected abstract fun buildPayload(): ByteArray

    fun encode(): ByteArray {
        val payload = buildPayload()
        val max = maxPayloadFor(type)
        if (payload.size > max) {
            throw RrpFrameException(
                Msgs.FRAME_PAYLOAD_LIMIT.t(payload.size, max, Integer.toHexString(type))
            )
        }
        if (streamId !in 0..0xFFFFFFFFL) throw RrpFrameException(Msgs.STREAM_ID_RANGE.t(streamId))
        if (flags !in 0..0xFFFF) throw RrpFrameException(Msgs.FLAGS_RANGE.t(flags))
        val out = ByteArray(HEADER_SIZE + payload.size)
        out[0] = VERSION.toByte()
        out[1] = type.toByte()
        putU16(out, 2, flags)
        putU32(out, 4, streamId)
        putU32(out, 8, payload.size.toLong())
        payload.copyInto(out, HEADER_SIZE)
        return out
    }

    // ------------------- типы кадров -------------------

    /** 0x01 C→S: JSON {agent, ver, device, caps, max_streams, proto}.
     *  v0.7.4 ФИКС: ver — ОБЯЗАТЕЛЬНО строка в кавычках ("ver":"1").
     *  APK 0.7.3 слал число ("ver":1) — сервер Go падал на json.Unmarshal
     *  в string-поле и отвечал ERROR 2 «protocol error» (регресс на проде).
     *  Канон-строка валидна и для старых серверов 0.7.x, и для новых. */
    class Hello(
        val agent: String,
        val protocolVersion: Int,
        val device: String,
        val caps: List<String>,
        val maxStreams: Int,
        /** Желаемый протокол (значение &proto= из ссылки; мусор → сервер сводит к дефолту). */
        val proto: String = "rrp1",
        /** Список протоколов, которые клиент готов поддерживать. */
        val protocols: List<String> = listOf(proto),
    ) : RrpFrame(TYPE_HELLO) {
        override fun buildPayload(): ByteArray {
            val capsJson = caps.joinToString(",") { MiniJson.q(it) }
            val protosJson = protocols.joinToString(",") { MiniJson.q(it) }
            val json = MiniJson.obj(
                "agent" to MiniJson.q(agent),
                "ver" to MiniJson.q(protocolVersion.toString()), // КАНОН: строка!
                "device" to MiniJson.q(device),
                "caps" to "[$capsJson]",
                "max_streams" to maxStreams.toString(),
                "proto" to MiniJson.q(proto),
                "protocols" to "[$protosJson]",
            )
            return json.toByteArray(Charsets.UTF_8)
        }

        companion object {
            internal fun fromJson(p: ByteArray): Hello {
                val m = MiniJson.parseFlat(p) ?: throw RrpFrameException(Msgs.HELLO_BAD_JSON.t())
                val caps = (m["caps"] ?: "")
                    .split(',')
                    .map { it.trim().trim('"') }
                    .filter { it.isNotEmpty() }
                val protos = (m["protocols"] ?: "")
                    .split(',')
                    .map { it.trim().trim('"') }
                    .filter { it.isNotEmpty() }
                return Hello(
                    agent = m["agent"] ?: "",
                    protocolVersion = m["ver"]?.toIntOrNull() ?: VERSION,
                    device = m["device"] ?: "",
                    caps = caps,
                    maxStreams = m["max_streams"]?.toIntOrNull() ?: 0,
                    proto = m["proto"] ?: "rrp1",
                    protocols = protos,
                )
            }
        }
    }

    /** 0x02 S→C: JSON {session_id, server_ver, nonce, tunnel_window}. nonce — base64url, одноразовый. */
    class HelloOk(
        val sessionId: String,
        val serverVer: String,
        val nonce: String,
        val tunnelWindow: Long,
        /** Протокол, выбранный сервером для сессии. */
        val proto: String = "rrp1",
        /** Полный реестр протоколов сервера (для UI-переключателя). */
        val protocols: List<String> = emptyList(),
    ) : RrpFrame(TYPE_HELLO_OK) {
        override fun buildPayload(): ByteArray = MiniJson.obj(
            "session_id" to MiniJson.q(sessionId),
            "server_ver" to MiniJson.q(serverVer),
            "nonce" to MiniJson.q(nonce),
            "tunnel_window" to tunnelWindow.toString(),
            "proto" to MiniJson.q(proto),
        ).toByteArray(Charsets.UTF_8)

        companion object {
            internal fun fromJson(p: ByteArray): HelloOk {
                val m = MiniJson.parseFlat(p) ?: throw RrpFrameException(Msgs.HELLO_OK_BAD_JSON.t())
                return HelloOk(
                    sessionId = m["session_id"] ?: "",
                    serverVer = m["server_ver"] ?: "",
                    nonce = m["nonce"] ?: "",
                    tunnelWindow = m["tunnel_window"]?.toLongOrNull() ?: 0L,
                    proto = m["proto"] ?: "rrp1",
                    protocols = splitCsv(m["protocols"]),
                )
            }

            internal fun splitCsv(raw: String?): List<String> =
                (raw ?: "").split(',').map { it.trim().trim('"') }.filter { it.isNotEmpty() }
        }
    }

    /** 0x03 C→S: JSON {mode:"token-hmac", hmac, nonce}. nonce добавлен к спецификационному
     *  набору полей — без него сервер не сможет воспроизвести HMAC(token, nonce||session_id). */
    class Auth(
        val mode: String,
        val hmacB64: String,
        val nonceB64: String,
    ) : RrpFrame(TYPE_AUTH) {
        override fun buildPayload(): ByteArray = MiniJson.obj(
            "mode" to MiniJson.q(mode),
            "hmac" to MiniJson.q(hmacB64),
            "nonce" to MiniJson.q(nonceB64),
        ).toByteArray(Charsets.UTF_8)

        companion object {
            internal fun fromJson(p: ByteArray): Auth {
                val m = MiniJson.parseFlat(p) ?: throw RrpFrameException(Msgs.AUTH_BAD_JSON.t())
                return Auth(m["mode"] ?: "", m["hmac"] ?: "", m["nonce"] ?: "")
            }
        }
    }

    /** 0x04 S→C: JSON {tunnel_id, role, max_streams, tunnel_window} */
    class Ready(
        val tunnelId: String,
        val role: String,
        val maxStreams: Int,
        val tunnelWindow: Long,
        /** Протокол сессии (финальное подтверждение). */
        val proto: String = "rrp1",
        /** Реестр протоколов сервера. */
        val protocols: List<String> = emptyList(),
        /** v0.8.2: возможности сервера поверх протокола (additive; старые
         *  серверы поле не присылают — клиент тогда молчит по NOISE). */
        val features: List<String> = emptyList(),
    ) : RrpFrame(TYPE_READY) {
        override fun buildPayload(): ByteArray = MiniJson.obj(
            "tunnel_id" to MiniJson.q(tunnelId),
            "role" to MiniJson.q(role),
            "max_streams" to maxStreams.toString(),
            "tunnel_window" to tunnelWindow.toString(),
        ).toByteArray(Charsets.UTF_8)

        companion object {
            internal fun fromJson(p: ByteArray): Ready {
                val m = MiniJson.parseFlat(p) ?: throw RrpFrameException(Msgs.READY_BAD_JSON.t())
                return Ready(
                    tunnelId = m["tunnel_id"] ?: "",
                    role = m["role"] ?: "",
                    maxStreams = m["max_streams"]?.toIntOrNull() ?: 0,
                    tunnelWindow = m["tunnel_window"]?.toLongOrNull() ?: 0L,
                    proto = m["proto"] ?: "rrp1",
                    protocols = HelloOk.splitCsv(m["protocols"]),
                    features = HelloOk.splitCsv(m["features"]),
                )
            }
        }
    }

    /** 0x10 S→C: binary [u8 atyp][addr][u16be port] */
    class Open(
        override val streamId: Long,
        val atyp: Int,
        val addr: ByteArray,
        val port: Int,
    ) : RrpFrame(TYPE_OPEN) {
        override fun buildPayload(): ByteArray {
            val p = ByteArray(1 + addr.size + 2)
            p[0] = atyp.toByte()
            addr.copyInto(p, 1)
            putU16(p, 1 + addr.size, port)
            return p
        }

        companion object {
            internal fun fromPayload(streamId: Long, p: ByteArray): Open {
                if (p.isEmpty()) throw RrpFrameException(Msgs.OPEN_EMPTY.t())
                val atyp = p[0].toInt() and 0xFF
                val (addrOff, addrLen) = when (atyp) {
                    RrpAddress.ATYP_IPV4 -> 1 to 4
                    RrpAddress.ATYP_IPV6 -> 1 to 16
                    RrpAddress.ATYP_DOMAIN -> {
                        if (p.size < 2) throw RrpFrameException(Msgs.OPEN_NO_HOSTLEN.t())
                        2 to (p[1].toInt() and 0xFF)
                    }
                    else -> throw RrpFrameException(Msgs.OPEN_BAD_ATYP.t(atyp))
                }
                if (p.size < addrOff + addrLen + 2) throw RrpFrameException(Msgs.OPEN_SHORT.t())
                val addr = p.copyOfRange(addrOff, addrOff + addrLen)
                return Open(streamId, atyp, addr, getU16(p, addrOff + addrLen))
            }
        }
    }

    /** 0x17 C→S: [u8 err_code] */
    class OpenOk(
        override val streamId: Long,
        val errCode: Int,
    ) : RrpFrame(TYPE_OPEN_OK) {
        override fun buildPayload(): ByteArray = byteArrayOf(errCode.toByte())

        companion object {
            internal fun fromPayload(streamId: Long, p: ByteArray): OpenOk {
                if (p.size != 1) throw RrpFrameException(Msgs.OPEN_OK_SIZE.t(p.size))
                return OpenOk(streamId, p[0].toInt() and 0xFF)
            }
        }
    }

    /** 0x11: DATA payload ≤ 65535 */
    class Data(
        override val streamId: Long,
        override val flags: Int,
        val bytes: ByteArray,
    ) : RrpFrame(TYPE_DATA) {
        override fun buildPayload(): ByteArray = bytes
    }

    /** 0x12: [u8 err] */
    class Close(
        override val streamId: Long,
        val errCode: Int,
    ) : RrpFrame(TYPE_CLOSE) {
        override fun buildPayload(): ByteArray = byteArrayOf(errCode.toByte())

        companion object {
            internal fun fromPayload(streamId: Long, p: ByteArray): Close {
                if (p.size != 1) throw RrpFrameException(Msgs.CLOSE_SIZE.t(p.size))
                return Close(streamId, p[0].toInt() and 0xFF)
            }
        }
    }

    /** 0x13: [u32be increment] */
    class Window(
        override val streamId: Long,
        val increment: Long,
    ) : RrpFrame(TYPE_WINDOW) {
        override fun buildPayload(): ByteArray = ByteArray(4).also { putU32(it, 0, increment) }

        companion object {
            internal fun fromPayload(streamId: Long, p: ByteArray): Window {
                if (p.size != 4) throw RrpFrameException(Msgs.WINDOW_SIZE.t(p.size))
                return Window(streamId, getU32(p, 0))
            }
        }
    }

    /** 0x14: [8B nonce] */
    class Ping(val nonce: ByteArray) : RrpFrame(TYPE_PING) {
        override fun buildPayload(): ByteArray = nonce

        companion object {
            internal fun fromPayload(p: ByteArray): Ping {
                if (p.size != 8) throw RrpFrameException(Msgs.PING_SIZE.t(p.size))
                return Ping(p.copyOf())
            }
        }
    }

    /** 0x15: [8B nonce] */
    class Pong(val nonce: ByteArray) : RrpFrame(TYPE_PONG) {
        override fun buildPayload(): ByteArray = nonce

        companion object {
            internal fun fromPayload(p: ByteArray): Pong {
                if (p.size != 8) throw RrpFrameException(Msgs.PONG_SIZE.t(p.size))
                return Pong(p.copyOf())
            }
        }
    }

    /** 0x21 S→C: пустой payload, stream_id = id UDP-ассоциации. Телефон отвечает OPEN_OK. */
    class UdpAssoc(override val streamId: Long) : RrpFrame(TYPE_UDP_ASSOC) {
        override fun buildPayload(): ByteArray = ByteArray(0)
    }

    /**
     * 0x22: [u8 atyp][addr][u16be port][data].
     * S→C — адрес назначения (телефон шлёт дейтаграмму),
     * C→S — фактический источник ответа.
     */
    class UdpData(
        override val streamId: Long,
        val atyp: Int,
        val addr: ByteArray,
        val port: Int,
        val bytes: ByteArray,
    ) : RrpFrame(TYPE_UDP_DATA) {
        override fun buildPayload(): ByteArray {
            val p = ByteArray(1 + addr.size + 2 + bytes.size)
            p[0] = atyp.toByte()
            addr.copyInto(p, 1)
            putU16(p, 1 + addr.size, port)
            bytes.copyInto(p, 3 + addr.size)
            return p
        }

        companion object {
            internal fun fromPayload(streamId: Long, p: ByteArray): UdpData {
                if (p.isEmpty()) throw RrpFrameException(Msgs.UDP_EMPTY.t())
                val atyp = p[0].toInt() and 0xFF
                val (addrOff, addrLen) = when (atyp) {
                    RrpAddress.ATYP_IPV4 -> 1 to 4
                    RrpAddress.ATYP_IPV6 -> 1 to 16
                    RrpAddress.ATYP_DOMAIN -> {
                        if (p.size < 2) throw RrpFrameException(Msgs.UDP_NO_HOSTLEN.t())
                        2 to (p[1].toInt() and 0xFF)
                    }
                    else -> throw RrpFrameException(Msgs.UDP_BAD_ATYP.t(atyp))
                }
                if (p.size < addrOff + addrLen + 2) throw RrpFrameException(Msgs.UDP_SHORT.t())
                val port = getU16(p, addrOff + addrLen)
                val dataOff = addrOff + addrLen + 2
                return UdpData(streamId, atyp, p.copyOfRange(addrOff, addrOff + addrLen), port,
                    p.copyOfRange(dataOff, p.size))
            }
        }
    }

    /** 0x23 C→S: JSON {"target":"host:port","timeout_ms":N} — запрос валидации egress. */
    class ProbeReq(
        val target: String,
        val timeoutMs: Long = 5_000,
    ) : RrpFrame(TYPE_PROBE) {
        override fun buildPayload(): ByteArray = MiniJson.obj(
            "target" to MiniJson.q(target),
            "timeout_ms" to timeoutMs.toString(),
        ).toByteArray(Charsets.UTF_8)
    }

    /** 0x23 S→C: JSON {"ok":true|false,"err":"","proto":"rrp1"} — ответ на PROBE. */
    class ProbeResp(
        val ok: Boolean,
        val err: String,
        val proto: String,
    ) : RrpFrame(TYPE_PROBE) {
        override fun buildPayload(): ByteArray = MiniJson.obj(
            "ok" to ok.toString(),
            "err" to MiniJson.q(err),
            "proto" to MiniJson.q(proto),
        ).toByteArray(Charsets.UTF_8)

        companion object {
            internal fun fromPayload(p: ByteArray): ProbeResp {
                val m = MiniJson.parseFlat(p)
                    ?: throw RrpFrameException(Msgs.PROBE_BAD_JSON.t())
                return ProbeResp(
                    ok = (m["ok"] ?: "false") == "true",
                    err = m["err"] ?: "",
                    proto = m["proto"] ?: "rrp1",
                )
            }
        }
    }

    /**
     * 0x26 (v0.8.2, модуль камуфляжа «API Mask», bidirectional): payload —
     * JSON-объект, похожий на обмен бизнес-API. Клиент шлёт NOISE только если
     * сервер в READY заявил features=["apimask"]; сервер отвечает только на
     * полученный NOISE — старые версии обеих сторон кадр не видят никогда.
     */
    class Noise(val json: String) : RrpFrame(TYPE_NOISE) {
        override fun buildPayload(): ByteArray = json.toByteArray(Charsets.UTF_8)

        companion object {
            internal fun fromPayload(p: ByteArray): Noise {
                val s = String(p, Charsets.UTF_8).trim()
                if (s.isEmpty() || s[0] != '{' || s[s.length - 1] != '}') {
                    throw RrpFrameException(Msgs.NOISE_NOT_JSON.t())
                }
                // ВАЖНО: тела NOISE содержат ВЛОЖЕННЫЕ объекты/массивы —
                // MiniJson.parseFlat умеет только плоские, поэтому здесь
                // лёгкая проверка сбалансированности (pure Kotlin, без org.json):
                // битый кадр = мусор шума, а не повод рвать туннель... но канал
                // декодирования кадров строгий: мусор отсекается здесь.
                if (!balancedJson(s)) {
                    throw RrpFrameException(Msgs.NOISE_BAD_JSON.t())
                }
                return Noise(s)
            }

            /** Сбалансированы ли {}, [] вне строк (кавычки/escape учитываются). */
            internal fun balancedJson(s: String): Boolean {
                var braces = 0
                var brackets = 0
                var inString = false
                var escaped = false
                for (c in s) {
                    if (inString) {
                        when {
                            escaped -> escaped = false
                            c == '\\' -> escaped = true
                            c == '"' -> inString = false
                        }
                        continue
                    }
                    when (c) {
                        '"' -> inString = true
                        '{' -> braces++
                        '}' -> {
                            braces--
                            if (braces < 0) return false
                        }
                        '[' -> brackets++
                        ']' -> {
                            brackets--
                            if (brackets < 0) return false
                        }
                    }
                }
                return !inString && braces == 0 && brackets == 0
            }
        }
    }

    /** 0x24 S→C (mtproto2): JSON {p,g,g_a} — параметры DH (base64url 256-байтовые доли). */
    class KeyReq(
        val p: String = "",
        val g: Int = 0,
        val gA: String = "",
        /** v0.9.5: kind протокола ("wireguard") — непустой ⇒ WG-хендшейк. */
        val kind: String = "",
        /** v0.9.5: WG static public сервера (b64url 32 Б) для kind=wireguard. */
        val sPub: String = "",
    ) : RrpFrame(TYPE_KEY_REQ) {
        override fun buildPayload(): ByteArray = MiniJson.obj(
            "p" to MiniJson.q(p),
            "g" to g.toString(),
            "g_a" to MiniJson.q(gA),
            "kind" to MiniJson.q(kind),
            "spub" to MiniJson.q(sPub),
        ).toByteArray(Charsets.UTF_8)

        companion object {
            internal fun fromPayload(p: ByteArray): KeyReq {
                val m = MiniJson.parseFlat(p) ?: throw RrpFrameException(Msgs.KEY_REQ_BAD_JSON.t())
                return KeyReq(
                    m["p"] ?: "", m["g"]?.toIntOrNull() ?: 0, m["g_a"] ?: "",
                    m["kind"] ?: "", m["spub"] ?: "",
                )
            }
        }
    }

    /** 0x25 C→S (mtproto2): JSON {g_b} — публичная доля клиента. */
    class KeyResp(val gB: String) : RrpFrame(TYPE_KEY_RESP) {
        override fun buildPayload(): ByteArray = MiniJson.obj(
            "g_b" to MiniJson.q(gB),
        ).toByteArray(Charsets.UTF_8)

        companion object {
            internal fun fromPayload(p: ByteArray): KeyResp {
                val m = MiniJson.parseFlat(p) ?: throw RrpFrameException(Msgs.KEY_RESP_BAD_JSON.t())
                return KeyResp(m["g_b"] ?: "")
            }
        }
    }

    /** 0x27 C→S (wireguard): бинарный payload — НАСТОЯЩИЙ WG msg1 (148 Б). */
    class WgInit(val raw: ByteArray) : RrpFrame(TYPE_WG_INIT) {
        override fun buildPayload(): ByteArray = raw

        companion object {
            internal fun fromPayload(p: ByteArray): WgInit = WgInit(p)
        }
    }

    /** 0x28 S→C (wireguard): бинарный payload — НАСТОЯЩИЙ WG msg2 (92 Б). */
    class WgResp(val raw: ByteArray) : RrpFrame(TYPE_WG_RESP) {
        override fun buildPayload(): ByteArray = raw

        companion object {
            internal fun fromPayload(p: ByteArray): WgResp = WgResp(p)
        }
    }

    /** 0x2A C→S (v0.9.5): JSON {"enabled":true|false} — выбор камуфляжа устройством. */
    class CamCtl(val enabled: Boolean) : RrpFrame(TYPE_CAM_CTL) {
        override fun buildPayload(): ByteArray = MiniJson.obj(
            "enabled" to enabled.toString(),
        ).toByteArray(Charsets.UTF_8)

        companion object {
            internal fun fromPayload(p: ByteArray): CamCtl {
                val m = MiniJson.parseFlat(p) ?: throw RrpFrameException(Msgs.KEY_REQ_BAD_JSON.t())
                return CamCtl(m["enabled"] == "true")
            }
        }
    }

    /** 0x20: utf8 JSON */
    class Stats(val json: String) : RrpFrame(TYPE_STATS) {
        override fun buildPayload(): ByteArray = json.toByteArray(Charsets.UTF_8)

        companion object {
            internal fun fromPayload(p: ByteArray): Stats = Stats(String(p, Charsets.UTF_8))
        }
    }

    /** 0x7F: [u16be code][utf8 msg] */
    class ErrorFrame(val code: Int, val message: String) : RrpFrame(TYPE_ERROR) {
        override fun buildPayload(): ByteArray {
            val msg = message.toByteArray(Charsets.UTF_8)
            if (msg.size > MAX_CONTROL_PAYLOAD - 2) {
                throw RrpFrameException(Msgs.ERROR_TOO_LONG.t())
            }
            val p = ByteArray(2 + msg.size)
            putU16(p, 0, code)
            msg.copyInto(p, 2)
            return p
        }

        companion object {
            internal fun fromPayload(p: ByteArray): ErrorFrame {
                if (p.size < 2) throw RrpFrameException(Msgs.ERROR_SHORT.t())
                return ErrorFrame(getU16(p, 0), String(p, 2, p.size - 2, Charsets.UTF_8))
            }
        }
    }

    companion object {
        const val VERSION = 1
        const val HEADER_SIZE = 12

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
        const val TYPE_UDP_ASSOC = 0x21
        const val TYPE_UDP_DATA = 0x22
        const val TYPE_PROBE = 0x23
        // v0.8: обмен ключами протокола mtproto2 (после READY, внутри приватного хендшейка)
        const val TYPE_KEY_REQ = 0x24
        const val TYPE_KEY_RESP = 0x25
        // v0.8.2: кадр камуфляжа «API Mask» (модуль apimask, см. core/Apimask.kt)
        const val TYPE_NOISE = 0x26
        // v0.9.5: протокол wireguard — НАСТОЯЩИЕ WG-кадры (Noise_IKpsk2) внутри
        // приватного канала: WG_INIT (C→S, msg1 148 Б) → WG_RESP (S→C, msg2 92 Б);
        // после обмена payload'ы DATA/UDP_DATA — WG transport-пакеты (type=4).
        const val TYPE_WG_INIT = 0x27
        const val TYPE_WG_RESP = 0x28
        // v0.9.5: управление камуфляжем с клиента (персистентный выбор устройства)
        const val TYPE_CAM_CTL = 0x2A
        const val TYPE_ERROR = 0x7F

        const val MAX_DATA_PAYLOAD = 65535
        const val MAX_CONTROL_PAYLOAD = 4096

        fun maxPayloadFor(type: Int): Int = when (type) {
            TYPE_DATA, TYPE_UDP_DATA -> MAX_DATA_PAYLOAD
            TYPE_WG_INIT, TYPE_WG_RESP -> 256 // wg msg1=148 Б / msg2=92 Б (запас)
            else -> MAX_CONTROL_PAYLOAD
        }

        /** Парсинг кадра из потока: 12 байт заголовка + payload, с проверкой версии/лимитов. */
        fun parse(source: InputStream): RrpFrame {
            val header = ByteArray(HEADER_SIZE)
            readFully(source, header)
            val ver = header[0].toInt() and 0xFF
            if (ver != VERSION) throw RrpFrameException(Msgs.FRAME_VERSION.t(ver))
            val type = header[1].toInt() and 0xFF
            val flags = getU16(header, 2)
            val streamId = getU32(header, 4)
            val len = getU32(header, 8)
            val max = maxPayloadFor(type)
            if (len > max) {
                throw RrpFrameException(
                    Msgs.FRAME_PAYLOAD_LIMIT.t(len, max, Integer.toHexString(type))
                )
            }
            val payload = ByteArray(len.toInt())
            readFully(source, payload)
            return fromParts(type, flags, streamId, payload)
        }

        fun parse(bytes: ByteArray): RrpFrame = parse(ByteArrayInputStream(bytes))

        private fun fromParts(type: Int, flags: Int, streamId: Long, payload: ByteArray): RrpFrame =
            when (type) {
                TYPE_HELLO -> Hello.fromJson(payload)
                TYPE_HELLO_OK -> HelloOk.fromJson(payload)
                TYPE_AUTH -> Auth.fromJson(payload)
                TYPE_READY -> Ready.fromJson(payload)
                TYPE_OPEN -> Open.fromPayload(streamId, payload)
                TYPE_DATA -> Data(streamId, flags, payload)
                TYPE_CLOSE -> Close.fromPayload(streamId, payload)
                TYPE_WINDOW -> Window.fromPayload(streamId, payload)
                TYPE_OPEN_OK -> OpenOk.fromPayload(streamId, payload)
                TYPE_PING -> Ping.fromPayload(payload)
                TYPE_PONG -> Pong.fromPayload(payload)
                TYPE_UDP_ASSOC -> UdpAssoc(streamId)
                TYPE_UDP_DATA -> UdpData.fromPayload(streamId, payload)
                TYPE_PROBE -> ProbeResp.fromPayload(payload)
                TYPE_KEY_REQ -> KeyReq.fromPayload(payload)
                TYPE_KEY_RESP -> KeyResp.fromPayload(payload)
                TYPE_NOISE -> Noise.fromPayload(payload)
                TYPE_WG_INIT -> WgInit(payload)
                TYPE_WG_RESP -> WgResp(payload)
                TYPE_CAM_CTL -> CamCtl.fromPayload(payload)
                TYPE_STATS -> Stats.fromPayload(payload)
                TYPE_ERROR -> ErrorFrame.fromPayload(payload)
                else -> throw RrpFrameException(Msgs.UNKNOWN_FRAME.t(Integer.toHexString(type)))
            }

        private fun readFully(input: InputStream, buf: ByteArray) {
            var off = 0
            while (off < buf.size) {
                val n = input.read(buf, off, buf.size - off)
                if (n < 0) throw EOFException(Msgs.STREAM_TRUNCATED.t(buf.size - off))
                off += n
            }
        }
    }


}

/** Минимальный JSON-хелпер для JSON-payload кадров (плоские объекты). Pure Kotlin. */
internal object MiniJson {
    fun escape(s: String): String = buildString {
        for (c in s) when (c) {
            '"' -> append("\\\"")
            '\\' -> append("\\\\")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (c < ' ') append("\\u%04x".format(c.code)) else append(c)
        }
    }

    fun q(s: String): String = "\"" + escape(s) + "\""

    /** Значения передаются уже валидным JSON-текстом (строки — в кавычках). */
    fun obj(vararg fields: Pair<String, String>): String =
        fields.joinToString(",", "{", "}") { (k, v) -> q(k) + ":" + v }

    /** Плоский JSON-объект → Map: строки декодируются, числа/массивы — сырым текстом. */
    fun parseFlat(p: ByteArray): Map<String, String>? {
        val s = String(p, Charsets.UTF_8)
        val out = mutableMapOf<String, String>()
        var i = 0
        fun skipWs() {
            while (i < s.length && s[i].isWhitespace()) i++
        }
        fun readString(): String? {
            if (i >= s.length || s[i] != '"') return null
            i++
            val sb = StringBuilder()
            while (i < s.length) {
                val c = s[i++]
                when {
                    c == '"' -> return sb.toString()
                    c == '\\' -> {
                        if (i >= s.length) return null
                        when (val e = s[i++]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'u' -> {
                                if (i + 4 > s.length) return null
                                val v = s.substring(i, i + 4).toIntOrNull(16) ?: return null
                                sb.append(v.toChar())
                                i += 4
                            }
                            else -> return null
                        }
                    }
                    else -> sb.append(c)
                }
            }
            return null
        }
        skipWs()
        if (i >= s.length || s[i] != '{') return null
        i++
        while (true) {
            skipWs()
            if (i < s.length && s[i] == '}') { i++; break }
            val key = readString() ?: return null
            skipWs()
            if (i >= s.length || s[i] != ':') return null
            i++
            skipWs()
            when {
                i < s.length && s[i] == '"' -> {
                    val v = readString() ?: return null
                    out[key] = v
                }
                i < s.length && s[i] == '[' -> {
                    i++
                    val start = i
                    var depth = 1
                    while (i < s.length && depth > 0) {
                        when (s[i]) {
                            '[' -> depth++
                            ']' -> depth--
                        }
                        i++
                    }
                    if (depth != 0) return null
                    out[key] = s.substring(start, i - 1)
                }
                else -> {
                    val start = i
                    while (i < s.length && s[i] !in ",}") i++
                    out[key] = s.substring(start, i).trim()
                }
            }
            skipWs()
            if (i < s.length && s[i] == ',') { i++; continue }
            if (i < s.length && s[i] == '}') { i++; break }
            return null
        }
        return out
    }
}
