package dev.stelgen.reverseray.core

import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.crypto.tls.CipherSuite
import org.bouncycastle.crypto.tls.DefaultTlsClient
import org.bouncycastle.crypto.tls.ProtocolVersion
import org.bouncycastle.crypto.tls.TlsAuthentication
import org.bouncycastle.crypto.tls.TlsClientProtocol
import org.bouncycastle.crypto.tls.TlsServerCertificate
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * RRP/1 client session over BouncyCastle TLS (works from API 14),
 * CA SPKI-pin verified manually in the TLS authentication callback.
 * Pure Kotlin (no android.* imports) — unit-testable on JVM.
 */
class RrpClient(private val listener: Listener) {

    interface Listener {
        fun onState(state: State, info: String)
        /** Phone-side egress dial requested by the server. Return socket or null on failure. */
        fun onOpenRequest(host: String, port: Int): Socket?
    }

    enum class State { CONNECTING, HANDSHAKE, READY, CLOSED }

    private lateinit var profile: RrpUri.Profile

    private var socket: Socket? = null
    private var protocol: TlsClientProtocol? = null
    private val streamIdBase = AtomicLong(((0..0xFFFF).random()).toLong() + 1)
    private val pendingCloses = ConcurrentHashMap<Long, Boolean>()
    private val openSockets = ConcurrentHashMap<Long, Socket>()

    @Volatile private var running = false
    @Volatile var state: State = State.CLOSED
        private set

    fun configure(profile: RrpUri.Profile) {
        this.profile = profile
    }

    /** Server asks the phone to dial. Dispatched from the read loop. */
    fun handleOpen(frame: RrpFrame.Frame) {
        val payload = frame.payload
        if (payload.size < 4) return sendOpenError(frame.streamId, 1)
        val atyp = payload[0].toInt() and 0xFF
        val host = when (atyp) {
            RrpFrame.ATYP_DOMAIN -> String(payload, 2, (payload[1].toInt() and 0xFF))
            RrpFrame.ATYP_IPV4 -> payload.sliceArray(1..4)
                .joinToString(".") { (it.toInt() and 0xFF).toString() }
            RrpFrame.ATYP_IPV6 -> "[${
                java.net.Inet6Address.getByAddress(payload.copyOfRange(1, 17)).hostAddress
            }]"
            else -> return sendOpenError(frame.streamId, 1)
        }
        val port = ((payload[payload.size - 2].toInt() and 0xFF) shl 8) or
                (payload[payload.size - 1].toInt() and 0xFF)
        val code = when {
            SsrfGuard.isBlocked(host, profile.allowLan) -> 3 // SSRF refused
            else -> {
                val dst = listener.onOpenRequest(host, port)
                if (dst == null) 1 else {
                    openSockets[frame.streamId] = dst
                    0
                }
            }
        }
        RrpFrame.write(out(), RrpFrame.TYPE_OPEN_OK, 0, frame.streamId, byteArrayOf(code.toByte()))
    }

    private fun sendOpenError(id: Long, code: Int) {
        runCatching { RrpFrame.write(out(), RrpFrame.TYPE_OPEN_OK, 0, id, byteArrayOf(code.toByte())) }
    }

    fun connect(p: RrpUri.Profile) {
        configure(p)
        running = true
        Thread({
            var attempt = 1
            while (running) {
                try {
                    setState(State.CONNECTING, "attempt $attempt")
                    doConnect()
                    return@Thread
                } catch (e: Exception) {
                    setState(State.CLOSED, "retry: ${e.message}")
                    if (!running) return@Thread
                    val backoff = (minOf(60_000L, 1000L shl (attempt - 1).coerceAtMost(6)) *
                            (0.7 + Math.random() * 0.6)).toLong()
                    try { Thread.sleep(backoff) } catch (_: InterruptedException) { return@Thread }
                    attempt++
                }
            }
        }, "rrp-connect").apply { isDaemon = true }.start()
    }

    fun disconnect() {
        running = false
        runCatching { protocol?.close() }
        runCatching { socket?.close() }
        setState(State.CLOSED, "disconnected")
    }

    private fun setState(s: State, info: String) {
        state = s
        listener.onState(s, info)
    }

    private fun out(): OutputStream = protocol!!.outputStream
    private fun inp(): InputStream = protocol!!.inputStream

    @Throws(Exception::class)
    private fun doConnect() {
        val port = profile.ports.firstOrNull { p ->
            runCatching {
                Socket().use { it.connect(InetSocketAddress(profile.host, p), 5000); true }
            }.getOrDefault(false)
        } ?: profile.ports.first()

        val raw = Socket()
        raw.connect(InetSocketAddress(profile.host, port), 5000)
        raw.tcpNoDelay = true
        socket = raw

        val client = object : DefaultTlsClient() {
            override fun getMinimumVersion(): ProtocolVersion = ProtocolVersion.TLSv12

            override fun getCipherSuites(): IntArray = intArrayOf(
                CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_AES_256_GCM_SHA384
            )

            override fun getAuthentication(): TlsAuthentication {
                return object : TlsAuthentication {
                    override fun notifyServerCertificate(cert: TlsServerCertificate?) {
                        requireNotNull(cert) { "no server certificate" }
                        val chain = cert.certificate.certificateList
                        require(chain.isNotEmpty()) { "empty cert chain" }
                        // Pin the CA: server presents [leaf, CA].
                        val ca = chain[chain.size - 1]
                        val spkiDer = ca.subjectPublicKeyInfo.getEncoded(ASN1Encoding.DER)
                        val digest = MessageDigest.getInstance("SHA-256").digest(spkiDer)
                        val pin = Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
                        if (profile.pin.isNotEmpty() && pin != profile.pin) {
                            throw IllegalStateException("CA pin mismatch")
                        }
                    }
                }
            }
        }

        val proto = TlsClientProtocol(raw.getInputStream(), raw.getOutputStream(), SecureRandom())
        protocol = proto
        setState(State.HANDSHAKE, "tls handshake")
        proto.connect(client)

        val hello = "{\"agent\":\"reverseray-android\",\"ver\":\"0.1.0\"," +
                "\"device\":\"${jsonEscape(profile.name)}\",\"max_streams\":64}"
        RrpFrame.write(out(), RrpFrame.TYPE_HELLO, 0, 0, hello.toByteArray())
        val hok = RrpFrame.read(inp())
        check(hok.type == RrpFrame.TYPE_HELLO_OK) { "expected HELLO_OK, got ${hok.type}" }
        val (sid, nonce) = parseHelloOk(hok.payload)
        val hmac = authCode(profile.token, nonce, sid)
        RrpFrame.write(
            out(), RrpFrame.TYPE_AUTH, 0, 0,
            "{\"mode\":\"token-hmac\",\"hmac\":\"$hmac\"}".toByteArray()
        )
        val ready = RrpFrame.read(inp())
        if (ready.type == RrpFrame.TYPE_ERROR) throw IOException("auth rejected")
        check(ready.type == RrpFrame.TYPE_READY) { "expected READY, got ${ready.type}" }
        setState(State.READY, "session $sid")
        readLoop()
    }

    private fun readLoop() {
        while (running) {
            val f = try {
                RrpFrame.read(inp())
            } catch (e: Exception) {
                if (running) setState(State.CLOSED, "transport: ${e.message}")
                return
            }
            when (f.type) {
                RrpFrame.TYPE_OPEN -> handleOpen(f)
                RrpFrame.TYPE_CLOSE -> {
                    openSockets.remove(f.streamId)?.close()
                    pendingCloses.remove(f.streamId)
                }
                RrpFrame.TYPE_PING ->
                    runCatching { RrpFrame.write(out(), RrpFrame.TYPE_PONG, 0, 0, f.payload) }
            }
        }
    }

    private fun parseHelloOk(payload: ByteArray): Pair<String, String> {
        val json = String(payload)
        val sid = Regex("\"session_id\"\\s*:\\s*\"([^\"]+)\"").find(json)?.groupValues?.get(1) ?: ""
        val nonce = Regex("\"nonce\"\\s*:\\s*\"([^\"]+)\"").find(json)?.groupValues?.get(1) ?: ""
        return sid to nonce
    }

    private fun authCode(token: String, nonceB64: String, sessionId: String): String {
        val nonce = Base64.getUrlDecoder().decode(nonceB64)
        val key = MessageDigest.getInstance("SHA-256").digest(token.toByteArray())
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        mac.update(nonce)
        mac.update(sessionId.toByteArray())
        return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal())
    }

    private fun jsonEscape(s: String): String =
        s.replace("\\", "\\\\").replace("\"", "\\\"")
}
