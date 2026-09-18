package dev.stelgen.reverseray.core

import java.io.IOException
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.Random
import java.util.Vector
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.tls.AlertDescription
import org.bouncycastle.tls.CertificateRequest
import org.bouncycastle.tls.CipherSuite
import org.bouncycastle.tls.DefaultTlsClient
import org.bouncycastle.tls.ProtocolName
import org.bouncycastle.tls.ProtocolVersion
import org.bouncycastle.tls.TlsAuthentication
import org.bouncycastle.tls.TlsClientProtocol
import org.bouncycastle.tls.TlsCredentials
import org.bouncycastle.tls.TlsFatalAlert
import org.bouncycastle.tls.TlsServerCertificate
import org.bouncycastle.tls.crypto.TlsCrypto
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider

/** Ошибка клиента RRP (TCP/TLS/handshake/соединение). */
class RrpClientException(message: String, cause: Throwable? = null) : IOException(message, cause)

/**
 * Клиент RRP/1-туннеля. Pure Kotlin (без android.*).
 *
 * TLS 1.3 через BouncyCastle (bctls 1.80, пост-миграция на TlsCrypto-API):
 * - SPKI-pin: sha256(SPKI leaf-сертификата), сверка вручную в notifyServerCertificate;
 * - ALPN "reverseray/1" через getProtocolNames()/ProtocolName (BC 1.80);
 * - Chacha20 в приоритете cipher-suite;
 * - провайдер BC задаётся явно (на Android платформенный "BC" — урезанный).
 *
 * Жизненный цикл: connect() → HELLO → HELLO_OK → AUTH → READY → рабочий режим
 * (один reader-поток обрабатывает все входящие кадры).
 * Переподключением управляет владелец (TunnelService) через backoffDelayMs();
 * экземпляр одноразовый — после close() создаётся новый.
 *
 * OPEN: по спецификации кадр ходит S→C (сервер просит телефон диалить цель) —
 * входящий OPEN обрабатывается с локальным диаллом и relay'ем DATA. Метод sendOpen()
 * оставлен по ТЗ для исходящего OPEN (клиент инициирует и ждёт OPEN_OK).
 */
class RrpClient(
    private val host: String,
    private val port: Int,
    private val token: String,
    private val pin: String? = null,
    private val agentName: String = DEFAULT_AGENT,
    private val allowLan: Boolean = false,
    private val listener: Listener? = null,
) {

    interface Listener {
        fun onState(client: RrpClient, state: State) {}
        fun onLog(client: RrpClient, message: String) {}
    }

    enum class State { DISCONNECTED, CONNECTING, HANDSHAKE, READY, CLOSED }

    class Stream internal constructor(
        val id: Long,
        val socket: Socket,
        /** flow-control: окно на стрим, байты. */
        val sendWindow: Semaphore,
    ) {
        val closed = AtomicBoolean(false)
        var remoteConsumed = 0
    }

    private val rnd = SecureRandom()
    private val running = AtomicBoolean(false)
    private val sendLock = Any()

    @Volatile private var socket: Socket? = null
    @Volatile private var tls: TlsClientProtocol? = null

    @Volatile var state: State = State.DISCONNECTED
        private set

    @Volatile var sessionId: String? = null
        private set

    @Volatile var tunnelWindow: Long = DEFAULT_TUNNEL_WINDOW
        private set

    @Volatile var maxStreams: Int = MAX_STREAMS_REQUEST
        private set

    private val helloLatch = CountDownLatch(1)
    private val readyLatch = CountDownLatch(1)
    @Volatile private var helloOkFrame: RrpFrame.HelloOk? = null
    @Volatile private var readyFrame: RrpFrame.Ready? = null
    @Volatile private var handshakeError: IOException? = null

    private val pendingOpens = ConcurrentHashMap<Long, CompletableFuture<Int>>()
    private val streams = ConcurrentHashMap<Long, Stream>()
    private val nextStreamId = AtomicLong(1)
    private val lastPongMs = AtomicLong(0)

    private val pingExecutor: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "rrp-ping").apply { isDaemon = true } }
    private val relayExecutor: ExecutorService =
        Executors.newCachedThreadPool { r -> Thread(r, "rrp-relay").apply { isDaemon = true } }

    // ------------------------------------------------------------------ connect

    @Throws(IOException::class)
    fun connect() {
        check(state == State.DISCONNECTED || state == State.CLOSED) { "клиент уже активен: $state" }
        setState(State.CONNECTING)

        val sock = Socket()
        try {
            sock.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
            sock.tcpNoDelay = true
        } catch (e: IOException) {
            closeQuietly(sock)
            setState(State.CLOSED)
            throw RrpClientException("TCP $host:$port: ${e.message}", e)
        }
        socket = sock

        val protocol = TlsClientProtocol(sock.getInputStream(), sock.getOutputStream())
        tls = protocol
        try {
            sock.soTimeout = TLS_HANDSHAKE_TIMEOUT_MS
            protocol.connect(buildTlsClient())
            sock.soTimeout = 0
        } catch (e: IOException) {
            close()
            throw RrpClientException("TLS $host:$port: ${e.message}", e)
        }

        running.set(true)
        setState(State.HANDSHAKE)
        Thread({ readerLoop() }, "rrp-reader-$port").apply { isDaemon = true }.start()

        sendFrame(RrpFrame.Hello(agentName, RrpFrame.VERSION, listOf("chacha20", "alpn"), MAX_STREAMS_REQUEST))
        try {
            if (!helloLatch.await(HANDSHAKE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                throw RrpClientException("таймаут HELLO_OK ($host:$port)")
            }
            handshakeError?.let { throw it }
            val ok = helloOkFrame ?: throw RrpClientException("HELLO_OK без данных")
            sessionId = ok.sessionId
            if (ok.tunnelWindow > 0) tunnelWindow = ok.tunnelWindow

            // AUTH: hmac = base64(HMAC-SHA256(token, nonce || session_id))
            val nonce = ByteArray(NONCE_SIZE).also { rnd.nextBytes(it) }
            val macInput = nonce + ok.sessionId.toByteArray(Charsets.UTF_8)
            val hmac = Base64.getEncoder()
                .encodeToString(hmacSha256(token.toByteArray(Charsets.UTF_8), macInput))
            sendFrame(
                RrpFrame.Auth(MODE_TOKEN_HMAC, hmac, Base64.getEncoder().encodeToString(nonce))
            )

            if (!readyLatch.await(HANDSHAKE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                throw RrpClientException("таймаут READY ($host:$port)")
            }
            handshakeError?.let { throw it }
            val rd = readyFrame ?: throw RrpClientException("READY без данных")
            if (rd.tunnelWindow > 0) tunnelWindow = rd.tunnelWindow
            if (rd.maxStreams > 0) maxStreams = rd.maxStreams

            setState(State.READY)
            lastPongMs.set(System.currentTimeMillis())
            scheduleNextPing()
            log("READY tunnel=${rd.tunnelId} role=${rd.role} window=$tunnelWindow maxStreams=$maxStreams")
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            close()
            throw RrpClientException("рукопожатие прервано", e)
        } catch (e: IOException) {
            close()
            throw e
        }
    }

    // ------------------------------------------------------------------ reader

    private fun readerLoop() {
        try {
            val proto = tls ?: throw RrpClientException("TLS не инициализирован")
            while (running.get()) {
                dispatch(RrpFrame.parse(proto.getInputStream()))
            }
        } catch (e: Throwable) {
            if (state != State.READY && handshakeError == null) {
                handshakeError = RrpClientException("рукопожатие не завершено: ${e.message}", e)
            } else if (running.get()) {
                log("reader остановлен: ${e.message}")
            }
        } finally {
            helloLatch.countDown()
            readyLatch.countDown()
            close()
        }
    }

    private fun dispatch(frame: RrpFrame) {
        when (frame) {
            is RrpFrame.HelloOk -> {
                helloOkFrame = frame
                helloLatch.countDown()
            }
            is RrpFrame.Ready -> {
                readyFrame = frame
                readyLatch.countDown()
            }
            is RrpFrame.Auth -> log("AUTH от сервера не ожидается")
            is RrpFrame.Hello -> log("HELLO от сервера не ожидается")
            is RrpFrame.Open -> handleIncomingOpen(frame)
            is RrpFrame.OpenOk -> pendingOpens.remove(frame.streamId)?.complete(frame.errCode)
            is RrpFrame.Data -> handleData(frame)
            is RrpFrame.Close -> closeStream(frame.streamId, notify = false)
            is RrpFrame.Window -> streams[frame.streamId]?.sendWindow
                ?.release(frame.increment.coerceAtMost(Int.MAX_VALUE.toLong()).toInt())
            is RrpFrame.Ping -> sendFrameQuiet(RrpFrame.Pong(frame.nonce))
            is RrpFrame.Pong -> lastPongMs.set(System.currentTimeMillis())
            is RrpFrame.Stats -> log("STATS: ${frame.json}")
            is RrpFrame.ErrorFrame -> {
                log("сервер ERROR ${frame.code}: ${frame.message}")
                for (id in pendingOpens.keys) {
                    pendingOpens.remove(id)?.complete(ERR_PROTOCOL)
                }
                if (state != State.READY && handshakeError == null) {
                    handshakeError =
                        RrpClientException("сервер вернул ERROR ${frame.code}: ${frame.message}")
                    helloLatch.countDown()
                    readyLatch.countDown()
                }
            }
        }
    }

    // ------------------------------------------------------------------ OPEN

    /**
     * Исходящий OPEN (по ТЗ): отправить кадр и дождаться OPEN_OK.
     * Возвращает err_code (ERR_OK = 0); без отправки — ERR_NOT_READY /
     * ERR_SSRF_BLOCKED / ERR_BAD_ADDRESS. Отменяется таймаутом OPEN_TIMEOUT_MS → ERR_TIMEOUT.
     */
    fun sendOpen(addr: String, port: Int): CompletableFuture<Int> {
        val future = CompletableFuture<Int>()
        if (state != State.READY) {
            future.complete(ERR_NOT_READY)
            return future
        }
        if (SsrfGuard.isBlocked(addr, allowLan)) {
            log("sendOpen: $addr заблокирован SSRF-guard")
            future.complete(ERR_SSRF_BLOCKED)
            return future
        }
        val encoded = try {
            RrpAddress.encodeAddr(addr)
        } catch (e: Exception) {
            future.complete(ERR_BAD_ADDRESS)
            return future
        }
        val streamId = nextStreamId.getAndIncrement().toLong() and 0xFFFFFFFFL
        pendingOpens[streamId] = future
        try {
            sendFrame(RrpFrame.Open(streamId, encoded.atyp, encoded.bytes, port))
        } catch (e: IOException) {
            pendingOpens.remove(streamId)
            future.completeExceptionally(e)
            return future
        }
        try {
            pingExecutor.schedule({
                pendingOpens.remove(streamId)?.complete(ERR_TIMEOUT)
            }, OPEN_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        } catch (_: RejectedExecutionException) {
            // клиент уже закрыт — future завершён в close()
        }
        return future
    }

    /** S→C OPEN: сервер просит телефон диалить цель. Ответ — OPEN_OK c err_code. */
    private fun handleIncomingOpen(frame: RrpFrame.Open) {
        val streamId = frame.streamId
        val targetHost = try {
            RrpAddress.decodeAddr(frame.atyp, frame.addr)
        } catch (e: Exception) {
            sendOpenOk(streamId, ERR_BAD_ADDRESS)
            return
        }
        if (SsrfGuard.isBlocked(targetHost, allowLan)) {
            log("OPEN $targetHost:${frame.port} заблокирован SSRF-guard")
            sendOpenOk(streamId, ERR_SSRF_BLOCKED)
            return
        }
        if (streams.size >= maxStreams) {
            sendOpenOk(streamId, ERR_TOO_MANY_STREAMS)
            return
        }
        try {
            relayExecutor.execute {
                var sock: Socket? = null
                try {
                    val s = Socket()
                    s.connect(InetSocketAddress(targetHost, frame.port), CONNECT_TIMEOUT_MS)
                    s.tcpNoDelay = true
                    sock = s
                    val st = registerStream(streamId, s)
                    sendOpenOk(streamId, ERR_OK)
                    pumpOutgoing(st) // цель → DATA → сервер; блокируется до закрытия стрима
                } catch (e: Exception) {
                    closeQuietly(sock)
                    sendOpenOk(streamId, ERR_CONNECT_FAILED)
                }
            }
        } catch (_: RejectedExecutionException) {
            sendOpenOk(streamId, ERR_GENERAL)
        }
    }

    private fun registerStream(id: Long, sock: Socket): Stream {
        val window = tunnelWindow.coerceIn(1, Int.MAX_VALUE.toLong()).toInt()
        val st = Stream(id, sock, Semaphore(window))
        streams[id] = st
        return st
    }

    /** Поток: сокет цели → DATA кадры (с учётом окна flow-control). */
    private fun pumpOutgoing(st: Stream) {
        val buf = ByteArray(16 * 1024)
        try {
            val input = st.socket.getInputStream()
            while (running.get() && !st.closed.get()) {
                val n = input.read(buf)
                if (n < 0) break
                if (n == 0) continue
                st.sendWindow.acquire(n) // семафор окна 512 КБ на стрим
                sendFrame(RrpFrame.Data(st.id, 0, buf.copyOf(n)))
            }
            if (!st.closed.get()) sendFrameQuiet(RrpFrame.Close(st.id, ERR_OK))
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        } catch (e: Exception) {
            sendFrameQuiet(RrpFrame.Close(st.id, ERR_GENERAL))
        } finally {
            closeStreamInternal(st)
        }
    }

    // ------------------------------------------------------------------ DATA / WINDOW

    private fun handleData(frame: RrpFrame.Data) {
        val st = streams[frame.streamId]
        if (st == null) {
            sendFrameQuiet(RrpFrame.Close(frame.streamId, ERR_NO_STREAM))
            return
        }
        try {
            val out = st.socket.getOutputStream()
            out.write(frame.bytes)
            out.flush()
            val consumed = st.remoteConsumed + frame.bytes.size
            val threshold = (tunnelWindow / 2).coerceIn(1, Int.MAX_VALUE.toLong()).toInt()
            if (consumed >= threshold) {
                st.remoteConsumed = 0
                sendFrameQuiet(RrpFrame.Window(st.id, consumed.toLong()))
            } else {
                st.remoteConsumed = consumed
            }
        } catch (e: IOException) {
            closeStream(frame.streamId, notify = true)
        }
    }

    private fun closeStream(id: Long, errCode: Int = ERR_GENERAL, notify: Boolean) {
        val st = streams.remove(id) ?: return
        st.closed.set(true)
        closeQuietly(st.socket)
        if (notify) sendFrameQuiet(RrpFrame.Close(id, errCode))
    }

    private fun closeStreamInternal(st: Stream) {
        streams.remove(st.id)?.let {
            it.closed.set(true)
            closeQuietly(it.socket)
        }
    }

    private fun sendOpenOk(streamId: Long, errCode: Int) {
        sendFrameQuiet(RrpFrame.OpenOk(streamId, errCode))
    }

    // ------------------------------------------------------------------ PING

    private fun scheduleNextPing() {
        if (!running.get()) return
        try {
            pingExecutor.schedule({
                if (!running.get()) return@schedule
                try {
                    sendFrame(RrpFrame.Ping(ByteArray(NONCE_SIZE).also { rnd.nextBytes(it) }))
                } catch (e: IOException) {
                    log("ping не отправлен: ${e.message}")
                }
                scheduleNextPing()
            }, pingIntervalMs(rnd), TimeUnit.MILLISECONDS)
        } catch (_: RejectedExecutionException) {
        }
    }

    // ------------------------------------------------------------------ frame IO

    private fun sendFrame(frame: RrpFrame) {
        val proto = tls ?: throw RrpClientException("нет TLS-соединения")
        synchronized(sendLock) {
            val out: OutputStream = proto.getOutputStream()
            out.write(frame.encode())
            out.flush()
        }
    }

    private fun sendFrameQuiet(frame: RrpFrame) {
        try {
            sendFrame(frame)
        } catch (e: Exception) {
            log("send не удался: ${e.message}")
        }
    }

    // ------------------------------------------------------------------ close

    fun close() {
        running.set(false)
        setState(State.CLOSED)
        helloLatch.countDown()
        readyLatch.countDown()
        try { pingExecutor.shutdownNow() } catch (_: Exception) {}
        try { relayExecutor.shutdownNow() } catch (_: Exception) {}
        streams.values.forEach {
            it.closed.set(true)
            closeQuietly(it.socket)
        }
        streams.clear()
        pendingOpens.values.forEach { it.complete(ERR_CONNECTION_CLOSED) }
        pendingOpens.clear()
        try { tls?.close() } catch (_: Exception) {}
        closeQuietly(socket)
        tls = null
        socket = null
    }

    // ------------------------------------------------------------------ misc

    private fun setState(s: State) {
        state = s
        listener?.onState(this, s)
    }

    private fun log(message: String) {
        listener?.onLog(this, message)
    }

    private fun closeQuietly(c: Socket?) {
        try { c?.close() } catch (_: Exception) {}
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    // ------------------------------------------------------------------ TLS (BC 1.80)

    private fun buildTlsClient(): DefaultTlsClient {
        val crypto: TlsCrypto = JcaTlsCryptoProvider()
            .setProvider(BouncyCastleProvider())
            .create(SecureRandom())
        return object : DefaultTlsClient(crypto) {
            override fun getProtocolVersions(): Array<ProtocolVersion> =
                arrayOf(ProtocolVersion.TLSv13, ProtocolVersion.TLSv12)

            // Chacha20 в приоритете, далее AES-GCM
            override fun getCipherSuites(): IntArray = intArrayOf(
                CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            )

            // ALPN: BC 1.80 — клиент предлагает имена через getProtocolNames()
            override fun getProtocolNames(): Vector<ProtocolName> =
                Vector(listOf(ProtocolName.asUtf8Encoding(ALPN_PROTOCOL)))

            override fun getAuthentication(): TlsAuthentication = object : TlsAuthentication {
                override fun notifyServerCertificate(serverCertificate: TlsServerCertificate) {
                    // SPKI-pin: sha256(SPKI leaf-сертификата), сверка вручную
                    val expected = decodePin(
                        pin ?: throw TlsFatalAlert(AlertDescription.bad_certificate)
                    )
                    val chain = serverCertificate.certificate.certificateList
                    if (chain.isEmpty()) throw TlsFatalAlert(AlertDescription.bad_certificate)
                    val leafDer = chain[0].encoded // TlsCertificate.getEncoded(): полный DER
                    val cert = org.bouncycastle.asn1.x509.Certificate.getInstance(leafDer)
                    val spkiDer = cert.subjectPublicKeyInfo.encoded
                    val actual = MessageDigest.getInstance("SHA-256").digest(spkiDer)
                    if (!MessageDigest.isEqual(actual, expected)) {
                        throw TlsFatalAlert(AlertDescription.bad_certificate)
                    }
                }

                override fun getClientCredentials(certificateRequest: CertificateRequest): TlsCredentials? =
                    null
            }
        }
    }

    /** pin — hex (64 симв.) или base64 (32 байта) sha256 от SPKI. */
    private fun decodePin(raw: String): ByteArray {
        val p = raw.trim()
        val bytes: ByteArray? = when {
            p.matches(Regex("^[0-9a-fA-F]{64}$")) ->
                ByteArray(32) { i -> p.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
            else -> try {
                Base64.getDecoder().decode(p)
            } catch (e: IllegalArgumentException) {
                try {
                    Base64.getUrlDecoder().decode(p)
                } catch (e2: IllegalArgumentException) {
                    null
                }
            }
        }
        if (bytes == null || bytes.size != 32) {
            throw RrpClientException("pin: ожидался sha256 (32 байта, hex/base64)")
        }
        return bytes
    }

    companion object {
        const val DEFAULT_AGENT = "ReverseRay-Android/0.1.0"
        const val ALPN_PROTOCOL = "reverseray/1"
        const val MODE_TOKEN_HMAC = "token-hmac"

        const val CONNECT_TIMEOUT_MS = 10_000
        const val TLS_HANDSHAKE_TIMEOUT_MS = 15_000
        const val HANDSHAKE_TIMEOUT_MS = 20_000L
        const val OPEN_TIMEOUT_MS = 30_000L
        const val NONCE_SIZE = 8
        const val MAX_STREAMS_REQUEST = 64

        /** Окно flow-control по умолчанию: 512 КБ на стрим. */
        const val DEFAULT_TUNNEL_WINDOW = 512 * 1024L

        // err_code для OPEN/OPEN_OK и sendOpen()
        const val ERR_OK = 0
        const val ERR_GENERAL = 1
        const val ERR_SSRF_BLOCKED = 2
        const val ERR_BAD_ADDRESS = 3
        const val ERR_CONNECT_FAILED = 4
        const val ERR_TIMEOUT = 5
        const val ERR_NOT_READY = 6
        const val ERR_NO_STREAM = 7
        const val ERR_TOO_MANY_STREAMS = 8
        const val ERR_PROTOCOL = 9
        const val ERR_CONNECTION_CLOSED = 10

        private const val PING_INTERVAL_MS = 60_000L

        /** Интервал PING: 60 с ±10 % джиттера. */
        fun pingIntervalMs(rnd: Random): Long {
            val jitter = PING_INTERVAL_MS / 10
            return PING_INTERVAL_MS - jitter + rnd.nextInt((2 * jitter + 1).toInt())
        }

        /** Экспоненциальный backoff переподключения 1→60 с ±30 % джиттера; attempt — 0-based. */
        fun backoffDelayMs(attempt: Int, rnd: Random): Long {
            val sec = (1L shl attempt.coerceIn(0, 6)).coerceAtMost(60L)
            val base = sec * 1000L
            val jitter = base * 3L / 10L
            return base - jitter + rnd.nextInt((2 * jitter + 1).toInt())
        }
    }
}
