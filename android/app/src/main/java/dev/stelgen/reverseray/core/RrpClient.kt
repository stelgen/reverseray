package dev.stelgen.reverseray.core

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Security
import java.util.Base64
import java.util.Random
import java.util.Vector
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
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto

/** Ошибка клиента RRP (TCP/TLS/handshake/соединение). */
class RrpClientException(message: String, cause: Throwable? = null) : IOException(message, cause)

/** Минимальная future для err_code OPEN: CompletableFuture недоступен на API < 24 (minSdk 14). */
class OpenFuture {
    private val latch = java.util.concurrent.CountDownLatch(1)
    @Volatile private var code: Int = RrpClient.ERR_GENERAL

    internal fun complete(errCode: Int) {
        code = errCode
        latch.countDown()
    }

    /** Блокирующе ждёт результата. return err_code (0 = OK). */
    fun get(): Int {
        latch.await()
        return code
    }

    /** Блокирующе ждёт с таймаутом; по таймауту возвращает ERR_TIMEOUT. */
    fun get(timeoutMs: Long): Int {
        latch.await(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)
        return code
    }
}

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
    val host: String,
    val port: Int,
    private val token: String,
    private val pin: String? = null,
    private val agentName: String = DEFAULT_AGENT,
    private val allowLan: Boolean = false,
    private val listener: Listener? = null,
    /** Имя устройства (поле device в HELLO; сервер требует непустое ≤64). */
    private val deviceName: String = "phone-1",
    /** Желаемый протокол (&proto= из ссылки; мусор сводится к дефолту). */
    private val protoId: String = RrpProtocols.DEFAULT,
    /** v0.7.4: цель валидационного PROBE после READY ("host:port").
     *  null — не проверять. Это «реальный трафик до реального хоста»:
     *  сервер диалит цель с егресса и отвечает фактом установки TCP. */
    private val validateProbeTarget: String? = null,
    /** Транспорт: "tcp" (сырой RRP/1) или "ws" (WebSocket-апгрейд /rrp). */
    private val transport: String = TRANSPORT_TCP,
    /**
     * v0.7.2 TOFU: доверять самоподписанным сертификатам сервера, даже если
     * CA-pin из конфига не совпал (сервер перегенерировал CA). Пин остаётся
     * мягкой проверкой: совпал — строгий режим; не совпал — принимаем валидную
     * self-signed цепочку и сообщаем новый пин через Listener.onPinAccepted.
     * false — строгий режим (для тестов evil-server и параноидальных юзеров).
     */
    val trustSelfSigned: Boolean = true,
) {

    interface Listener {
        fun onState(client: RrpClient, state: State) {}
        fun onLog(client: RrpClient, message: String) {}
        /** TOFU: пин из конфига не совпал, принят самоподписанный сервер. */
        fun onPinAccepted(client: RrpClient, newPin: String) {}
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

    /** Ввод/вывод поверх TLS: сырой поток или WebSocket-обёртка. */
    @Volatile private var wireIn: InputStream? = null
    @Volatile private var wireOut: OutputStream? = null
    @Volatile private var wireWs: WsStream? = null

    /** Счётчики трафика (байты payload'ов DATA/UDP_DATA) для графика в UI. */
    private val txBytes = AtomicLong(0)
    private val rxBytes = AtomicLong(0)

    /** v0.7.4: счётчики ПАКЕТОВ (кадров DATA/UDP_DATA) и последний размер —
     *  для строки «стрелки» на главном экране (тип, размер, пакеты туда/сюда). */
    private val packetsTx = AtomicLong(0)
    private val packetsRx = AtomicLong(0)
    private val lastPacketTxSize = AtomicLong(0)
    private val lastPacketRxSize = AtomicLong(0)

    /** Тип последнего пакета: "TCP" (DATA) или "UDP" (UDP_DATA). */
    @Volatile var lastPacketKind: String = ""
        private set

    /** [txCount, rxCount, lastTxSize, lastRxSize] — снимок для UI. */
    fun packetsSnapshot(): LongArray = longArrayOf(
        packetsTx.get(), packetsRx.get(),
        lastPacketTxSize.get(), lastPacketRxSize.get(),
    )

    /** Фактически принятый SPKI-пин сервера (заполняется в TOFU-режиме). */
    @Volatile var acceptedPin: String? = null
        private set

    /** UDP-ассоциации: stream_id → локальный relay (DatagramSocket). */
    private val udpAssocs = ConcurrentHashMap<Long, UdpAssoc>()

    @Volatile var state: State = State.DISCONNECTED
        private set

    @Volatile var sessionId: String? = null
        private set

    /** Протокол, выбранный сервером в этой сессии (канон после READY). */
    @Volatile var negotiatedProto: String = RrpProtocols.DEFAULT
        private set

    /** Реестр протоколов, присланный сервером (для UI-переключателя). */
    @Volatile var serverProtocols: List<String> = emptyList()
        private set

    @Volatile private var probeResp: RrpFrame.ProbeResp? = null

    @Volatile var tunnelWindow: Long = DEFAULT_TUNNEL_WINDOW
        private set

    @Volatile var maxStreams: Int = MAX_STREAMS_REQUEST
        private set

    private val helloLatch = CountDownLatch(1)
    private val readyLatch = CountDownLatch(1)
    @Volatile private var helloOkFrame: RrpFrame.HelloOk? = null
    @Volatile private var readyFrame: RrpFrame.Ready? = null
    @Volatile private var handshakeError: IOException? = null

    private val pendingOpens = ConcurrentHashMap<Long, OpenFuture>()
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

        // Транспорт поверх TLS (v0.7): ws → HTTP-апгрейд /rrp; tcp → сырые кадры.
        if (transport.equals(TRANSPORT_WS, ignoreCase = true)) {
            try {
                sock.soTimeout = WS_HANDSHAKE_TIMEOUT_MS
                val ws = WsStream(protocol.inputStream, protocol.outputStream, host, port)
                ws.handshake()
                sock.soTimeout = 0
                wireWs = ws
                wireIn = ws
                wireOut = WsOutput(ws)
            } catch (e: IOException) {
                close()
                throw RrpClientException("WebSocket $host:$port: ${e.message}", e)
            }
        } else {
            wireIn = protocol.inputStream
            wireOut = protocol.outputStream
        }

        running.set(true)
        setState(State.HANDSHAKE)
        Thread({ readerLoop() }, "rrp-reader-$port").apply { isDaemon = true }.start()

        val hello = RrpFrame.Hello(
            agent = agentName,
            protocolVersion = RrpFrame.VERSION,
            device = deviceName,
            caps = listOf("chacha20", "alpn"),
            maxStreams = MAX_STREAMS_REQUEST,
            proto = RrpProtocols.normalize(protoId),
            protocols = RrpProtocols.displayList(),
        )
        log("SENT HELLO agent=$agentName device=$deviceName ver=${RrpFrame.VERSION} caps=[chacha20,alpn] proto=${RrpProtocols.normalize(protoId)} max_streams=$MAX_STREAMS_REQUEST (${hello.encode().size}Б)")
        sendFrame(hello)
        try {
            if (!helloLatch.await(HANDSHAKE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                throw RrpClientException("таймаут HELLO_OK ($host:$port)")
            }
            handshakeError?.let { throw it }
            val ok = helloOkFrame ?: throw RrpClientException("HELLO_OK без данных")
            sessionId = ok.sessionId
            if (ok.tunnelWindow > 0) tunnelWindow = ok.tunnelWindow

            // v0.7.3 ФИКСЫ: (1) nonce — СЕРВЕРНЫЙ из HELLO_OK (клиент раньше
            // генерировал свой — сервер сверяет HMAC со своим); (2) ключ HMAC =
            // SHA256(token), не сырой токен (иначе auth всегда падает).
            log("RECV HELLO_OK session=${ok.sessionId} server_ver=${ok.serverVer} nonce=${ok.nonce.ifEmpty { "<НЕТ>" }} window=${ok.tunnelWindow}")
            if (ok.nonce.isEmpty()) {
                throw RrpClientException("HELLO_OK без nonce (сервер не прислал одноразовый nonce)")
            }
            val nonceBytes = try {
                Base64.getUrlDecoder().decode(ok.nonce)
            } catch (e: IllegalArgumentException) {
                try { Base64.getDecoder().decode(ok.nonce) } catch (e2: IllegalArgumentException) { null }
            } ?: throw RrpClientException("HELLO_OK: nonce не base64 (${ok.nonce.take(32)})")
            val macInput = nonceBytes + ok.sessionId.toByteArray(Charsets.UTF_8)
            val hmacKey = MessageDigest.getInstance("SHA-256").digest(token.toByteArray(Charsets.UTF_8))
            // v0.7.4 ФИКС: HMAC — base64url БЕЗ паддинга (RawURLEncoding на сервере).
            // APK 0.7.3 кодировал стандартным base64 (с «+ /» и «=») — сервер
            // не мог декодировать и отвечал «ERROR 1: auth failed».
            val hmac = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(hmacSha256(hmacKey, macInput))
            log("SENT AUTH mode=$MODE_TOKEN_HMAC nonce=${ok.nonce} hmac=${hmac.take(12)}… sessionId=$sessionId")
            sendFrame(
                RrpFrame.Auth(MODE_TOKEN_HMAC, hmac, ok.nonce)
            )

            if (!readyLatch.await(HANDSHAKE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                throw RrpClientException("таймаут READY ($host:$port)")
            }
            handshakeError?.let { throw it }
            val rd = readyFrame ?: throw RrpClientException("READY без данных")
            if (rd.tunnelWindow > 0) tunnelWindow = rd.tunnelWindow
            if (rd.maxStreams > 0) maxStreams = rd.maxStreams
            negotiatedProto = RrpProtocols.normalize(rd.proto)
            RrpProtocols.rememberServerProtocols(rd.protocols)
            serverProtocols = rd.protocols

            setState(State.READY)
            lastPongMs.set(System.currentTimeMillis())
            scheduleNextPing()
            log("RECV READY tunnel=${rd.tunnelId} role=${rd.role} proto=${rd.proto} protocols=${rd.protocols} maxStreams=${rd.maxStreams} window=${rd.tunnelWindow} → State.READY")

            // v0.7.4: валидация «реального трафика» — PROBE до реального хоста.
            // Используется при смене протокола: коммит только после успеха.
            validateProbeTarget?.let { target ->
                log("PROBE → $target (валидация протокола ${rd.proto})")
                val pr = probeOnce(target, PROBE_TIMEOUT_MS)
                if (pr == null) {
                    throw RrpClientException("PROBE не отвечен сервером (валидация не пройдена)")
                }
                if (!pr.ok) {
                    throw RrpClientException("валидация не пройдена: ${pr.err.ifEmpty { "нет egress" }}")
                }
                log("PROBE OK — egress до $target подтверждён")
            }
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
            val input = wireIn ?: throw RrpClientException("транспорт не инициализирован")
            while (running.get()) {
                dispatch(RrpFrame.parse(input))
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
                RrpProtocols.rememberServerProtocols(frame.protocols)
                serverProtocols = frame.protocols
                negotiatedProto = RrpProtocols.normalize(frame.proto)
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
            is RrpFrame.Data -> {
                rxBytes.addAndGet(frame.bytes.size.toLong())
                packetsRx.incrementAndGet()
                lastPacketRxSize.set(frame.bytes.size.toLong())
                lastPacketKind = KIND_TCP
                handleData(frame)
            }
            is RrpFrame.UdpAssoc -> handleIncomingUdpAssoc(frame)
            is RrpFrame.UdpData -> {
                rxBytes.addAndGet(frame.bytes.size.toLong())
                packetsRx.incrementAndGet()
                lastPacketRxSize.set(frame.bytes.size.toLong())
                lastPacketKind = KIND_UDP
                handleUdpData(frame)
            }
            is RrpFrame.Close -> closeStream(frame.streamId, notify = false)
            is RrpFrame.Window -> streams[frame.streamId]?.sendWindow
                ?.release(frame.increment.coerceAtMost(Int.MAX_VALUE.toLong()).toInt())
            is RrpFrame.Ping -> sendFrameQuiet(RrpFrame.Pong(frame.nonce))
            is RrpFrame.Pong -> lastPongMs.set(System.currentTimeMillis())
            is RrpFrame.Stats -> log("STATS: ${frame.json}")
            is RrpFrame.ProbeResp -> {
                log("RECV PROBE ok=${frame.ok} err=${frame.err} proto=${frame.proto}")
                probeResp = frame
            }
            is RrpFrame.ProbeReq -> log("PROBE от сервера не ожидается")
            is RrpFrame.ErrorFrame -> {
                log("сервер ERROR ${frame.code}: ${frame.message} (raw payload ${frame.rawHex()})")
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
    fun sendOpen(addr: String, port: Int): OpenFuture {
        val future = OpenFuture()
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
            future.complete(ERR_CONNECT_FAILED)
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
        // DNS-resolve выполняем сами и проверяем КАЖДЫЙ адрес по байтам:
        // hostname может резолвиться в приватный IP (DNS-rebinding bypass строки-гварда)
        val allowedAddr = try {
            java.net.InetAddress.getAllByName(targetHost)
                .firstOrNull { !SsrfGuard.isBlockedAddress(it, allowLan) }
        } catch (e: Exception) {
            sendOpenOk(streamId, ERR_BAD_ADDRESS)
            return
        }
        if (allowedAddr == null) {
            log("OPEN $targetHost:${frame.port}: все резолвы заблокированы SSRF-guard")
            sendOpenOk(streamId, ERR_SSRF_BLOCKED)
            return
        }
        try {
            relayExecutor.execute {
                var sock: Socket? = null
                try {
                    val s = Socket()
                    // коннект на уже проверенный адрес — без повторного DNS-резолва
                    s.connect(InetSocketAddress(allowedAddr, frame.port), CONNECT_TIMEOUT_MS)
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

    /** Поток: сокет цели → DATA кадры (с учётом окна flow-control).
     *  acquire с таймаутом: если сервер умер и не наращивает окно — поток не висит вечно. */
    private fun pumpOutgoing(st: Stream) {
        val buf = ByteArray(16 * 1024)
        try {
            val input = st.socket.getInputStream()
            while (running.get() && !st.closed.get()) {
                val n = input.read(buf)
                if (n < 0) break
                if (n == 0) continue
                if (!st.sendWindow.tryAcquire(n, WINDOW_ACQUIRE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                    log("stream ${st.id}: окно не наращено за ${WINDOW_ACQUIRE_TIMEOUT_MS}мс — закрываю")
                    sendFrameQuiet(RrpFrame.Close(st.id, ERR_TIMEOUT))
                    break
                }
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

    // ------------------------------------------------------------------ UDP (v0.7)

    /** S→C UDP_ASSOC: сервер просит поднять UDP-релей. Ответ — OPEN_OK c err_code. */
    private fun handleIncomingUdpAssoc(frame: RrpFrame.UdpAssoc) {
        val id = frame.streamId
        if (udpAssocs.size >= maxStreams) {
            sendOpenOk(id, ERR_TOO_MANY_STREAMS)
            return
        }
        val assoc = try {
            UdpAssoc(id)
        } catch (e: Exception) {
            log("UDP assoc: не удалось поднять сокет: ${e.message}")
            sendOpenOk(id, ERR_CONNECT_FAILED)
            return
        }
        udpAssocs[id] = assoc
        sendOpenOk(id, ERR_OK)
        Thread({ udpReceiveLoop(assoc) }, "rrp-udp-$id").apply { isDaemon = true }.start()
    }

    /** Приём дейтаграмм из интернета → UDP_DATA C→S (источник = фактический отправитель). */
    private fun udpReceiveLoop(assoc: UdpAssoc) {
        val buf = ByteArray(UDP_RECV_BUFFER)
        while (running.get() && !assoc.closed.get()) {
            val pkt = DatagramPacket(buf, buf.size)
            try {
                assoc.socket.receive(pkt)
            } catch (_: Exception) {
                break
            }
            if (pkt.length <= 0) continue
            val src = pkt.address
            val atyp = if (src.address.size == 4) RrpAddress.ATYP_IPV4 else RrpAddress.ATYP_IPV6
            sendFrameQuiet(RrpFrame.UdpData(assoc.id, atyp, src.address, pkt.port, buf.copyOf(pkt.length)))
        }
    }

    /** S→C UDP_DATA: дейтаграмма на адрес назначения (с SSRF-guard; порт 53 = DNS+ разрешён). */
    private fun handleUdpData(frame: RrpFrame.UdpData) {
        val assoc = udpAssocs[frame.streamId]
        if (assoc == null || assoc.closed.get()) return
        val targetHost = try {
            RrpAddress.decodeAddr(frame.atyp, frame.addr)
        } catch (e: Exception) {
            return
        }
        // Порт 53 разрешён даже в приватные сети: это DNS-релей телефона,
        // тот же резолвер, которым телефон пользуется сам (документировано в protocol.md).
        val allow = allowLan || frame.port == 53
        if (SsrfGuard.isBlocked(targetHost, allow)) {
            log("UDP $targetHost:${frame.port} заблокирован SSRF-guard")
            return
        }
        val dst: java.net.InetAddress = when (frame.atyp) {
            RrpAddress.ATYP_IPV4, RrpAddress.ATYP_IPV6 -> try {
                java.net.InetAddress.getByAddress(frame.addr)
            } catch (e: Exception) {
                return
            }
            else -> {
                // домен: резолвим сами и проверяем каждый адрес (DNS-rebinding)
                val resolved = try {
                    java.net.InetAddress.getAllByName(targetHost)
                        .firstOrNull { !SsrfGuard.isBlockedAddress(it, allow) }
                } catch (e: Exception) {
                    null
                }
                if (resolved == null) {
                    log("UDP $targetHost:${frame.port}: резолв заблокирован SSRF-guard")
                    return
                }
                resolved
            }
        }
        if (SsrfGuard.isBlockedAddress(dst, allow)) {
            log("UDP $targetHost:${frame.port}: адрес заблокирован SSRF-guard")
            return
        }
        if (frame.bytes.isEmpty()) return
        try {
            assoc.socket.send(DatagramPacket(frame.bytes, frame.bytes.size, dst, frame.port))
        } catch (e: Exception) {
            log("udp send failed: ${e.message}")
        }
    }

    /** Локальная UDP-ассоциация: DatagramSocket + поток приёма. */
    private inner class UdpAssoc(val id: Long) {
        val socket: java.net.DatagramSocket = java.net.DatagramSocket()
        val closed = AtomicBoolean(false)

        init {
            socket.reuseAddress = true
        }

        fun closeQuietly() {
            if (closed.compareAndSet(false, true)) {
                try { socket.close() } catch (_: Exception) {}
            }
        }
    }

    /** OutputStream-адаптер над WsStream: один вызов write = одно binary-сообщение. */
    private class WsOutput(private val ws: WsStream) : OutputStream() {
        override fun write(b: Int) = throw UnsupportedOperationException("WS: побайтовая запись не поддерживается")
        override fun write(b: ByteArray) {
            ws.writeMessage(b)
        }
        override fun write(b: ByteArray, off: Int, len: Int) {
            ws.writeMessage(if (off == 0 && len == b.size) b else b.copyOfRange(off, off + len))
        }
        override fun flush() {}
        override fun close() = ws.closeFrame()
    }

    // ------------------------------------------------------------------ PROBE

    /** Результат PROBE-валидации egress. */
    data class ProbeResult(val ok: Boolean, val err: String)

    /**
     * Отправляет PROBE и ждёт ответ (единичный, без ретраев — ретраи и
     * откат делает владелец). null — таймаут/нет ответа.
     */
    fun probeOnce(target: String, timeoutMs: Long): ProbeResult? {
        if (state != State.READY) return null
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
            log("PROBE не отправлен: ${e.message}")
            null
        }
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
        val out = wireOut ?: throw RrpClientException("нет соединения")
        when (frame) {
            is RrpFrame.Data -> {
                txBytes.addAndGet(frame.bytes.size.toLong())
                packetsTx.incrementAndGet()
                lastPacketTxSize.set(frame.bytes.size.toLong())
                lastPacketKind = KIND_TCP
            }
            is RrpFrame.UdpData -> {
                txBytes.addAndGet(frame.bytes.size.toLong())
                packetsTx.incrementAndGet()
                lastPacketTxSize.set(frame.bytes.size.toLong())
                lastPacketKind = KIND_UDP
            }
            else -> {}
        }
        synchronized(sendLock) {
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
        udpAssocs.values.forEach { it.closeQuietly() }
        udpAssocs.clear()
        try { wireWs?.closeFrame() } catch (_: Exception) {}
        try { tls?.close() } catch (_: Exception) {}
        closeQuietly(socket)
        wireIn = null
        wireOut = null
        wireWs = null
        tls = null
        socket = null
    }

    // ------------------------------------------------------------------ трафик

    /** [tx, rx] суммарные байты payload'ов с момента connect (для графика UI). */
    fun bytesSnapshot(): Pair<Long, Long> = txBytes.get() to rxBytes.get()

    // ------------------------------------------------------------------ misc

    private fun setState(s: State) {
        state = s
        listener?.onState(this, s)
    }

    private fun log(message: String) {
        listener?.onLog(this, message)
    }

    /** Hex-дамп первых 64 байт (для анализа raw-данных в журнале приложения). */
    private fun RrpFrame.rawHex(): String {
        val p = try { encode().copyOfRange(RrpFrame.HEADER_SIZE, encode().size) } catch (e: Exception) { ByteArray(0) }
        val n = minOf(64, p.size)
        return p.take(n).joinToString(" ") { String.format("%02x", it) } + if (p.size > n) "…" else ""
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
        ensureFullBouncyCastle()
        // BcTlsCrypto — лёгкий (lightweight) бэкенд без JCA: не зависит от
        // провайдера "BC" платформы (на Android он урезан; v0.5.1 не чинит
        // все устройства). Работает на всех Android начиная с API 14.
        val crypto: TlsCrypto = defaultCrypto()
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
                    val chain = serverCertificate.certificate.certificateList
                    if (chain.isEmpty()) throw TlsFatalAlert(AlertDescription.bad_certificate)
                    val leafDer = chain[0].encoded // TlsCertificate.getEncoded(): полный DER
                    val cert = org.bouncycastle.asn1.x509.Certificate.getInstance(leafDer)
                    val spkiDer = cert.subjectPublicKeyInfo.encoded
                    val actual = MessageDigest.getInstance("SHA-256").digest(spkiDer)
                    val actualB64 = Base64.getEncoder().encodeToString(actual)

                    // Строгий путь: пин из конфига совпал.
                    if (pin != null) {
                        val expected = decodePin(pin)
                        if (MessageDigest.isEqual(actual, expected)) {
                            acceptedPin = actualB64
                            return
                        }
                    }
                    // TOFU (v0.7.2): пин не совпал/не задан — принимаем валидную
                    // самоподписанную цепочку (leaf подписан последним сертификатом
                    // цепочки, последний — self-signed CA). Это возвращает туннель
                    // к жизни после перегенерации CA на сервере без re-enroll.
                    if (trustSelfSigned && isSelfSignedChain(chain)) {
                        log("TLS: CA-pin не совпал — принят самоподписанный сервер (TOFU); новый pin=$actualB64 (обнови строку конфига)")
                        acceptedPin = actualB64
                        listener?.onPinAccepted(this@RrpClient, actualB64)
                        return
                    }
                    throw TlsFatalAlert(AlertDescription.bad_certificate)
                }

                override fun getClientCredentials(certificateRequest: CertificateRequest): TlsCredentials? =
                    null
            }
        }
    }

    /**
     * Проверка self-signed цепочки без JCA-провайдера "BC": leaf подписан
     * последним сертификатом цепочки, последний — CA (IsCA) и подписан сам собой.
     * Достаточно для TOFU: мы не пытаемся построить WebPKI-доверие, мы лишь
     * фиксируем, что сервер предъявил валидную самоподписанную иерархию.
     */
    private fun isSelfSignedChain(
        chain: Array<org.bouncycastle.tls.crypto.TlsCertificate>,
    ): Boolean {
        return try {
            val cf = java.security.cert.CertificateFactory.getInstance("X.509")
            val javaChain = chain.map { c ->
                cf.generateCertificate(java.io.ByteArrayInputStream(c.getEncoded()))
            }
            if (javaChain.isEmpty()) {
                false
            } else {
                val leaf = javaChain.first() as java.security.cert.X509Certificate
                val top = javaChain.last() as java.security.cert.X509Certificate
                // verify() бросает исключение при плохой подписи — ловится ниже
                leaf.verify(top.publicKey)
                top.subjectX500Principal == top.issuerX500Principal
            }
        } catch (e: Exception) {
            false
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
        const val DEFAULT_AGENT = "ReverseRay-Android/0.7.4"

        const val KIND_TCP = "TCP"
        const val KIND_UDP = "UDP"

        /** Таймаут валидационного PROBE, мс (сервер клампит в 1..15 с). */
        const val PROBE_TIMEOUT_MS = 5_000L
        const val TRANSPORT_TCP = "tcp"
        const val TRANSPORT_WS = "ws"

        /** Lightweight-крипто без JCA: не зависит от провайдера "BC" платформы. */
        fun defaultCrypto(): TlsCrypto = BcTlsCrypto(SecureRandom())

        @Volatile private var bcEnsured = false

        /**
         * Android содержит урезанный провайдер "BC" (или не содержит вовсе):
         * JcaTlsCrypto резолвит дайджесты через Security и падает
         * ("no such algorithm: SHA-512 for provider BC").
         * Регистрируем ПОЛНЫЙ BouncyCastleProvider из пакета приложения
         * (идемпотентно) — нужен для JCA-хелперов (MessageDigest/Mac) на
         * старых устройствах. Сам TLS-crypto с v0.7 использует BcTlsCrypto
         * (lightweight) и от JCA-провайдера не зависит вовсе.
         */
        fun ensureFullBouncyCastle() {
            if (bcEnsured) return
            synchronized(this) {
                if (bcEnsured) return
                try {
                    Security.removeProvider("BC")
                    Security.insertProviderAt(org.bouncycastle.jce.provider.BouncyCastleProvider(), 1)
                    // self-check: алгоритм, на котором падал резолв
                    MessageDigest.getInstance("SHA-512", "BC")
                    bcEnsured = true
                } catch (e: Exception) {
                    // не удалось — оставляем как есть (ошибка всплывёт в buildTlsClient с внятным стектрейсом)
                }
            }
        }
        const val ALPN_PROTOCOL = "reverseray/1"
        const val MODE_TOKEN_HMAC = "token-hmac"

        const val CONNECT_TIMEOUT_MS = 10_000
        const val TLS_HANDSHAKE_TIMEOUT_MS = 15_000
        const val WS_HANDSHAKE_TIMEOUT_MS = 15_000
        const val HANDSHAKE_TIMEOUT_MS = 20_000L
        const val UDP_RECV_BUFFER = 64 * 1024
        const val OPEN_TIMEOUT_MS = 30_000L
        const val WINDOW_ACQUIRE_TIMEOUT_MS = 30_000L
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
