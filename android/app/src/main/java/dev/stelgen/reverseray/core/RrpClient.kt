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
open class RrpClientException(message: String, cause: Throwable? = null) : IOException(message, cause)

/**
 * v0.9.4: сервер отклонил токен (ERROR 1 «auth failed») — это НЕ сетевой сбой:
 * ретраи бессмысленны и лишь зарабатывают IP-локаут (30с·2ⁿ; клиент видит его
 * как «TLS handshake_failure(40)» — BC конвертирует глухой pre-TLS close в
 * alert 40). Владелец (TunnelService) обязан остановить авто-реконнект и
 * потребовать обновить ссылку из rr.sh/enroll.
 */
class RrpAuthException(message: String) : RrpClientException(message)

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
 * - SPKI-pin: sha256(SPKI CA = ПОСЛЕДНИЙ серт цепочки), сверка в
 *   notifyServerCertificate (v0.9.0: раньше хешировался лист — ломалось при
 *   плановой ротации листа);
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
    /** v0.8.2: политика шума камуфляжа «API Mask» (null — модуль выключен). */
    private val noisePolicy: Apimask.NoisePolicy? = null,
    /** Желаемый протокол (&proto= из ссылки; мусор сводится к дефолту). */
    private val protoId: String = RrpProtocols.DEFAULT,
    /** v0.7.4: цель валидационного PROBE после READY ("host:port").
     *  null — не проверять. Это «реальный трафик до реального хоста»:
     *  сервер диалит цель с егресса и отвечает фактом установки TCP. */
    private val validateProbeTarget: String? = null,
    /**
     * v0.9.5: начальный выбор камуфляжа устройством (кадр 0x2A после READY):
     * true/false — отправить один раз; null — не отправлять. Выбор персистентен
     * на сервере — переживает офлайн клиента и применяется будущим сессиям.
     */
    private val initialCamCtl: Boolean? = null,
    /** Транспорт: "tcp" (сырой RRP/1) или "ws" (WebSocket-апгрейд /rrp). */
    private val transport: String = TRANSPORT_TCP,
    /**
     * v0.7.2 TOFU: принимать валидный самоподписанный сервер, если пин из
     * конфига не задан (первый enroll: «подружили клиент-сервер, зафиксировали
     * сертификат»). v0.8.1 КАНОН БЕЗОПАСНОСТИ: если пин ЗАДАН и НЕ совпал —
     * соединение ОТКЛОНЯЕТСЯ (признак MITM/подмены сервера), по умолчанию
     * strict (false). true оставлен только для явного.override и тестов.
     */
    val trustSelfSigned: Boolean = false,
) {

    interface Listener {
        fun onState(client: RrpClient, state: State) {}
        fun onLog(client: RrpClient, message: String) {}
        /** TOFU: пин из конфига не совпал, принят самоподписанный сервер. */
        fun onPinAccepted(client: RrpClient, newPin: String) {}

        /** v0.9.0: пин из ссылки не совпал (ротация CA владельцем/или MITM).
         *  realPin — фактический пин сервера в каноне ссылки (base64url). */
        fun onPinMismatch(client: RrpClient, realPin: String) {}
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

    /** v0.8.1: срок действия серверного TLS-сертификата (epoch мс; 0 — неизвестен). */
    @Volatile var serverCertValidUntilMs: Long = 0
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

    /** v0.8.2: возможности сервера из READY (например "apimask"). */
    @Volatile var serverFeatures: List<String> = emptyList()
        private set

    /** Сервер подтвердил камуфляж «API Mask» (клиент может слать NOISE). */
    val apimaskSupported: Boolean
        get() = serverFeatures.contains(Apimask.FEATURE)

    /** Счётчики шума камуфляжа (байты payload'ов NOISE; для честной статистики). */
    private val noiseTx = AtomicLong(0)
    private val noiseRx = AtomicLong(0)
    @Volatile private var noiseBudgetLogged = false

    @Volatile private var probeResp: RrpFrame.ProbeResp? = null

    /** v0.8: крипто-контекст mtproto2 (не null после успешного DH-апгрейда). */
    @Volatile private var mtCrypto: MtProto.SessionCrypto? = null

    /** Активен ли MTProto-конверт в этой сессии (для UI/статуса). */
    val mtProtoActive: Boolean get() = mtCrypto != null

    /** v0.9.5: крипто-контекст wireguard (не null после WG-хендшейка). */
    @Volatile private var wgCrypto: Wg.Transport? = null

    /** Активен ли WireGuard-конверт в этой сессии. */
    val wgActive: Boolean get() = wgCrypto != null

    /**
     * v0.9.6 ФИКС ДЕДЛОКА WG-хендшейка: reader-поток НЕ МОЖЕТ ждать WG_RESP —
     * он единственный читает кадры, а WG_RESP диспатчится ТОЛЬКО им
     * (self-deadlock: ждали кадр, держа единственного его доставщика).
     * Теперь: KEY_REQ(kind=wg) → строим msg1 и шлём WG_INIT БЕЗ ожидания;
     * пришедший WG_RESP догревается в dispatch и активирует крипту там же.
     * Дедлайн — серверный key-timer убьёт сессию, если ответа не будет.
     */

    /** Активен ли крипто-конверт протокола (mtproto2 или wireguard). */
    val tunnelCryptoActive: Boolean get() = mtCrypto != null || wgCrypto != null

    /** v0.9.6: незавершённый WG-хендшейк (msg1 отправлен, ждём WG_RESP). */
    @Volatile private var wgHandshake: Wg.ClientHandshake? = null
    @Volatile private var wgPsk: ByteArray? = null

    /**
     * v0.9.5: начальный выбор камуфляжа для этого устройства (кадр 0x2A после
     * READY). true/false — отправить; null — не отправлять (клиент молчит).
     */
    @Volatile private var pendingCamCtl: Boolean? = initialCamCtl

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
    // v0.9.2 (R6): адаптивный keepalive — время отправки последнего PING и RTT
    private val lastPingSentAt = AtomicLong(0)
    private val lastRttMs = AtomicLong(0)

    private val pingExecutor: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "rrp-ping").apply { isDaemon = true } }
    private val relayExecutor: ExecutorService =
        Executors.newCachedThreadPool { r -> Thread(r, "rrp-relay").apply { isDaemon = true } }

    // ------------------------------------------------------------------ connect

    @Throws(IOException::class)
    fun connect() {
        check(state == State.DISCONNECTED || state == State.CLOSED) { Msgs.CLIENT_ACTIVE.t(state) }
        setState(State.CONNECTING)

        val sock = Socket()
        try {
            // v0.8.1: коннект РАВНОПРАВЕН по IP и по DNS-имени; честно показываем,
            // во что резолвится имя (канал «ничего не прячем»).
            val resolved = try {
                java.net.InetAddress.getAllByName(host).firstOrNull { !it.isLoopbackAddress || host.contains(':') || host == "localhost" }
                    ?: java.net.InetAddress.getAllByName(host).first()
            } catch (e: Exception) {
                throw RrpClientException("DNS $host: ${e.message}", e)
            }
            val byName = host.firstOrNull { !it.isDigit() && it != '.' && it != ':' } != null
            log("TCP $host:$port → $resolved (${if (byName) "DNS-имя" else "IP"})")
            sock.connect(InetSocketAddress(resolved, port), CONNECT_TIMEOUT_MS)
            sock.tcpNoDelay = true
        } catch (e: RrpClientException) {
            closeQuietly(sock)
            setState(State.CLOSED)
            throw e
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
        log(
            Msgs.SENT_HELLO.t(
                agentName, deviceName, RrpFrame.VERSION, RrpProtocols.normalize(protoId),
                RrpProtocols.labelWithVer(protoId), MAX_STREAMS_REQUEST, hello.encode().size,
            ),
        )
        sendFrame(hello)
        try {
            if (!helloLatch.await(HANDSHAKE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                throw RrpClientException(Msgs.HELLO_OK_TIMEOUT.t("$host:$port"))
            }
            handshakeError?.let { throw it }
            val ok = helloOkFrame ?: throw RrpClientException(Msgs.HELLO_OK_EMPTY.t())
            sessionId = ok.sessionId
            if (ok.tunnelWindow > 0) tunnelWindow = ok.tunnelWindow

            // v0.7.3 ФИКСЫ: (1) nonce — СЕРВЕРНЫЙ из HELLO_OK (клиент раньше
            // генерировал свой — сервер сверяет HMAC со своим); (2) ключ HMAC =
            // SHA256(token), не сырой токен (иначе auth всегда падает).
            log("RECV HELLO_OK session=${ok.sessionId} server_ver=${ok.serverVer} nonce=${ok.nonce.ifEmpty { "<НЕТ>" }} window=${ok.tunnelWindow}")
            if (ok.nonce.isEmpty()) {
                throw RrpClientException(Msgs.HELLO_OK_NO_NONCE.t())
            }
            val nonceBytes = try {
                Base64.getUrlDecoder().decode(ok.nonce)
            } catch (e: IllegalArgumentException) {
                try { Base64.getDecoder().decode(ok.nonce) } catch (e2: IllegalArgumentException) { null }
            } ?: throw RrpClientException(Msgs.HELLO_OK_BAD_NONCE.t(ok.nonce.take(32)))
            val macInput = nonceBytes + ok.sessionId.toByteArray(Charsets.UTF_8)
            val hmacKey = MessageDigest.getInstance("SHA-256").digest(token.toByteArray(Charsets.UTF_8))
            // v0.7.4 ФИКС: HMAC — base64url БЕЗ паддинга (RawURLEncoding на сервере).
            // APK 0.7.3 кодировал стандартным base64 (с «+ /» и «=») — сервер
            // не мог декодировать и отвечал «ERROR 1: auth failed».
            val hmac = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(hmacSha256(hmacKey, macInput))
            // v0.9.4: token6 — первые 6 символов токена ИЗ КОНФИГА; владелец
            // сверяет их со ссылкой из rr.sh/enroll. Не совпали — ссылка устарела.
            log("SENT AUTH mode=$MODE_TOKEN_HMAC token6=${token.take(6)} nonce=${ok.nonce} hmac=${hmac.take(12)}… sessionId=$sessionId")
            sendFrame(
                RrpFrame.Auth(MODE_TOKEN_HMAC, hmac, ok.nonce)
            )

            if (!readyLatch.await(HANDSHAKE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                throw RrpClientException(Msgs.READY_TIMEOUT.t("$host:$port"))
            }
            handshakeError?.let { throw it }
            val rd = readyFrame ?: throw RrpClientException(Msgs.READY_EMPTY.t())
            if (rd.tunnelWindow > 0) tunnelWindow = rd.tunnelWindow
            if (rd.maxStreams > 0) maxStreams = rd.maxStreams
            negotiatedProto = RrpProtocols.normalize(rd.proto)
            RrpProtocols.rememberServerProtocols(rd.protocols)
            serverProtocols = rd.protocols
            serverFeatures = rd.features

            setState(State.READY)
            lastPongMs.set(System.currentTimeMillis())
            scheduleNextPing()
            log("RECV READY tunnel=${rd.tunnelId} role=${rd.role} proto=${rd.proto} (${RrpProtocols.labelWithVer(rd.proto)}) protocols=${rd.protocols.joinToString(",") { RrpProtocols.labelWithVer(it) }} maxStreams=${rd.maxStreams} window=${rd.tunnelWindow} → State.READY")
            // v0.8.2: камуфляж «API Mask» — только если сервер подтвердил
            // возможность (features) и модуль включён манифестом
            flushPendingCamCtl() // v0.9.5: начальный выбор камуфляжа устройства
            if (apimaskSupported && noisePolicy != null) {
                log(Msgs.APIMASK_ENABLED.t())
                scheduleNoise()
            }

            // v0.7.4: валидация «реального трафика» — PROBE до реального хоста.
            // Используется при смене протокола: коммит только после успеха.
            validateProbeTarget?.let { target ->
                log(Msgs.PROBE_SENT.t(target, rd.proto))
                val pr = probeOnce(target, PROBE_TIMEOUT_MS)
                if (pr == null) {
                    throw RrpClientException(Msgs.PROBE_NOT_ANSWERED.t())
                }
                if (!pr.ok) {
                    throw RrpClientException(Msgs.PROBE_VALIDATION_FAILED.t(pr.err.ifEmpty { Msgs.PROBE_NO_EGRESS.t() }))
                }
                log(Msgs.PROBE_OK.t(target))
            }
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            close()
            throw RrpClientException(Msgs.HANDSHAKE_INTERRUPTED.t(), e)
        } catch (e: IOException) {
            close()
            throw e
        }
    }

    // ------------------------------------------------------------------ reader

    private fun readerLoop() {
        try {
            val input = wireIn ?: throw RrpClientException(Msgs.TRANSPORT_NOT_READY.t())
            while (running.get()) {
                dispatch(RrpFrame.parse(input))
            }
        } catch (e: Throwable) {
            if (state != State.READY && handshakeError == null) {
                handshakeError = RrpClientException(Msgs.HANDSHAKE_FAILED.t(e.message), e)
            } else if (running.get()) {
                log(Msgs.READER_STOPPED.t(e.message))
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
            is RrpFrame.Auth -> log(Msgs.AUTH_UNEXPECTED.t())
            is RrpFrame.Hello -> log(Msgs.HELLO_UNEXPECTED.t())
            is RrpFrame.Open -> handleIncomingOpen(frame)
            is RrpFrame.OpenOk -> pendingOpens.remove(frame.streamId)?.complete(frame.errCode)
            is RrpFrame.Data -> {
                val f = decryptPayload(frame) ?: return
                rxBytes.addAndGet(f.bytes.size.toLong())
                packetsRx.incrementAndGet()
                lastPacketRxSize.set(f.bytes.size.toLong())
                lastPacketKind = KIND_TCP
                handleData(f)
            }
            is RrpFrame.UdpAssoc -> handleIncomingUdpAssoc(frame)
            is RrpFrame.UdpData -> {
                val f = decryptUdpPayload(frame) ?: return
                rxBytes.addAndGet(f.bytes.size.toLong())
                packetsRx.incrementAndGet()
                lastPacketRxSize.set(f.bytes.size.toLong())
                lastPacketKind = KIND_UDP
                handleUdpData(f)
            }
            is RrpFrame.Close -> closeStream(frame.streamId, notify = false)
            is RrpFrame.Window -> streams[frame.streamId]?.sendWindow
                ?.release(frame.increment.coerceAtMost(Int.MAX_VALUE.toLong()).toInt())
            is RrpFrame.Ping -> sendFrameQuiet(RrpFrame.Pong(frame.nonce))
            is RrpFrame.Pong -> {
                lastPongMs.set(System.currentTimeMillis())
                // v0.9.2 (R6): фактический RTT — для адаптивного keepalive
                val sentAt = lastPingSentAt.get()
                if (sentAt > 0) {
                    val rtt = System.currentTimeMillis() - sentAt
                    if (rtt in 1..300_000) lastRttMs.set(rtt)
                }
            }
            is RrpFrame.Stats -> log("STATS: ${frame.json}")
            is RrpFrame.ProbeResp -> {
                log("RECV PROBE ok=${frame.ok} err=${frame.err} proto=${frame.proto}")
                probeResp = frame
            }
            is RrpFrame.ProbeReq -> log(Msgs.PROBE_UNEXPECTED.t())
            is RrpFrame.KeyReq -> handleKeyReq(frame) // v0.8/v0.9.5: mtproto2 DH | wireguard WG_INIT
            is RrpFrame.KeyResp -> log(Msgs.KEY_RESP_UNEXPECTED.t())
            is RrpFrame.WgResp -> {
                // v0.9.5: WG msg2 — активируем клиентский транспорт WG-конвертов.
                // v0.9.6: дедлок-фикс — consume ЗДЕСЬ (reader-поток), а не в
                // handleWgKeyReq: он единственный доставщик этого кадра.
                log(Msgs.WG_RESP_RECV.t(frame.raw.size))
                finishWgHandshake(frame)
            }
            is RrpFrame.WgInit -> log(Msgs.WG_INIT_UNEXPECTED.t())
            is RrpFrame.Noise -> {
                // v0.8.2: ответ сервера на наш шум — байты считаются в общий
                // трафик (честно: это реальные байты мобильной сети),
                // но НЕ в «пакеты» пользовательских данных
                val n = frame.json.toByteArray(Charsets.UTF_8).size
                rxBytes.addAndGet(n.toLong())
                noiseRx.addAndGet(n.toLong())
            }
            is RrpFrame.CamCtl -> log(Msgs.CAM_CTL_UNEXPECTED.t())
            is RrpFrame.ErrorFrame -> {
                log(Msgs.SERVER_ERROR_RAW.t(frame.code, frame.message, frame.rawHex()))
                for (id in pendingOpens.keys) {
                    pendingOpens.remove(id)?.complete(ERR_PROTOCOL)
                }
                if (state != State.READY && handshakeError == null) {
                    // v0.9.4: код 1 сервер отправляет ТОЛЬКО на провал AUTH
                    // («auth failed») — типизируем отдельно, чтобы сервис мог
                    // остановить авто-реконнект вместо долбёжки в локаут.
                    handshakeError =
                        if (frame.code == 1) RrpAuthException(Msgs.SERVER_ERROR.t(frame.code, frame.message))
                        else RrpClientException(Msgs.SERVER_ERROR.t(frame.code, frame.message))
                    helloLatch.countDown()
                    readyLatch.countDown()
                }
            }
        }
    }

    // ------------------------------------------------------------------ MTProto/2 (v0.8)

    /**
     * KEY_REQ от сервера (после READY при согласованном proto=mtproto2):
     * валидируем p (anti-logjam — обязан равняться каноническому dh_prime
     * Telegram) и g=3, проверяем g_a по канону guidelines, генерируем свою
     * долю, шлём KEY_RESP и включаем MTProto-конверт на DATA/UDP_DATA.
     */
    private fun handleKeyReq(frame: RrpFrame.KeyReq) {
        if (mtCrypto != null || wgCrypto != null) {
            log(Msgs.KEY_REQ_IGNORED.t())
            return
        }
        if (frame.kind.isNotBlank() && frame.kind != MtProto.PROTO_ID) {
            handleWgKeyReq(frame)
            return
        }
        try {
            val pBytes = MtProto.b64urlDecode(frame.p)
            if (!pBytes.contentEquals(MtProto.P.toByteArray().let { bytes ->
                    // BigInteger.toByteArray() может дать 257 байт с ведущим 0
                    if (bytes.size == 257) bytes.copyOfRange(1, 257) else bytes
                })
            ) {
                throw MtProto.MtProtoException(Msgs.DH_PRIME_MISMATCH.t())
            }
            if (frame.g != MtProto.G.toInt()) {
                throw MtProto.MtProtoException(Msgs.DH_G_UNEXPECTED.t(frame.g))
            }
            val gA = MtProto.publicFromBytes(MtProto.b64urlDecode(frame.gA))
            MtProto.validatePublic(gA)
            val dh = MtProto.ClientDh()
            dh.generatePrivate()
            val gB = MtProto.publicBytes(dh.public)
            val gABytes = MtProto.b64urlDecode(frame.gA)
            val authKey = dh.shared(gA)
            val sid = sessionId ?: throw MtProto.MtProtoException(Msgs.NO_SESSION_ID.t())
            mtCrypto = MtProto.SessionCrypto(
                authKey,
                MtProto.saltFor(sid, gABytes, gB),
                MtProto.sessionId8(sid),
            )
            log(Msgs.MTPROTO_KEYS_OK.t())
            listener?.onState(this, State.READY) // уведомить UI о включении крипто
            sendFrame(RrpFrame.KeyResp(MtProto.b64url(gB)))
        } catch (e: Exception) {
            log(Msgs.MTPROTO_EXCHANGE_FAILED.t(e.message))
            close()
        }
    }

    /** Расшифровка DATA-конверта (в обычном режиме — без изменений). */
    /** Активный конверт: wireguard (v0.9.5) имеет приоритет, затем mtproto2. */
    private fun activeMaxPlainData(): Int? = when {
        wgCrypto != null -> Wg.MAX_PLAIN_DATA
        mtCrypto != null -> MtProto.SessionCrypto.MAX_PLAIN_DATA
        else -> null
    }

    private fun encryptDown(bytes: ByteArray): ByteArray {
        wgCrypto?.let { return it.seal(bytes) }
        mtCrypto?.let { return it.encryptDown(bytes) }
        return bytes
    }

    private fun decryptUpEnvelope(payload: ByteArray): ByteArray {
        wgCrypto?.let { return it.open(payload) }
        mtCrypto?.let { return it.decryptUp(payload) }
        return payload
    }

    private fun decryptPayload(frame: RrpFrame.Data): RrpFrame.Data? {
        if (mtCrypto == null && wgCrypto == null) return frame
        return try {
            RrpFrame.Data(frame.streamId, frame.flags, decryptUpEnvelope(frame.bytes))
        } catch (e: Exception) {
            log(Msgs.MTPROTO_DATA_ENVELOPE_BAD.t(frame.streamId, e.message))
            close()
            null
        }
    }

    /** Расшифровка UDP_DATA-конверта. */
    private fun decryptUdpPayload(frame: RrpFrame.UdpData): RrpFrame.UdpData? {
        if (mtCrypto == null && wgCrypto == null) return frame
        return try {
            RrpFrame.UdpData(frame.streamId, frame.atyp, frame.addr, frame.port, decryptUpEnvelope(frame.bytes))
        } catch (e: Exception) {
            log(Msgs.MTPROTO_UDP_ENVELOPE_BAD.t(e.message))
            null
        }
    }

    /**
     * WG-хендшейк (v0.9.5): KEY_REQ несёт WG static public сервера
     * ({"kind":"wireguard","spub":…}). Клиент — WG-инициатор: строит
     * НАСТОЯЩИЙ msg1 (Noise_IKpsk2, PSK = SHA256(token)), шлёт WG_INIT.
     *
     * v0.9.6: БЕЗ ожидания WG_RESP на reader-потоке (self-deadlock —
     * WG_RESP придёт через тот же поток; см. dispatch → finishWgHandshake).
     */
    private fun handleWgKeyReq(frame: RrpFrame.KeyReq) {
        try {
            val serverPub = MtProto.b64urlDecode(frame.sPub)
            if (serverPub.size != Wg.KEY_SIZE) {
                throw Wg.WgException(Msgs.WG_BAD_SPUB.t(frame.sPub.length))
            }
            val psk = Wg.tokenPsk(token)
            val (msg1, hs) = Wg.newClientHandshake(serverPub, psk)
            log(Msgs.WG_INIT_SENT.t(Wg.MSG_INIT_SIZE))
            wgHandshake = hs
            wgPsk = psk
            sendFrame(RrpFrame.WgInit(msg1))
        } catch (e: Exception) {
            // ридер умирает честной причиной (серверный key-timer параллельно закроет сессию)
            throw RrpClientException(Msgs.WG_FAILED.t(e.message ?: "?"), e)
        }
    }

    /**
     * v0.9.6: WG_RESP (msg2) — финал WG-хендшейка. Вызывается из dispatch
     * (reader-поток): consumeResponse чисто локальный (без чтения кадров),
     * поэтому здесь deadlock невозможен по построению.
     */
    private fun finishWgHandshake(frame: RrpFrame.WgResp) {
        val hs = wgHandshake ?: run {
            log(Msgs.WG_INIT_UNEXPECTED.t())
            return
        }
        val psk = wgPsk
        try {
            hs.consumeResponse(frame.raw, psk ?: throw Wg.WgException(Msgs.WG_RESP_TIMEOUT.t()))
            wgCrypto = Wg.clientTransport(hs)
            wgHandshake = null
            wgPsk = null
            log(Msgs.WG_KEYS_AGREED.t())
            listener?.onState(this, State.READY) // UI: статус крипты
        } catch (e: Exception) {
            // битый msg2 — нарушение протокола: сессия закрыта честной причиной
            throw RrpClientException(Msgs.WG_FAILED.t(e.message ?: "?"), e)
        }
    }

    /** v0.9.5: выбор камуфляжа устройством — кадр 0x2A немедленно (если READY). */
    fun sendCamCtl(enabled: Boolean) {
        pendingCamCtl = enabled
        if (state == State.READY) {
            log(Msgs.CAM_CTL_SENT.t(if (enabled) "on" else "off"))
            sendFrame(RrpFrame.CamCtl(enabled))
        }
    }

    private fun flushPendingCamCtl() {
        val want = pendingCamCtl ?: return
        pendingCamCtl = null
        if (state == State.READY) {
            log(Msgs.CAM_CTL_SENT.t(if (want) "on" else "off"))
            try {
                sendFrame(RrpFrame.CamCtl(want))
            } catch (e: IOException) {
                log(Msgs.CAM_CTL_FAILED.t(e.message ?: "?"))
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
            log(Msgs.SEND_OPEN_SSRF.t(addr))
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
            log(Msgs.OPEN_SSRF.t("$targetHost:${frame.port}"))
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
            log(Msgs.OPEN_RESOLVES_SSRF.t("$targetHost:${frame.port}"))
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
                    log(Msgs.WINDOW_NOT_GROWN.t(st.id, WINDOW_ACQUIRE_TIMEOUT_MS))
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
            log(Msgs.UDP_ASSOC_FAILED.t(e.message))
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
            log(Msgs.UDP_SSRF.t("$targetHost:${frame.port}"))
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
                    log(Msgs.UDP_RESOLVE_SSRF.t("$targetHost:${frame.port}"))
                    return
                }
                resolved
            }
        }
        if (SsrfGuard.isBlockedAddress(dst, allow)) {
            log(Msgs.UDP_ADDR_SSRF.t("$targetHost:${frame.port}"))
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
        override fun write(b: Int) = throw UnsupportedOperationException(Msgs.WS_WRITE_UNSUPPORTED.t())
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
            log(Msgs.PROBE_SEND_FAILED.t(e.message))
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
                    lastPingSentAt.set(System.currentTimeMillis())
                    sendFrame(RrpFrame.Ping(ByteArray(NONCE_SIZE).also { rnd.nextBytes(it) }))
                } catch (e: IOException) {
                    log(Msgs.PING_SEND_FAILED.t(e.message))
                }
                scheduleNextPing()
            }, pingIntervalMs(rnd, lastRttMs.get()), TimeUnit.MILLISECONDS)
        } catch (_: RejectedExecutionException) {
        }
    }

    // ------------------------------------------------------------------ frame IO

    private fun sendFrame(frame: RrpFrame) {
        val out = wireOut ?: throw RrpClientException(Msgs.NO_CONNECTION.t())
        var wire: RrpFrame = frame
        when (frame) {
            is RrpFrame.Data -> {
                txBytes.addAndGet(frame.bytes.size.toLong())
                packetsTx.incrementAndGet()
                lastPacketTxSize.set(frame.bytes.size.toLong())
                lastPacketKind = KIND_TCP
                val maxPlain = activeMaxPlainData()
                if (maxPlain != null) {
                    if (frame.bytes.size > maxPlain) {
                        throw RrpClientException(Msgs.DATA_LIMIT.t(frame.bytes.size))
                    }
                    wire = RrpFrame.Data(frame.streamId, frame.flags, encryptDown(frame.bytes))
                }
            }
            is RrpFrame.UdpData -> {
                txBytes.addAndGet(frame.bytes.size.toLong())
                packetsTx.incrementAndGet()
                lastPacketTxSize.set(frame.bytes.size.toLong())
                lastPacketKind = KIND_UDP
                val maxPlain = activeMaxPlainData()
                if (maxPlain != null) {
                    if (frame.bytes.size > maxPlain) {
                        // семантика UDP: слишком большая дейтаграмма дропается
                        log(Msgs.UDP_DATA_LIMIT.t(frame.bytes.size))
                        return
                    }
                    wire = RrpFrame.UdpData(frame.streamId, frame.atyp, frame.addr, frame.port, encryptDown(frame.bytes))
                }
            }
            is RrpFrame.Noise -> {
                // v0.8.2: шум камуфляжа — считается в общий трафик телефона
                // (честно), но НЕ в строку «пакеты» пользовательских данных
                val n = frame.json.toByteArray(Charsets.UTF_8).size
                txBytes.addAndGet(n.toLong())
                noiseTx.addAndGet(n.toLong())
            }
            else -> {}
        }
        synchronized(sendLock) {
            out.write(wire.encode())
            out.flush()
        }
    }

    // ------------------------------------------------------------------ NOISE (v0.8.2)

    /**
     * Расписание шума камуфляжа: раз в [min;max] сек (джиттер манифеста)
     * слать API-подобный NOISE-кадр; суточный бюджет из манифеста; каждая
     * посылка честно логируется строкой вызывающей стороны (язык приложения).
     */
    private fun scheduleNoise() {
        val policy = noisePolicy ?: return
        if (!running.get() || !apimaskSupported) return
        try {
            pingExecutor.schedule({
                if (!running.get()) return@schedule
                val body = try {
                    policy.engine.nextRequest()
                } catch (e: Exception) {
                    log(Msgs.NOISE_GEN_FAILED.t(e.message))
                    null
                }
                if (body == null) {
                    if (!noiseBudgetLogged) {
                        noiseBudgetLogged = true
                        log(policy.logLine(0, policy.engine.usedToday(), policy.engine.cfg.maxBytesPerDay))
                    }
                    // бюджет исчерпан: тихо ждём (проверка раз в час; завтра — шум возобновится)
                    try {
                        pingExecutor.schedule({ scheduleNoise() }, 3_600_000L, TimeUnit.MILLISECONDS)
                    } catch (_: RejectedExecutionException) {}
                    return@schedule
                }
                try {
                    sendFrame(RrpFrame.Noise(body))
                    val bytes = body.toByteArray(Charsets.UTF_8).size
                    policy.engine.onSent(bytes)
                    log(policy.logLine(bytes, policy.engine.usedToday(), policy.engine.cfg.maxBytesPerDay))
                } catch (e: IOException) {
                    log(Msgs.NOISE_SEND_FAILED.t(e.message))
                }
                scheduleNoise()
            }, policy.engine.nextDelayMs(), TimeUnit.MILLISECONDS)
        } catch (_: RejectedExecutionException) {
        }
    }

    private fun sendFrameQuiet(frame: RrpFrame) {
        try {
            sendFrame(frame)
        } catch (e: Exception) {
            log(Msgs.SEND_FAILED.t(e.message))
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

    /** [tx, rx] байты шума камуфляжа с момента connect (v0.8.2, честная статистика). */
    fun noiseSnapshot(): Pair<Long, Long> = noiseTx.get() to noiseRx.get()

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
                    // v0.9.0 КАНОН ПИНА: SHA256(SPKI ПОСЛЕДНЕГО серта цепочки (CA)).
                    // До 0.9.0 хешировался ЛИСТ (chain[0]) — лист ротируется «заранее»,
                    // CA не меняется: честные ссылки ломались ложным «pin mismatch»
                    // на проде после перевыпуска листа (TLS bad_certificate(42)).
                    val chainDer = chain.map { it.encoded }
                    val actual = RrpPin.caSha256(chainDer)
                    val actualB64 = RrpPin.toLinkPin(actual)

                    // Строгий путь: пин из конфига совпал.
                    if (pin != null) {
                        val expected = RrpPin.fromLinkPin(pin)
                        if (expected == null) {
                            log(Msgs.PIN_FORMAT.t())
                            throw TlsFatalAlert(AlertDescription.bad_certificate)
                        }
                        if (MessageDigest.isEqual(actual, expected)) {
                            acceptedPin = actualB64
                            rememberServerCert(chain)
                            return
                        }
                        // v0.8.1 КАНОН: пин задан и не совпал → ОТКАЗ. Это либо
                        // смена CA владельцем (нужен re-enroll), либо MITM —
                        // другим сертификатам мы НЕ доверяем никогда.
                        if (!trustSelfSigned) {
                            log(Msgs.TLS_PIN_MISMATCH.t(actualB64))
                            // v0.9.0: UI может предложить владельцу ЯВНО принять
                            // новый пин (анти-MITM канон: молча не доверяем никогда)
                            listener?.onPinMismatch(this@RrpClient, actualB64)
                            throw TlsFatalAlert(AlertDescription.bad_certificate)
                        }
                    }
                    // TOFU: (а) пина нет — первая «дружба» клиент↔сервер: принимаем
                    // валидную самоподписанную цепочку и ФИКСИРУЕМ пин — дальше
                    // шифруемся только с ним; (б) явный trustSelfSigned=true
                    // (override для тестов/параноидального режима).
                    // При заданном пине (дефолт) чужой самоподписанный сервер сюда
                    // НЕ попадает: строкой выше соединение уже отклонено.
                    if ((pin == null || trustSelfSigned) && isSelfSignedChain(chain)) {
                        if (pin == null) {
                            log(Msgs.TLS_TOFU_FIRST.t(actualB64))
                        } else {
                            log(Msgs.TLS_TOFU_OVERRIDE.t(actualB64))
                        }
                        acceptedPin = actualB64
                        rememberServerCert(chain)
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
     * Запоминает срок действия серверного сертификата из цепочки — честно
     * показываем пользователю (лог + «О приложении»): кем подписан и до какого
     * числа действителен.
     */
    private fun rememberServerCert(chain: Array<org.bouncycastle.tls.crypto.TlsCertificate>) {
        try {
            val cf = java.security.cert.CertificateFactory.getInstance("X.509")
            val leaf = cf.generateCertificate(java.io.ByteArrayInputStream(chain[0].getEncoded()))
                as java.security.cert.X509Certificate
            serverCertValidUntilMs = leaf.notAfter.time
            lastServerCertNotAfterMs = leaf.notAfter.time
            log(
                Msgs.TLS_CERT_VALID.t(
                    java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US).format(leaf.notAfter),
                    leaf.issuerX500Principal.name?.take(60) ?: "?",
                ),
            )
        } catch (_: Exception) {
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


    companion object {
        const val DEFAULT_AGENT = "ReverseRay-Android/0.8.2"

        /** Последний увиденный срок действия серта сервера (для «О приложении», epoch мс). */
        @Volatile var lastServerCertNotAfterMs: Long = 0
            private set

        const val KIND_TCP = "TCP"
        const val KIND_UDP = "UDP"

        /** Таймаут валидационного PROBE, мс (сервер клампит в 1..15 с). */
        const val PROBE_TIMEOUT_MS = 5_000L

        /** v0.9.2 (R6): границы адаптивного keepalive (см. pingIntervalMs). */
        private const val MIN_PING_INTERVAL_MS = 20_000L
        private const val MAX_PING_INTERVAL_MS = 55_000L
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

        /** Интервал PING: 60 с ±10 % джиттера (базовый, без данных RTT). */
        fun pingIntervalMs(rnd: Random): Long = pingIntervalMs(rnd, 0L)

        /**
         * v0.9.2 (R6): адаптивный keepalive — интервал из фактического RTT:
         * base = clamp(RTT × 4, 20с, 55с) ±10 % джиттера; без RTT — 60с.
         * Мобильные сети с длинным RTT пингуют реже (экономия батарейки
         * и трафика), быстрые Wi-Fi — чаще (раньше ловим мёртвый сокет).
         * Idle-таймаут сервера 180с — держим интервал < 60с всегда.
         */
        fun pingIntervalMs(rnd: Random, rttMs: Long): Long {
            val base = if (rttMs > 0) (rttMs * 4).coerceIn(MIN_PING_INTERVAL_MS, MAX_PING_INTERVAL_MS) else PING_INTERVAL_MS
            val jitter = base / 10
            return base - jitter + rnd.nextInt((2 * jitter + 1).toInt())
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
