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
import java.util.Locale

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
    internal val token: String,
    internal val pin: String? = null,
    private val agentName: String = DEFAULT_AGENT,
    internal val allowLan: Boolean = false,
    internal val listener: Listener? = null,
    /** Имя устройства (поле device в HELLO; сервер требует непустое ≤64). */
    private val deviceName: String = "phone-1",
    /** v0.8.2: политика шума камуфляжа «API Mask» (null — модуль выключен). */
    private val noisePolicy: Apimask.NoisePolicy? = null,
    /** Желаемый протокол (&proto= из ссылки; мусор сводится к дефолту). */
    private val protoId: String = RrpProtocols.DEFAULT,
    /** v0.7.4: цель валидационного PROBE после READY ("host:port").
     *  null — не проверять. Это «реальный трафик до реального хоста»:
     *  сервер диалит цель с егресса и отвечает фактом установки TCP. */
    internal val validateProbeTarget: String? = null,
    /** v1.8.0: цель end-to-end пробника полезной нагрузки ("host:port", HTTP).
     *  Сквозной путь OPEN→DATA→ответ через DATA-кадры: ловит сигнатурную
     *  блокировку (ТСПУ режет payload при живых контрольных кадрах), которую
     *  не видят PING/EWMA/серверный PROBE. null — пробник выключен (старое
     *  поведение). Таймаут калибруется от RTT-базлайна (E2eProbe). */
    internal val e2eProbeTarget: String? = E2E_DEFAULT_TARGET,
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

        /** v1.8.4: клиентские сообщения несут уровень журнала (trace..panic). */
        fun onLog(client: RrpClient, message: String, kind: LogKind) {}
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
        /** v1.3.0 «буфер трафика»: токен привязки сокета (caps stream-resume). */
        var resumeToken: ByteArray? = null
        /** Сокет припаркован: pump обязан выйти БЕЗ закрытия сокета. */
        val parked = AtomicBoolean(false)
    }

    internal val rnd = SecureRandom() // internal — зоны-extensions
    internal val running = AtomicBoolean(false) // internal — зоны-extensions
    internal val sendLock = Any()

    @Volatile private var socket: Socket? = null
    @Volatile private var tls: TlsClientProtocol? = null

    /** Ввод/вывод поверх TLS: сырой поток или WebSocket-обёртка. */
    @Volatile private var wireIn: InputStream? = null
    @Volatile private var wireOut: OutputStream? = null
    @Volatile private var wireWs: WsStream? = null

    /** Счётчики трафика (байты payload'ов DATA/UDP_DATA) для графика в UI. */
    internal val txBytes = AtomicLong(0)
    internal val rxBytes = AtomicLong(0)

    /** v0.7.4: счётчики ПАКЕТОВ (кадров DATA/UDP_DATA) и последний размер —
     *  для строки «стрелки» на главном экране (тип, размер, пакеты туда/сюда). */
    internal val packetsTx = AtomicLong(0)
    internal val packetsRx = AtomicLong(0)
    internal val lastPacketTxSize = AtomicLong(0)
    internal val lastPacketRxSize = AtomicLong(0)

    /** Тип последнего пакета: "TCP" (DATA) или "UDP" (UDP_DATA). */
    @Volatile var lastPacketKind: String = ""
        internal set

    /** [txCount, rxCount, lastTxSize, lastRxSize] — снимок для UI. */
    fun packetsSnapshot(): LongArray = longArrayOf(
        packetsTx.get(), packetsRx.get(),
        lastPacketTxSize.get(), lastPacketRxSize.get(),
    )

    /** Фактически принятый SPKI-пин сервера (заполняется в TOFU-режиме). */
    @Volatile var acceptedPin: String? = null
        internal set

    /** v0.8.1: срок действия серверного TLS-сертификата (epoch мс; 0 — неизвестен). */
    @Volatile var serverCertValidUntilMs: Long = 0
        internal set

    /** UDP-ассоциации: stream_id → локальный relay (DatagramSocket). */
    internal val udpAssocs = ConcurrentHashMap<Long, UdpAssoc>()

    @Volatile var state: State = State.DISCONNECTED
        private set

    @Volatile var sessionId: String? = null
        private set

    /** Протокол, выбранный сервером в этой сессии (канон после READY). */
    @Volatile var negotiatedProto: String = RrpProtocols.DEFAULT
        // v1.8.4: internal set — финалы бесшовной смены (RrpWg/RrpBt/RrpMproto)
        // актуализируют протокол сразу после подмены конверта.
        internal set

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

    @Volatile internal var probeResp: RrpFrame.ProbeResp? = null

    /** v0.8: крипто-контекст mtproto2 (не null после успешного DH-апгрейда). */
    @Volatile internal var mtCrypto: MtProto.SessionCrypto? = null

    /** Активен ли MTProto-конверт в этой сессии (для UI/статуса). */
    val mtProtoActive: Boolean get() = mtCrypto != null

    /** v0.9.5: крипто-контекст wireguard (не null после WG-хендшейка). */
    @Volatile internal var wgCrypto: Wg.Transport? = null

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

    /** Активен ли крипто-конверт протокола (mtproto2/wireguard/bittorrent). */
    val tunnelCryptoActive: Boolean get() = mtCrypto != null || wgCrypto != null || btCrypto != null

    /** v0.9.6: незавершённый WG-хендшейк (msg1 отправлен, ждём WG_RESP). */
    @Volatile internal var wgHandshake: Wg.ClientHandshake? = null
    @Volatile internal var wgPsk: ByteArray? = null

    /** v0.10: крипто-контекст bittorrent (не null после MSE-хендшейка). */
    @Volatile internal var btCrypto: Torrent.Transport? = null
    @Volatile internal var btHandshake: Torrent.ClientHandshake? = null

    /** Активен ли BitTorrent MSE-конверт в этой сессии. */
    val btActive: Boolean get() = btCrypto != null

    // ---- v0.10: бесшовная смена протокола (0x2C) ----

    /**
     * v1.8.3: очередь паркинга смены протокола (SwitchParking) — окно +
     * backpressure (канон v1.3.0 «буфер в RAM без дропов»). Контрольные кадры
     * идут свободно. var — для тестов (подменяется на узкое окно).
     */
    @Volatile internal var switchParking = SwitchParking(resolveParkedFramesMax())

    /** Ожидаемый ответ 0x2C (протокол-цель, nonce); null — запроса нет. */
    @Volatile internal var protoSwitchAck: RrpFrame.ProtoSwitch? = null // internal — зона в RrpClientSwitch.kt
    @Volatile internal var protoSwitchNonce: String = "" // internal — зона в RrpClientSwitch.kt
    @Volatile internal var pendingSwitchTarget: String? = null // v1.8.4: internal — финалы крипты в RrpWg/RrpBt/RrpMproto

    /**
     * v0.9.5: начальный выбор камуфляжа для этого устройства (кадр 0x2A после
     * READY). true/false — отправить; null — не отправлять (клиент молчит).
     */
    @Volatile internal var pendingCamCtl: Boolean? = initialCamCtl

    @Volatile var tunnelWindow: Long = DEFAULT_TUNNEL_WINDOW
        private set

    @Volatile var maxStreams: Int = MAX_STREAMS_REQUEST
        private set

    private val helloLatch = CountDownLatch(1)
    private val readyLatch = CountDownLatch(1)
    @Volatile private var helloOkFrame: RrpFrame.HelloOk? = null
    @Volatile private var readyFrame: RrpFrame.Ready? = null
    @Volatile private var handshakeError: IOException? = null

    internal val pendingOpens = ConcurrentHashMap<Long, OpenFuture>()
    internal val streams = ConcurrentHashMap<Long, Stream>()
    internal val nextStreamId = AtomicLong(1)
    private val lastPongMs = AtomicLong(0)
    // v0.9.2 (R6): адаптивный keepalive — время отправки последнего PING и RTT
    internal val lastPingSentAt = AtomicLong(0) // internal — зона health
    internal val lastRttMs = AtomicLong(0) // internal — зона health

    // ---- v0.10: пробник качества (тестирование скважности) ----
    // Постоянное тестирование связи: PING каждые ~5с + PROBE каждые 30с;
    // окно потерь 60с — данные для AutoBalancer (смена только по гистерезису).
    internal val pingResults = java.util.ArrayDeque<Pair<Long, Boolean>>() // internal — зона health
    @Volatile internal var rttEwmaMs: Long = 0
    @Volatile internal var lastProbeOk: Boolean? = null // internal — зона в RrpClientHealth.kt
    @Volatile internal var lastPingCounted = false // потерю этого пинга уже учли; internal — зона health
    @Volatile internal var lastProberTickMs = 0L // internal — зона health

    // ---- v1.8.0: end-to-end пробник полезной нагрузки (сквозной путь) ----
    @Volatile internal var lastE2e: Pair<Long, E2eProbe.Outcome>? = null // internal — зона в RrpClientHealth.kt
    @Volatile internal var lastE2eTickMs = 0L // internal — зона в RrpClientHealth.kt
    internal val e2eBusy = AtomicBoolean(false) // internal — зона health

    internal val pingExecutor: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "rrp-ping").apply { isDaemon = true } }
    internal val relayExecutor: ExecutorService =
        Executors.newCachedThreadPool { r -> Thread(r, "rrp-relay").apply { isDaemon = true } }
    // v1.3.0 «буфер трафика»: паркинг сокетов таргетов при потере транспорта.
    // Отдельный daemon-пул: переживает close() клиента (TTL-рипер).
    internal val parkExecutor: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "rrp-park").apply { isDaemon = true } }
    internal val parkedSockets = java.util.concurrent.ConcurrentHashMap<String, ParkedSock>()

    /** Припаркованный сокет таргета: живёт до реконнекта (OPEN_RESUME) или TTL. */
    class ParkedSock(val socket: Socket, val parkedAt: Long)

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

        // v1.8.4 ФИКС AUTO: пустой protoId — режим «лучший общий протокол»,
        // в HELLO уходит PREFERRED_AUTO (normalizeExecutable), а не normalize()
        // (который пустоту мапил в rrp1 — сервер честно даунгрейдил AUTO до
        // rrp1, и «авто не пробивался» там, где rrp1 режется ТСПУ).
        val helloProto = RrpProtocols.normalizeExecutable(protoId)
        val hello = RrpFrame.Hello(
            agent = agentName,
            protocolVersion = RrpFrame.VERSION,
            device = deviceName,
            caps = listOf("chacha20", "alpn", "stream-resume"),
            maxStreams = MAX_STREAMS_REQUEST,
            proto = helloProto,
            protocols = RrpProtocols.displayList(),
        )
        log(
            Msgs.SENT_HELLO.t(
                agentName, deviceName, RrpFrame.VERSION, helloProto,
                RrpProtocols.labelWithVer(helloProto), MAX_STREAMS_REQUEST, hello.encode().size,
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
            debug("SENT AUTH mode=$MODE_TOKEN_HMAC token6=${token.take(6)} nonce=${ok.nonce} hmac=${hmac.take(12)}… sessionId=$sessionId")
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
            scheduleProber() // v0.10: постоянный тест качества связи
            log("RECV READY tunnel=${rd.tunnelId} role=${rd.role} proto=${rd.proto} (${RrpProtocols.labelWithVer(rd.proto)}) protocols=${rd.protocols.joinToString(",") { RrpProtocols.labelWithVer(it) }} maxStreams=${rd.maxStreams} window=${rd.tunnelWindow} → State.READY")
            // v0.8.2: камуфляж «API Mask» — только если сервер подтвердил
            // возможность (features) и модуль включён манифестом
            flushPendingCamCtl() // v0.9.5: начальный выбор камуфляжа устройства
            if (apimaskSupported && noisePolicy != null) {
                debug(Msgs.APIMASK_ENABLED.t())
                scheduleNoise()
            }

            // v0.7.4: валидация «реального трафика» — PROBE до реального хоста.
            // Используется при смене протокола: коммит только после успеха.
            validateProbeTarget?.let { target ->
                debug(Msgs.PROBE_SENT.t(target, rd.proto))
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
                val f = RrpFrame.parse(input)
                // v1.8.4: TRACE — кадр за кадром (тип/размер) для диагностики протокола.
                trace("recv ${f.javaClass.simpleName} id=${f.streamId} type=0x%02X".format(f.type))
                dispatch(f)
            }
        } catch (e: Throwable) {
            if (state != State.READY && handshakeError == null) {
                handshakeError = RrpClientException(Msgs.HANDSHAKE_FAILED.t(e.message), e)
            } else if (running.get()) {
                log(Msgs.READER_STOPPED.t(e.message), LogKind.WARN)
            }
        } finally {
            helloLatch.countDown()
            readyLatch.countDown()
            close(parkLive = true)
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
            is RrpFrame.Auth -> debug(Msgs.AUTH_UNEXPECTED.t())
            is RrpFrame.Hello -> debug(Msgs.HELLO_UNEXPECTED.t())
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
            is RrpFrame.ResumeToken -> streams[frame.streamId]?.let { it.resumeToken = frame.token }
            is RrpFrame.OpenResume -> handleOpenResume(frame)
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
                    if (rtt in 1..300_000) {
                        lastRttMs.set(rtt)
                        // v0.10: EWMA RTT (0.25) — сглаживание для балансера
                        rttEwmaMs = if (rttEwmaMs == 0L) rtt else (rttEwmaMs * 3 + rtt) / 4
                    }
                }
                lastPingCounted = true
                recordPingResult(true)
            }
            is RrpFrame.Stats -> debug("STATS: ${frame.json}")
            is RrpFrame.ProbeResp -> {
                debug("RECV PROBE ok=${frame.ok} err=${frame.err} proto=${frame.proto}")
                probeResp = frame
            }
            is RrpFrame.ProbeReq -> debug(Msgs.PROBE_UNEXPECTED.t())
            is RrpFrame.KeyReq -> handleKeyReq(frame) // v0.8/v0.9.5: mtproto2 DH | wireguard WG_INIT
            is RrpFrame.KeyResp -> debug(Msgs.KEY_RESP_UNEXPECTED.t())
            is RrpFrame.BtResp -> finishBtHandshake(frame)
            is RrpFrame.BtInit -> debug(Msgs.BT_INIT_UNEXPECTED.t())
            is RrpFrame.ProtoSwitch -> handleProtoSwitchAck(frame)
            is RrpFrame.WgResp -> {
                // v0.9.5: WG msg2 — активируем клиентский транспорт WG-конвертов.
                // v0.9.6: дедлок-фикс — consume ЗДЕСЬ (reader-поток), а не в
                // handleWgKeyReq: он единственный доставщик этого кадра.
                debug(Msgs.WG_RESP_RECV.t(frame.raw.size))
                finishWgHandshake(frame)
            }
            is RrpFrame.WgInit -> debug(Msgs.WG_INIT_UNEXPECTED.t())
            is RrpFrame.Noise -> {
                // v0.8.2: ответ сервера на наш шум — байты считаются в общий
                // трафик (честно: это реальные байты мобильной сети),
                // но НЕ в «пакеты» пользовательских данных
                val n = frame.json.toByteArray(Charsets.UTF_8).size
                rxBytes.addAndGet(n.toLong())
                noiseRx.addAndGet(n.toLong())
            }
            is RrpFrame.CamCtl -> debug(Msgs.CAM_CTL_UNEXPECTED.t())
            is RrpFrame.ErrorFrame -> {
                log(Msgs.SERVER_ERROR_RAW.t(frame.code, frame.message, frame.rawHex()), LogKind.ERROR)
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

    /** Расшифровка DATA-конверта (в обычном режиме — без изменений). */
    /** Активный конверт: wireguard (v0.9.5) имеет приоритет, затем mtproto2. */
    internal fun activeMaxPlainData(): Int? = when {
        wgCrypto != null -> Wg.MAX_PLAIN_DATA
        btCrypto != null -> Torrent.MAX_PLAIN_DATA
        mtCrypto != null -> MtProto.SessionCrypto.MAX_PLAIN_DATA
        else -> null
    }

    internal fun encryptDown(bytes: ByteArray): ByteArray {
        wgCrypto?.let { return it.seal(bytes) }
        btCrypto?.let { return it.seal(bytes) }
        mtCrypto?.let { return it.encryptDown(bytes) }
        return bytes
    }

    private fun decryptUpEnvelope(payload: ByteArray): ByteArray {
        wgCrypto?.let { return it.open(payload) }
        btCrypto?.let { return it.open(payload) }
        mtCrypto?.let { return it.decryptUp(payload) }
        return payload
    }

    internal fun decryptPayload(frame: RrpFrame.Data): RrpFrame.Data? {
        if (mtCrypto == null && wgCrypto == null && btCrypto == null) return frame
        return try {
            RrpFrame.Data(frame.streamId, frame.flags, decryptUpEnvelope(frame.bytes))
        } catch (e: Exception) {
            log(Msgs.MTPROTO_DATA_ENVELOPE_BAD.t(frame.streamId, e.message), LogKind.ERROR)
            close()
            null
        }
    }

    /** Расшифровка UDP_DATA-конверта. */
    internal fun decryptUdpPayload(frame: RrpFrame.UdpData): RrpFrame.UdpData? {
        if (mtCrypto == null && wgCrypto == null && btCrypto == null) return frame
        return try {
            RrpFrame.UdpData(frame.streamId, frame.atyp, frame.addr, frame.port, decryptUpEnvelope(frame.bytes))
        } catch (e: Exception) {
            log(Msgs.MTPROTO_UDP_ENVELOPE_BAD.t(e.message), LogKind.ERROR)
            null
        }
    }

    /** v0.9.5: выбор камуфляжа устройством — кадр 0x2A немедленно (если READY). */
    fun sendCamCtl(enabled: Boolean) {
        pendingCamCtl = enabled
        if (state == State.READY) {
            debug(Msgs.CAM_CTL_SENT.t(if (enabled) "on" else "off"))
            sendFrame(RrpFrame.CamCtl(enabled))
        }
    }

    @Volatile var udpEnabled: Boolean = true

    /** S→C UDP_ASSOC: сервер просит поднять UDP-релей. Ответ — OPEN_OK c err_code. */
    internal class UdpAssoc(val id: Long) {
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

    // ------------------------------------------------------------------ frame IO

    internal fun sendFrame(frame: RrpFrame) {
        val out = wireOut ?: throw RrpClientException(Msgs.NO_CONNECTION.t())
        // v0.10: во время бесшовной смены протокола payload-кадры копятся
        // и уходят новым конвертом после завершения перехендшейка.
        when (frame) {
            is RrpFrame.Data, is RrpFrame.UdpData -> {
                // v1.8.3: backpressure — окно очереди паркинга; переполнение
                // ставит отправителя на паузу до снятия паркинга или смерти
                // сессии (канон «ноль потерь», дропа нет).
                if (switchParking.offer(frame) { running.get() && wireOut != null }) return
            }
            else -> {}
        }
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
                        log(Msgs.UDP_DATA_LIMIT.t(frame.bytes.size), LogKind.WARN)
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
                    log(Msgs.NOISE_GEN_FAILED.t(e.message), LogKind.WARN)
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
                    log(Msgs.NOISE_SEND_FAILED.t(e.message), LogKind.WARN)
                }
                scheduleNoise()
            }, policy.engine.nextDelayMs(), TimeUnit.MILLISECONDS)
        } catch (_: RejectedExecutionException) {
        }
    }

    internal fun sendFrameQuiet(frame: RrpFrame) {
        try {
            sendFrame(frame)
        } catch (e: Exception) {
            log(Msgs.SEND_FAILED.t(e.message), LogKind.ERROR)
        }
    }

    // ------------------------------------------------------------------ close

    fun close() = close(parkLive = false)

    /**
     * close(parkLive = true) — смерть транспорта (readerLoop): потоки с токеном
     * НЕ закрываются, сокеты паркуются (TCP-сессии с сайтами переживают блып,
     * сервер резюмит их OPEN_RESUME после реконнекта). parkLive=false —
     * явный stop пользователем: чистое закрытие всего.
     */
    fun close(parkLive: Boolean) {
        pendingSwitchTarget = null // v1.8.4: свитч не переживает смерть транспорта
        running.set(false)
        setState(State.CLOSED)
        helloLatch.countDown()
        readyLatch.countDown()
        try { pingExecutor.shutdownNow() } catch (_: Exception) {}
        try { relayExecutor.shutdownNow() } catch (_: Exception) {}
        // v1.8.3: очередь паркинга очищена, заблокированные отправители
        // (backpressure) выходят с ошибкой — сессия мертва.
        switchParking.close()
        if (parkLive) {
            streams.values.toList().forEach { st ->
                if (st.resumeToken != null && !st.parked.get()) {
                    st.parked.set(true)
                    parkSocket(st)
                }
            }
        }
        streams.values.forEach {
            it.closed.set(true)
            if (!(parkLive && it.parked.get())) closeQuietly(it.socket)
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

    /**
     * v1.8.4: уровень по умолчанию INFO (виден при стандартном minLevel).
     * Протокольные детали — DEBUG/TRACE, ошибки — WARN/ERROR: уровни задаются
     * на месте вызова; фильтрацию выполняет LogStore (minLevel из настроек).
     */
    internal fun log(message: String, kind: LogKind = LogKind.INFO) {
        listener?.onLog(this, message, kind)
    }

    /** Детали протокола (хендшейки, кадры) — видны при minLevel ≤ DEBUG. */
    internal fun debug(message: String) = log(message, LogKind.DEBUG)

    /** Протокольная трассировка (кадр за кадром) — видна при minLevel TRACE. */
    internal fun trace(message: String) = log(message, LogKind.TRACE)

    internal fun closeQuietly(c: Socket?) {
        try { c?.close() } catch (_: Exception) {}
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    companion object {
        const val DEFAULT_AGENT = "ReverseRay-Android/0.8.2"

        /** Последний увиденный срок действия серта сервера (для «О приложении», epoch мс). */
        @Volatile var lastServerCertNotAfterMs: Long = 0
            internal set

        const val KIND_TCP = "TCP"
        const val KIND_UDP = "UDP"

        /** Таймаут валидационного PROBE, мс (сервер клампит в 1..15 с). */
        const val PROBE_TIMEOUT_MS = 5_000L
        // v0.10: пробник качества (скважность) — тик/интервалы/окно
        const val MONITOR_TICK_MS = 5_000L
        const val PROBER_INTERVAL_MS = 30_000L
        const val PING_LOSS_AFTER_MS = 15_000L
        const val HEALTH_WINDOW_MS = 60_000L
        const val DEFAULT_PROBE_TARGET = "1.1.1.1:443"

        // v1.8.0: end-to-end пробник полезной нагрузки (сквозь DATA-кадры)
        const val E2E_INTERVAL_MS = 60_000L
        const val E2E_STALE_MS = 3 * E2E_INTERVAL_MS
        const val E2E_DEFAULT_TARGET = "connectivitycheck.gstatic.com:80"
        /** Маленький запрос-ответ: generate_204 (ответ — только заголовок). */
        val E2E_REQUEST = (
            "GET /generate_204 HTTP/1.1\r\n" +
                "Host: connectivitycheck.gstatic.com\r\n" +
                "User-Agent: rrp-e2e\r\n" +
                "Connection: close\r\n\r\n"
            ).toByteArray()
        const val E2E_MARKER = " 204"

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

        /**
         * v1.8.1: id стримов, инициируемых телефоном, — ЧЁТНЫЕ; сервер занимает
         * НЕЧЁТНЫЕ (session.openStream: nextID += 2 «odd ids are
         * server-originated»). Умножение счётчика на 2 разводит пространства
         * без коллизий (маска u32 — переполнение безопасно заворачивается).
         */
        internal fun phoneStreamId(seq: Long): Long = (seq * 2) and 0xFFFFFFFFL

        /** Окно flow-control по умолчанию: 512 КБ на стрим. */
        const val DEFAULT_TUNNEL_WINDOW = 512 * 1024L

        // v1.8.3: окно очереди паркинга смены протокола (backpressure,
        // канон v1.3.0 «буфер в RAM без дропов»). Env-override по образцу
        // окон flow-control: RR_PARKED_FRAMES_MAX (16..4096).
        const val DEFAULT_PARKED_FRAMES_MAX = 256

        internal fun resolveParkedFramesMax(): Int =
            System.getenv("RR_PARKED_FRAMES_MAX")?.toIntOrNull()
                ?.coerceIn(16, 4096) ?: DEFAULT_PARKED_FRAMES_MAX

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
        const val ERR_NO_PARKED = 5 // v1.3.0: OPEN_RESUME — сокет уже не дожил

        /** v1.3.0: такт pump (пробуждение для проверки parked/running). */
        const val PUMP_POLL_MS = 250
        /** v1.3.0: TTL припаркованного сокета (сек) — синхронизировано с сервером. */
        const val STREAM_PARK_MS = 30_000L
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
