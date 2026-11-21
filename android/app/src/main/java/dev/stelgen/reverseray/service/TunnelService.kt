package dev.stelgen.reverseray.service

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import dev.stelgen.reverseray.MainActivity
import dev.stelgen.reverseray.L10nUi
import dev.stelgen.reverseray.R
import dev.stelgen.reverseray.core.Apimask
import dev.stelgen.reverseray.core.AutoBalancer
import dev.stelgen.reverseray.core.ProtoRotator
import dev.stelgen.reverseray.core.ConnectionManager
import dev.stelgen.reverseray.core.ConfigResult
import dev.stelgen.reverseray.core.ConfigSource
import dev.stelgen.reverseray.core.LogStore
import dev.stelgen.reverseray.core.SessionStore
import dev.stelgen.reverseray.core.Msgs
import dev.stelgen.reverseray.core.Negotiation
import dev.stelgen.reverseray.core.ProtoFallback
import dev.stelgen.reverseray.core.ProtocolState
import dev.stelgen.reverseray.core.RrpAuthException
import dev.stelgen.reverseray.core.RrpClient
import dev.stelgen.reverseray.core.switchProto // v1.8.10: зона свитча вынесена в core/RrpClientSwitch.kt (extension)
import dev.stelgen.reverseray.core.healthSample // v1.8.10: зона health вынесена в core/RrpClientHealth.kt (extension)
import dev.stelgen.reverseray.core.RrpProtocols
import dev.stelgen.reverseray.core.RrpUri
import dev.stelgen.reverseray.core.RrpUriConfig
import dev.stelgen.reverseray.ui.Formats
import java.net.NetworkInterface
import dev.stelgen.reverseray.net.SpeedTest
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.Random
import java.util.concurrent.atomic.AtomicLong

/**
 * Foreground-сервис: держит пул RrpClient (по одному на порт из конфига).
 *
 * - уведомления: channels на 26+, просто Notification на старых;
 * - сеть: NetworkCallback на 21+, CONNECTIVITY_ACTION — фолбэк для <21;
 * - при появлении сети — мгновенный retry всех коннектов с cooldown 3 c;
 * - экспоненциальный backoff 1→60 c ±30 % (RrpClient.backoffDelayMs);
 *
 * v0.8:
 * - ЛИМИТ ТРАФИКА — КОРОЛЬ: при исчерпании отправляется РОВНО НОЛЬ байт
 *   (туннель останавливается, все кадры затыкаются), на экране — сообщение
 *   и отдельное окно при нажатии Старт/Реконнект; счётчик живёт в RAM и
 *   пишется на память РЕДКО (раз в минуту — дисциплина SSD/памяти);
 * - автоподключение (по умолчанию выкл): при достигнутом лимите ждём
 *   даты сброса и переподключаемся только после него;
 * - спидтест 5 с после CONNECTED — только если лимит не достигнут;
 * - счётчик трафика за всё время (KEY_TRAFFIC_LIFETIME) — запись раз в минуту;
 * - журнал статуса с цветовыми ролями (зелёный/красный/тёмно-жёлтый/белый)
 *   для единого консольного окна на всех вкладках.
 *
 * v0.7.4:
 * - СМЕНА ПРОТОКОЛА с валидацией реального трафика (PROBE до реального хоста):
 *   provisional-коннект с новым протоколом → PROBE → коммит (запись ссылки
 *   и протокола) только после успеха; при неудаче — мгновенный откат UI
 *   и остаёмся на последнем рабочем протоколе. Анти-цикл: 3 ретрая с паузой,
 *   cooldown 60 с между сменами, ссылка не трогается до валидации.
 * - ЛИМИТ ТРАФИКА (по умолчанию без ограничений): сумма вход+выход за период
 *   (сутки/календарный месяц с днём сброса); превышение → туннель останавливается.
 * - ТОЛЬКО WI-FI: не поднимать туннель в мобильной сети, стартовать при появлении Wi-Fi.
 * - ЛОГИ НАСТРОЕК: изменённые настройки попадают в статус-лог только при
 *   фактическом изменении значения.
 * - Счётчики пакетов/последний размер для строки «стрелки» на главном экране.
 */
/** Цветовая роль строки журнала — в едином лог-центре LogStore (v0.9.6). */
typealias LogKind = dev.stelgen.reverseray.core.LogKind

/**
 * v1.8.6: имя протокола/режима для статусов и UI БЕЗ пояснений (канон «как
 * WS»): AUTO/ROTATE — постоянные метки, остальное — короткое имя протокола.
 * Файловая (чистая, без состояния сервиса) — общий клиент и сервис без дублей.
 */
internal fun protoDisplayName(id: String): String = when {
    id == TunnelService.PROTO_AUTO || id.isBlank() -> ProtocolState.AUTO
    id == TunnelService.PROTO_ROTATE -> ProtocolState.ROTATE
    else -> RrpProtocols.label(id)
}

class TunnelService : Service() {

    // v0.8.3: язык сервиса/уведомлений из prefs (канон i18n)
    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(L10nUi.wrap(base))
    }

    internal class Target(val host: String, val port: Int)

    @Volatile internal var lifetime: AtomicLong = AtomicLong(0)

    internal inner class Runner(val target: Target) {
        /** Сессия (профиль), к которой принадлежит раннер (v1.5.0). */
        internal var sess: Sess? = null
        @Volatile internal var kick = false
        /** v0.9.2: раннер выведен из эксплуатации (смена протокола) — поток
         * runLoop обязан завершиться, а не пересоздать коннект (иначе
         * двойные коннекты: старый+новый набор на один порт). */
        @Volatile internal var retired = false
        /** активный клиент — для форс-закрытия при stopTunnel (иначе стоп ждёт handshake-таймаут до 20с) */
        @Volatile internal var client: RrpClient? = null
    }

    internal val runners = mutableListOf<Runner>()

    // ---------- v1.5.0 «Multi-Server Core»: профили/сессии ----------

    /** Хранилище профилей (миграция v1.3→v1.5 — в onCreate). */
    internal lateinit var sessionStore: SessionStore

    /** Менеджер N сессий (живёт пока туннель поднят). */
    @Volatile internal var manager: ConnectionManager? = null

    /** Сессия сервиса: профиль + точка агрегации состояния. */
    internal inner class Sess(val id: String, val profile: SessionStore.Profile)

    internal val sessById = java.util.concurrent.ConcurrentHashMap<String, Sess>()

    /** Сессия, занятая валидационной сменой протокола (gate только для неё). */
    @Volatile internal var switchingSessionId: String? = null

    // v1.0.2 (мультипоточность): состояние каждого раннера (ключ = sessId|порт)
    internal val sessionStates = java.util.concurrent.ConcurrentHashMap<String, String>()
    internal val runnerStateKey = ThreadLocal<String>()
    internal val rnd = Random()
    internal val lastNetKick = AtomicLong(0)
    @Volatile internal var statsThread: Thread? = null
    internal var lastTx = 0L
    internal var lastRx = 0L

    @Volatile internal var stopping = true
    internal var wakeLock: PowerManager.WakeLock? = null
    /** v0.9.6: Wi-Fi-lock — радио не засыпает в фоне (Android 4+, из коробки). */
    internal var wifiLock: android.net.wifi.WifiManager.WifiLock? = null
    internal var networkCallback: ConnectivityManager.NetworkCallback? = null
    internal var legacyReceiver: BroadcastReceiver? = null

    /** Идёт ли сейчас валидационная смена протокола. */
    @Volatile internal var switchingProto = false

    // ---------- v1.8.0: режим «Ротация» (альтернатива авто-режиму) ----------
    /** Пер-сессионные ротаторы (расписание у каждого своё). */
    internal val rotators = java.util.concurrent.ConcurrentHashMap<String, ProtoRotator>()
    internal val rotateExecutor: java.util.concurrent.ScheduledExecutorService =
        java.util.concurrent.Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "rrp-rotate").apply { isDaemon = true }
        }
    internal var rotateTask: java.util.concurrent.ScheduledFuture<*>? = null

    // ---------- v1.5.0: балансер пер-сессионный (в ConnectionManager);
    // решение балансера исполняет sessionOwner.onBalancerSwitch (ниже).

    /**
     * Бесшовная смена протокола в живых раннерах ОДНОЙ сессии (кадр 0x2C —
     * согласование без разрыва связи). Ссылка НЕ меняется (AUTO остаётся AUTO —
     * сервер переговорит при реконнекте сам). false — хоть один раннер отказал.
     */
    internal fun switchProtoLiveOf(sess: Sess, target: String): Boolean {
        var all = true
        val list = synchronized(runners) { runners.filter { it.sess === sess } }
        for (r in list) {
            val c = r.client
            if (c == null) {
                all = false
                continue
            }
            try {
                if (c.state == RrpClient.State.READY && !c.switchProto(target)) all = false
            } catch (_: Exception) {
                all = false
            }
        }
        return all
    }

    /** Сессия-владелец для менеджера: создаёт воркеры, принимает события. */
    internal val sessionOwner = object : ConnectionManager.Owner {
        override fun createWorker(
            profile: SessionStore.Profile,
            sessionId: String,
        ): ConnectionManager.Worker {
            val sess = Sess(sessionId, profile)
            sessById[sessionId] = sess
            return SessionWorker(sess)
        }

        override fun onSessionLog(session: ConnectionManager.Session, message: String, kind: LogKind) {
            // v1.5.0: строка с тегом сессии + структурный тег для фильтра LOG
            pushLog("[${session.profile.name}] $message", kind, session = session.profile.name)
        }

        override fun onSessionState(session: ConnectionManager.Session, state: String) {
            sendBroadcast(
                Intent(ACTION_STATUS).setPackage(packageName)
                    .putExtra(EXTRA_STATE, state)
                    .putExtra(EXTRA_STATUS, session.stateText.ifBlank { state })
                    .putExtra(EXTRA_SESSION_ID, session.id)
                    .putExtra(EXTRA_PROFILE_NAME, session.profile.name),
            )
            // дедлайн-обновление уведомления: постатрочное состояние сессий
            try {
                (applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                    .notify(NOTIF_ID, buildNotification(lastStatus))
            } catch (_: Exception) {
            }
        }

        override fun onSessionStats(session: ConnectionManager.Session, rxRate: Long, txRate: Long) {
            // поля Session обновлены менеджером; сервис читает их в своём stats-лупе
        }

        override fun onBalancerSwitch(session: ConnectionManager.Session, target: String, reason: String) {
            pushLog(
                Msgs.BAL_DEGRADED.t(
                    reason, RrpProtocols.labelWithVer(session.balancer.current),
                    RrpProtocols.labelWithVer(target),
                ),
            )
            val ok = switchProtoLiveOf(sessById[session.id] ?: return, target)
            session.balancer.onSwitchResult(System.currentTimeMillis(), target, ok)
            if (ok) {
                val msg = getString(R.string.status_switch_done, RrpProtocols.labelWithVer(target))
                sendBroadcast(
                    Intent(ACTION_STATUS).setPackage(packageName)
                        .putExtra(EXTRA_STATE, STATE_CONNECTED)
                        .putExtra(EXTRA_STATUS, msg)
                        .putExtra(EXTRA_PROTO, target)
                        .putExtra(EXTRA_SESSION_ID, session.id)
                        .putExtra(EXTRA_PROFILE_NAME, session.profile.name),
                )
            } else {
                pushLog(
                    Msgs.BAL_FAIL_MARKED.t(
                        RrpProtocols.labelWithVer(target),
                        session.balancer.cooldownLeftSec(System.currentTimeMillis()),
                    ),
                )
            }
        }
    }

    /** Сетевой воркер одной сессии: раннеры по портам профиля (изолированно). */
    private inner class SessionWorker(private val sess: Sess) : ConnectionManager.Worker {
        override fun start() {
            spawnRunnersFor(sess)
        }

        override fun stop() {
            killRunnersOf(sess)
        }

        override fun kick() {
            synchronized(runners) { runners.forEach { if (it.sess === sess) it.kick = true } }
            if (runnersOf(sess).isEmpty() && !stopping) spawnRunnersFor(sess)
        }

        override fun bytesSnapshot(): Pair<Long, Long> {
            var tx = 0L
            var rx = 0L
            synchronized(runners) {
                runners.forEach { r ->
                    if (r.sess !== sess) return@forEach
                    r.client?.bytesSnapshot()?.let { (a, b) -> tx += a; rx += b }
                }
            }
            return tx to rx
        }

        override fun healthSample(): AutoBalancer.Sample? = firstClientOf(sess)?.healthSample()

        override fun negotiatedProto(): String = firstClientOf(sess)?.negotiatedProto ?: ""

        override fun serverProtocols(): List<String> = firstClientOf(sess)?.serverProtocols ?: emptyList()

        override fun switchProto(target: String): Boolean = switchProtoLiveOf(sess, target)

        override fun isRunning(): Boolean = runnersOf(sess).isNotEmpty()

        // v1.8.0: ротация и авто — взаимоисключающие режимы выбора:
        // при включённой ротации пер-сессионный балансер не стартует.
        override fun autoBalance(): Boolean = claimedOf(sess.profile.uri).isBlank() && !rotationEnabled()
    }
    /** Спидтест не молотит при каждом READY. */
    @Volatile private var speedTestBusy = false
    /** Ждун сброса лимита для авто-переподключения. */
    @Volatile internal var limitWaitThread: Thread? = null

    internal val clientListener = object : RrpClient.Listener {
        /** Сессия, владеющая клиентом (v1.5.0: тегирование логов per-сессия). */
        private fun sessOf(client: RrpClient): Sess? =
            synchronized(runners) { runners.firstOrNull { it.client === client }?.sess }

        override fun onLog(client: RrpClient, message: String, kind: LogKind) {
            Log.d(TAG, "${client.host}:${client.port}: $message")
            val sess = sessOf(client)
            if (sess != null) {
                manager?.workerLog(sess.id, "${client.host}:${client.port}: $message", kind)
                    ?: pushLog("[${sess.profile.name}] ${client.host}:${client.port}: $message", kind)
            } else {
                pushLog("${client.host}:${client.port}: $message", kind)
            }
        }

        // v0.9.0: пин из ссылки не совпал — UI предлагает владельцу ЯВНО
        // принять новый пин (анти-MITM канон: молча не доверяем никогда)
        override fun onPinMismatch(client: RrpClient, realPin: String) {
            sendBroadcast(
                Intent(ACTION_STATUS).setPackage(packageName)
                    .putExtra(EXTRA_STATE, STATE_PIN_MISMATCH)
                    .putExtra(EXTRA_STATUS, getString(R.string.pin_mismatch_status))
                    .putExtra(EXTRA_REAL_PIN, realPin)
            )
        }

        override fun onState(client: RrpClient, state: RrpClient.State) {
            if (state == RrpClient.State.READY) {
                val sess = sessOf(client)
                if (client.mtProtoActive) {
                    pushLog(getString(R.string.log_mtp_keys), LogKind.OK)
                }
                lastNegotiatedProto = client.negotiatedProto
                syncProtoState()
                sendBroadcast(
                    Intent(ACTION_STATUS).setPackage(packageName)
                        .putExtra(EXTRA_STATUS, client.negotiatedProto)
                        .putExtra(EXTRA_STATE, STATE_PROTO)
                        .putExtra(EXTRA_PROTO, client.negotiatedProto)
                        .apply {
                            sess?.let {
                                putExtra(EXTRA_SESSION_ID, it.id)
                                putExtra(EXTRA_PROFILE_NAME, it.profile.name)
                            }
                        }
                )
                maybeRunSpeedTest()
            }
        }
    }

    /** Спидтест 5 с — ровно один раз на сессию, ТОЛЬКО если лимит не достигнут.
     *  v0.8.1: честно показываем ВСЕ внешние хосты (HTTP-проверка, TCP-пинг,
     *  скачивание) — канон «куда пошли — обо всём признаёмся». */
    private fun maybeRunSpeedTest() {
        if (stopping) return
        val usage = accountTraffic(0)
        if (usage.limit > 0 && usage.used >= usage.limit) {
            pushLog(getString(R.string.log_speedtest_skipped), LogKind.WARN)
            return
        }
        if (speedTestBusy) return
        speedTestBusy = true
        pushLog(getString(R.string.log_speedtest_plan, SpeedTest.plan().joinToString(" · ")))
        Thread {
            val r = SpeedTest.run()
                val line = if (r.ok) {
                val mbs = String.format(Locale.US, "%.1f", r.bytesPerSec / 1024.0 / 1024.0)
                getString(
                    R.string.log_speedtest_result,
                    mbs, r.pingMs,
                    if (r.httpOk) getString(R.string.speed_http_ok, r.httpMs) else getString(R.string.speed_http_down),
                    fmtBytes(r.totalBytes), r.durationMs / 1000,
                )
            } else {
                getString(R.string.log_speedtest_failed, r.error ?: getString(R.string.speed_no_data))
            }
            pushLog(line, if (r.ok) LogKind.OK else LogKind.WARN)
            // v1.0.0: карточке — своя строка БЕЗ префикса «speed test:»
            // (было «Speed test: speed test: 15.26 MB/s …» — дубль слов)
            val cardLine = if (r.ok) {
                val mbsCard = String.format(Locale.US, "%.1f", r.bytesPerSec / 1024.0 / 1024.0)
                getString(
                    R.string.speedtest_card,
                    mbsCard, r.pingMs,
                    if (r.httpOk) getString(R.string.speed_http_ok, r.httpMs) else getString(R.string.speed_http_down),
                )
            } else {
                getString(R.string.speedtest_failed_short, r.error ?: getString(R.string.speed_no_data))
            }
            sendBroadcast(
                Intent(ACTION_STATS).setPackage(packageName)
                    .putExtra(EXTRA_SPEEDTEST_TEXT, cardLine)
            )
            speedTestBusy = false
        }.apply { isDaemon = true }.start()
    }

    // v0.8.3: единицы из ресурсов (динамический язык) — общий Formats (дубль удалён)
    internal fun fmtBytes(b: Long): String = Formats.bytes(this, b)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
        ensureStore()
        lifetime = AtomicLong(prefs().getLong(KEY_TRAFFIC_LIFETIME, 0L))
        applyLogMinLevel(prefs())
    }

    /** Ленивая инициализация SessionStore + ОДНОРАЗОВАЯ миграция v1.3→v1.5. */
    internal fun ensureStore() {
        if (!::sessionStore.isInitialized) {
            sessionStore = SessionStore(PrefsBackend(prefs()))
            val migrated = sessionStore.migrateLegacy(prefs().getString(KEY_CONFIG, null))
            if (migrated != null) {
                pushLog(Msgs.SESSION_MIGRATED.t(migrated.name), LogKind.OK)
            }
        }
    }

    /** Профиль по id (или null). */
    internal fun profileById(id: String?): SessionStore.Profile? =
        if (::sessionStore.isInitialized) sessionStore.byId(id) else null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_SWITCH_PROTO -> {
                // v1.8.0: "rotate" перехватываем ДО normalize (normalize свёл бы
                // неизвестный id к rrp1) — это режим выбора, не протокол.
                val rawProto = intent.getStringExtra(EXTRA_PROTO) ?: ""
                val p = if (rawProto == PROTO_ROTATE) PROTO_ROTATE else RrpProtocols.normalize(rawProto)
                startForegroundCompat(getString(R.string.notif_starting))
                Thread({ switchProtocol(p) }, "rrp-switch").start()
                return START_STICKY
            }
            ACTION_CAMO -> {
                // v0.9.5: выбор камуфляжа из GUI — персистентно + кадр 0x2A
                // живой сессии; работает и когда клиент «не подключен»
                // (применится будущей сессией — сервер помнит выбор).
                val enabled = intent.getBooleanExtra(EXTRA_ENABLED, true)
                Thread({ applyCamouflage(enabled) { msg -> updateStatus(STATE_INFO, msg) } }, "rrp-camo").start()
                return START_STICKY
            }
            ACTION_UDP -> {
                // v1.0.0: гейт UDP-релея галочкой владельца — живая сессия тоже
                // (клиент отклоняет новые UDP_ASSOC немедленно)
                val enabled = intent.getBooleanExtra(EXTRA_ENABLED, true)
                prefs().edit().putBoolean(KEY_UDP_ENABLED, enabled).apply()
                runners.forEach { r -> r.client?.udpEnabled = enabled }
                pushLog(
                    getString(if (enabled) R.string.log_udp_on else R.string.log_udp_off),
                    LogKind.INFO,
                )
                return START_STICKY
            }
            ACTION_SESSION -> {
                // v1.5.0: управление ОДНОЙ сессией из дашборда/настроек
                ensureStore()
                val id = intent.getStringExtra(EXTRA_SESSION_ID)
                val cmd = intent.getStringExtra(EXTRA_SESSION_CMD) ?: ""
                if (id != null) Thread({ handleSessionCommand(id, cmd) }, "rrp-sess").start()
                return START_STICKY
            }
            ACTION_ACCEPT_PIN -> {
                // v0.9.0: владелец ЯВНО принял новый пин CA — обновляем ссылку,
                // пишем в журнал и реконнектим. Никакого молчаливого доверия.
                ensureStore()
                val newPin = intent.getStringExtra(EXTRA_REAL_PIN)
                // v1.8.4: резолв через единый ConfigSource (профиль → зеркало)
                val link = (resolvedConfig() as? ConfigResult.Valid)?.cfg?.serialize()
                val updated = newPin?.let { RrpUri.replacePin(link ?: "", it) }
                if (updated != null) {
                    // v1.5.0: пин обновляется в URI PRIMARY-профиля + зеркало
                    commitPrimaryUri(updated)
                    pushLog(Msgs.PIN_ACCEPTED.t(newPin), LogKind.WARN)
                    startTunnel()
                } else {
                    pushLog(Msgs.SEND_FAILED.t("pin update failed"), LogKind.ERROR)
                }
                return START_STICKY
            }
            else -> startTunnel()
        }
        return START_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // v0.9.6: свёртка приложения из recents НЕ глушит туннель —
        // foreground-сервис продолжает работать (START_STICKY), лог честный.
        pushLog(Msgs.TASK_REMOVED_STILL_RUNNING.t(), LogKind.INFO)
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    // ---------- туннель ----------

    internal fun startTunnel() {
        ensureStore()
        startRotateTick() // v1.8.0: тик ротации живёт всё время работы туннеля
        if (!stopping && sessById.isNotEmpty()) {
            updateStatus(STATE_INFO, getString(R.string.status_already_running))
            return
        }
        // v1.5.0: набор сессий = PRIMARY (всегда — главная кнопка/BootReceiver)
        // + включённые профили; guardrail — максимум MAX_SESSIONS одновременных.
        val primary = sessionStore.active()
        val wanted = LinkedHashMap<String, SessionStore.Profile>()
        primary?.let { wanted[it.id] = it }
        for (p in sessionStore.profiles()) {
            if (p.enabled && p.id != primary?.id) wanted[p.id] = p
        }
        val capped = wanted.values.take(ConnectionManager.MAX_SESSIONS)
        if (capped.isEmpty()) {
            updateStatus(STATE_ERROR, getString(R.string.status_no_config))
            stopSelf()
            return
        }
        stopping = false
        startForegroundCompat(getString(R.string.notif_starting))
        acquireWakeLock()
        // преамбула устройства — по PRIMARY (канон одной строки на старт)
        try {
            val pcfg = RrpUri.parse(capped.first().uri)
            logDevicePreamble(pcfg)
        } catch (_: Exception) {}

        // v0.7.4: «только по Wi-Fi» — в мобильной сети туннель не поднимаем;
        // NetworkCallback дёрнет kickAll при появлении Wi-Fi.
        if (wifiOnly() && !isOnWifi()) {
            updateStatus(STATE_INFO, getString(R.string.status_wait_wifi))
            registerNetworkWatching()
            startStatsLoop()
            return
        }

        manager = ConnectionManager(sessionOwner)
        for (p in capped) startSession(p)
        registerNetworkWatching()
        startStatsLoop()
        // v1.5.0: балансер пер-сессионный (ConnectionManager тикает AUTO-сессии)
        val pHost = try { RrpUri.parse(capped.first().uri).host } catch (_: Exception) { "" }
        updateStatus(STATE_CONNECTING, getString(R.string.status_connecting, pHost))
    }

    /** Информация об устройстве — в журнал простым текстом (одна строка на старт). */
    private fun logDevicePreamble(cfg: RrpUriConfig) {
        try {
            val info = getString(
                R.string.log_device_info,
                Build.MANUFACTURER, Build.MODEL, Build.VERSION.RELEASE, Build.VERSION.SDK_INT,
                Build.DISPLAY, currentProto(), cfg.host, cfg.ports.joinToString(","),
            )
            pushLog(info)
        } catch (_: Exception) {}
    }

    // ---------- смена протокола (валидация → коммит, иначе откат) ----------

    internal fun stopTunnel() {
        stopping = true
        stopRotateTick() // v1.8.0: ротация не переживает остановку туннеля
        // v1.5.0: все сессии через менеджер (каждая — изолированный stop)
        manager?.stopAll()
        manager = null
        sessById.clear()
        val active: List<Runner>
        synchronized(runners) {
            active = runners.toList()
            runners.clear()
        }
        active.forEach {
            it.kick = true
            try { it.client?.close() } catch (_: Exception) {}
        }
        statsThread?.interrupt()
        statsThread = null
        limitWaitThread?.interrupt()
        limitWaitThread = null
        unregisterNetworkWatching()
        releaseWakeLock()
        persistUsageSafely()
        // v1.8.6: сессии нет — согласованного протокола нет; читатели видят
        // заявленный из ссылки (или AUTO), а не хвост прошлой сессии.
        lastNegotiatedProto = ""
        syncProtoState()
        updateStatus(STATE_STOPPED, getString(R.string.status_stopped))
    }

    private fun persistUsageSafely() {
        try { persistUsage() } catch (_: Exception) {}
    }

    // ---------- сеть ----------

    // ---------- статус ----------

    /** Приоритет агрегата статусов: PIN > LIMIT > CONNECTED > CONNECTING > ERROR. */
    private fun aggregateStates(states: Collection<String>, fallback: String): String = when {
        states.isEmpty() -> fallback
        states.any { it == STATE_PIN_MISMATCH } -> STATE_PIN_MISMATCH
        states.any { it == STATE_LIMIT_REACHED } -> STATE_LIMIT_REACHED
        states.any { it == STATE_CONNECTED || it == STATE_PROTO } -> STATE_CONNECTED
        states.any { it == STATE_CONNECTING || it == STATE_RETRY || it == STATE_PROTO_ROLLBACK } -> STATE_CONNECTING
        states.any { it == STATE_ERROR } -> STATE_ERROR
        else -> fallback
    }

    /**
     * v1.8.6: синхронизация ProtocolState — ЕДИНОГО источника «текущий
     * протокол» для всех вкладок/логов. Вызывается на каждом статусе и после
     * каждой записи ссылки; UI и логи только читают (никакой разношерсти).
     */
    internal fun syncProtoState() {
        ProtocolState.sync(prefs().getString(KEY_CONFIG, "") ?: "", prefs().getBoolean(KEY_PROTO_ROTATE, false))
        ProtocolState.update(negotiated = lastNegotiatedProto)
    }

    internal fun updateStatus(state: String, text: String) {
        lastStatus = text
        // v0.9.2 (R3): источник истины для UI — сервис (переживает recreate).
        // v1.5.0 (Multi-Server Core): агрегат ДВУХ уровней — внутри сессии
        // (по портам) и глобальный (по сессиям менеджера). Кнопка/уведомление
        // не дёргаются разнобоем; события сессий уходят с sessionId/name.
        val key = runnerStateKey.get()
        var sessAgg: String? = null
        if (key != null) {
            sessionStates[key] = state
            val sessId = key.substringBefore('|')
            sessAgg = aggregateStates(sessionStates.filterKeys { it.startsWith("$sessId|") }.values, state)
            manager?.workerState(sessId, sessAgg, text, "")
        }
        val mgr = manager
        val agg = if (key == null || mgr == null || mgr.count() <= 1) {
            sessAgg ?: state
        } else {
            aggregateStates(mgr.all().map { it.state }, state)
        }
        lastState = agg
        // v1.8.6: единый источник «текущий протокол» синхронизируется на
        // КАЖДЫЙ статус (сервис — единственный писатель, UI — только читатели).
        syncProtoState()
        // цветовая роль по состоянию (канон единого консольного окна v0.8)
        val kind = when (state) {
            STATE_CONNECTED, STATE_PROTO -> LogKind.OK
            STATE_ERROR, STATE_STOPPED, STATE_LIMIT_REACHED -> LogKind.ERROR
            STATE_CONNECTING, STATE_RETRY -> LogKind.WARN
            else -> LogKind.INFO
        }
        pushLog(text, kind)
        sendBroadcast(
            Intent(ACTION_STATUS)
                .setPackage(packageName)
                .putExtra(EXTRA_STATUS, text)
                .putExtra(EXTRA_STATE, agg)
                .apply {
                    if (key != null) {
                        putExtra(EXTRA_SESSION_ID, key.substringBefore('|'))
                        profileById(key.substringBefore('|'))?.let {
                            putExtra(EXTRA_PROFILE_NAME, it.name)
                        }
                    }
                }
        )
        try {
            (applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .notify(NOTIF_ID, buildNotification(text))
        } catch (_: Exception) {
        }
    }

    internal fun prefs(): SharedPreferences = getSharedPreferences(PREFS, MODE_PRIVATE)

    internal fun allowLan(): Boolean = prefs().getBoolean(KEY_ALLOW_LAN, false)

    companion object {
        internal const val TAG = "ReverseRay"

        const val PREFS = "reverseray"
        const val KEY_CONFIG = "config"
        const val KEY_AUTOSTART = "autostart"
        const val KEY_ALLOW_LAN = "allow_lan"

        // v0.7.4: протокол и лимит трафика
        const val KEY_PROTO = "proto"
        const val KEY_TRAFFIC_LIMIT = "traffic_limit"      // байт; 0 = без лимита
        const val KEY_LIMIT_PERIOD = "limit_period"        // PERIOD_DAY | PERIOD_MONTH
        const val KEY_LIMIT_RESET_DAY = "limit_reset_day"  // 1..28 (для месяца)
        const val KEY_TRAFFIC_USED = "traffic_used"        // израсходовано за период
        const val KEY_USAGE_PERIOD = "usage_period"        // ключ периода ("2026-10-08")
        const val KEY_WIFI_ONLY = "wifi_only"

        /** v1.8.4: минимальный уровень журнала (идентификатор LogKind). */
        const val KEY_LOG_MIN_LEVEL = "log_min_level"
        const val KEY_PROBE_TARGET = "probe_target"
        const val KEY_AUTO_UPDATE = "auto_update"          // проверка обновлений раз в 24 ч
        const val KEY_THEME = "theme"                      // v0.8.1: auto|dark|light
        // v0.8:
        /** v0.9.5: сентинел режима AUTO (ссылка без proto=). */
        const val PROTO_AUTO = "auto"

        // v1.8.0: режим «Ротация» (пикер) — альтернатива AUTO, взаимоисключающая
        const val PROTO_ROTATE = "rotate"
        /** Канон ротации: смена каждые 30 минут (строгий round-robin). */
        const val ROTATE_INTERVAL_MS = 30 * 60 * 1000L
        /** Тик проверки расписания ротации. */
        const val ROTATE_TICK_MS = 30_000L
        /** Персистентный флаг режима ротации (prefs; ссылка — источник правды протокола). */
        const val KEY_PROTO_ROTATE = "proto_rotate"

        const val KEY_AUTO_RECONNECT = "auto_reconnect"    // автоподключение при открытии + ожидание сброса лимита (выкл по умолчанию)
        // v0.9.5: выбор камуфляжа «API Mask» КЛИЕНТОМ (персистентно и локально,
        // и на сервере через кадр 0x2A — переживает офлайн).
        const val KEY_CAMO_OFF = "camouflage_off"
        const val KEY_UDP_ENABLED = "udp_enabled" // v1.0.0: по умолчанию ВКЛ
        const val KEY_TRAFFIC_LIFETIME = "traffic_lifetime" // суммарный трафик за всё время
        const val PERIOD_DAY = "day"
        const val PERIOD_MONTH = "month"
        const val DEFAULT_PROBE_TARGET = "1.1.1.1:443"

        const val STATE_CONNECTING = "CONNECTING"
        const val STATE_CONNECTED = "CONNECTED"
        const val STATE_RETRY = "RETRY"
        const val STATE_ERROR = "ERROR"
        const val STATE_STOPPED = "STOPPED"
        const val STATE_INFO = "INFO"
        const val STATE_PROTO = "PROTO"
        const val STATE_PROTO_ROLLBACK = "PROTO_ROLLBACK"
        const val STATE_LIMIT_REACHED = "LIMIT_REACHED" // v0.8: лимит — отдельное важное состояние
        const val STATE_PIN_MISMATCH = "PIN_MISMATCH" // v0.9.0: ротация CA — явное подтверждение владельца
        const val EXTRA_REAL_PIN = "real_pin" // v0.9.0: фактический пин сервера (base64url канона ссылки)
        const val ACTION_ACCEPT_PIN = "dev.stelgen.reverseray.action.ACCEPT_PIN" // v0.9.0

        const val EXTRA_STATE = "state"

        const val ACTION_START = "dev.stelgen.reverseray.action.START"
        const val ACTION_STOP = "dev.stelgen.reverseray.action.STOP"
        const val ACTION_STATUS = "dev.stelgen.reverseray.action.STATUS"
        const val ACTION_STATS = "dev.stelgen.reverseray.action.STATS"
        const val ACTION_SWITCH_PROTO = "dev.stelgen.reverseray.action.SWITCH_PROTO"

        /** v0.9.5: управление камуфляжем «API Mask» из GUI (кадр 0x2A + pref). */
        const val ACTION_CAMO = "dev.stelgen.reverseray.action.CAMO"
        const val ACTION_UDP = "dev.stelgen.reverseray.action.UDP" // v1.0.0: гейт UDP-релея
        const val EXTRA_ENABLED = "enabled"
        const val EXTRA_STATUS = "status"
        const val EXTRA_TX_RATE = "tx_rate"
        const val EXTRA_RX_RATE = "rx_rate"
        const val EXTRA_TX_TOTAL = "tx_total"
        const val EXTRA_RX_TOTAL = "rx_total"
        const val EXTRA_PROTO = "proto"
        const val EXTRA_PKT_TX_COUNT = "pkt_tx_count"
        const val EXTRA_PKT_RX_COUNT = "pkt_rx_count"
        const val EXTRA_PKT_TX_SIZE = "pkt_tx_size"
        const val EXTRA_PKT_RX_SIZE = "pkt_rx_size"
        const val EXTRA_PKT_KIND = "pkt_kind"
        const val EXTRA_USAGE_BYTES = "usage_bytes"
        const val EXTRA_USAGE_LIMIT = "usage_limit"
        const val EXTRA_SPEEDTEST_TEXT = "speedtest_text" // v0.8: строка спидтеста
        // v1.5.0: мульти-серверные события (старые экстра-ключи сохранены)
        const val EXTRA_SESSION_ID = "session_id"
        const val EXTRA_PROFILE_NAME = "profile_name"
        const val EXTRA_SESSIONS = "sessions" // JSON-снапшот всех сессий (дашборд)
        const val ACTION_SESSION = "dev.stelgen.reverseray.action.SESSION"
        const val EXTRA_SESSION_CMD = "session_cmd" // connect|disconnect|reconnect|probe|primary
        internal const val STATS_INTERVAL_MS = 500L
        internal const val ERROR_HOLD_MS = 1_500L
        internal const val PERSIST_EVERY_TICKS = 120 // ~60 c — дисциплина SSD/памяти (v0.8)
        internal const val LIMIT_POLL_MS = 60_000L // проверка сброса лимита раз в минуту

        internal const val CHANNEL_ID = "tunnel"
        internal const val NOTIF_ID = 1
        internal const val NET_RETRY_COOLDOWN_MS = 3_000L

        // смена протокола: ретраи/паузы/cooldown — защита от rate-limit циклов
        internal const val SWITCH_RETRIES = 3
        internal const val SWITCH_RETRY_PAUSE_MS = 5_000L
        internal const val SWITCH_COOLDOWN_MS = 60_000L
        @Volatile internal var nextSwitchAllowedAt = 0L

        @Volatile var lastStatus: String = ""
        /** v0.9.2 (R3): последнее состояние/протокол — для мгновенной
         * синхронизации UI после пересоздания Activity (кнопка/статус). */
        @Volatile var lastState: String = STATE_STOPPED

        /** v0.9.9: актуальный согласованный протокол сессии (UI переживает recreate). */
        @Volatile var lastNegotiatedProto: String = ""

        /** v0.9.9: живая ли сессия (для показа согласованного протокола в UI). */
        fun isSessionState(s: String): Boolean =
            s == STATE_CONNECTED || s == STATE_PROTO
    
        // v1.6.0: буфер графика УБРАН из сервиса — единственный источник
        // истории главного графика: ui/GraphHistory (пишется ВСЕГДА:
        // туннелем и общесистемным сэмплером Activity; переживает recreate).
        // v0.9.6: журнал ОДИН на всё приложение — LogStore (канал STATUS).
        // Окна (главная/обновление/лог) берут из него сообщения своего типа.
        fun snapshotLogs(): List<LogStore.Entry> = LogStore.snapshot(LogStore.Channel.STATUS)

        fun pushLog(line: String, kind: LogKind = LogKind.INFO, session: String = "") {
            LogStore.push(line, kind, LogStore.Channel.STATUS, session)
        }

        /**
         * v1.8.4: применить настройку «Уровень журнала» (prefs → LogStore.minLevel).
         * Вызывается при старте сервиса и после смены в настройках.
         */
        fun applyLogMinLevel(p: android.content.SharedPreferences) {
            val k = LogKind.from(p.getString(KEY_LOG_MIN_LEVEL, null)) ?: LogKind.INFO
            LogStore.minLevel = k
        }

        /**
         * Логирование изменения настройки: вызывается ТОЛЬКО когда значение
         * реально изменилось (проверка на стороне MainActivity). Попадает и в
         * журнал, и в статусную строку главного экрана.
         */
        fun logSettingChange(name: String, from: String, to: String) {
            if (from == to) return // не менялось — не пишем
            val line = Msgs.LOG_SETTING_CHANGE.t(name, from, to) // companion без Context — типизированный каталог core
            pushLog(line, LogKind.NOTICE) // v1.8.4: уведомление (бирюза) — важное, но не проблема
            lastStatus = line
        }

        /** Первый не-loopback IPv4 в локальной сети (или IPv6 как фолбэк). */
        fun localIp(): String? {
            return try {
                val cand = NetworkInterface.getNetworkInterfaces().asSequence()
                    .filter { it.isUp && !it.isLoopback }
                    .flatMap { it.inetAddresses.asSequence() }
                    .toList()
                cand.firstOrNull { !it.isLoopbackAddress && it is java.net.Inet4Address }?.hostAddress
                    ?: cand.firstOrNull { !it.isLoopbackAddress }?.hostAddress
            } catch (_: Exception) {
                null
            }
        }
    }
}

/**
 * SharedPreferences-адаптер для SessionStore (v1.5.0, APK).
 * Тесты используют свою in-memory карту — core остаётся pure Kotlin.
 */
class PrefsBackend(private val p: android.content.SharedPreferences) : SessionStore.Backend {
    override fun getString(key: String): String? = p.getString(key, null)
    override fun putString(key: String, value: String) { p.edit().putString(key, value).apply() }
    override fun remove(key: String) { p.edit().remove(key).apply() }
    override fun contains(key: String): Boolean = p.contains(key)
}
