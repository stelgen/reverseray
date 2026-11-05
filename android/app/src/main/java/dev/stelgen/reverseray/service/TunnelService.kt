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
import dev.stelgen.reverseray.core.ConnectionManager
import dev.stelgen.reverseray.core.LogStore
import dev.stelgen.reverseray.core.SessionStore
import dev.stelgen.reverseray.core.Msgs
import dev.stelgen.reverseray.core.Negotiation
import dev.stelgen.reverseray.core.ProtoFallback
import dev.stelgen.reverseray.core.RrpAuthException
import dev.stelgen.reverseray.core.RrpClient
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

class TunnelService : Service() {

    // v0.8.3: язык сервиса/уведомлений из prefs (канон i18n)
    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(L10nUi.wrap(base))
    }

    private class Target(val host: String, val port: Int)

    @Volatile private var lifetime: AtomicLong = AtomicLong(0)

    private inner class Runner(val target: Target) {
        /** Сессия (профиль), к которой принадлежит раннер (v1.5.0). */
        var sess: Sess? = null
        @Volatile var kick = false
        /** v0.9.2: раннер выведен из эксплуатации (смена протокола) — поток
         * runLoop обязан завершиться, а не пересоздать коннект (иначе
         * двойные коннекты: старый+новый набор на один порт). */
        @Volatile var retired = false
        /** активный клиент — для форс-закрытия при stopTunnel (иначе стоп ждёт handshake-таймаут до 20с) */
        @Volatile var client: RrpClient? = null
    }

    private val runners = mutableListOf<Runner>()

    // ---------- v1.5.0 «Multi-Server Core»: профили/сессии ----------

    /** Хранилище профилей (миграция v1.3→v1.5 — в onCreate). */
    private lateinit var sessionStore: SessionStore

    /** Менеджер N сессий (живёт пока туннель поднят). */
    @Volatile private var manager: ConnectionManager? = null

    /** Сессия сервиса: профиль + точка агрегации состояния. */
    private inner class Sess(val id: String, val profile: SessionStore.Profile)

    private val sessById = java.util.concurrent.ConcurrentHashMap<String, Sess>()

    /** Сессия, занятая валидационной сменой протокола (gate только для неё). */
    @Volatile private var switchingSessionId: String? = null

    // v1.0.2 (мультипоточность): состояние каждого раннера (ключ = sessId|порт)
    private val sessionStates = java.util.concurrent.ConcurrentHashMap<String, String>()
    private val runnerStateKey = ThreadLocal<String>()
    private val rnd = Random()
    private val lastNetKick = AtomicLong(0)
    @Volatile private var statsThread: Thread? = null
    private var lastTx = 0L
    private var lastRx = 0L

    @Volatile private var stopping = true
    private var wakeLock: PowerManager.WakeLock? = null
    /** v0.9.6: Wi-Fi-lock — радио не засыпает в фоне (Android 4+, из коробки). */
    private var wifiLock: android.net.wifi.WifiManager.WifiLock? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var legacyReceiver: BroadcastReceiver? = null

    /** Идёт ли сейчас валидационная смена протокола. */
    @Volatile private var switchingProto = false

    // ---------- v1.5.0: балансер пер-сессионный (в ConnectionManager);
    // решение балансера исполняет sessionOwner.onBalancerSwitch (ниже).

    /**
     * Бесшовная смена протокола в живых раннерах ОДНОЙ сессии (кадр 0x2C —
     * согласование без разрыва связи). Ссылка НЕ меняется (AUTO остаётся AUTO —
     * сервер переговорит при реконнекте сам). false — хоть один раннер отказал.
     */
    private fun switchProtoLiveOf(sess: Sess, target: String): Boolean {
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

    /** Первый живой клиент сессии (для healthSample/proto снапшотов). */
    private fun firstClientOf(sess: Sess): RrpClient? =
        synchronized(runners) { runners.firstOrNull { it.sess === sess }?.client }

    private fun runnersOf(sess: Sess): List<Runner> =
        synchronized(runners) { runners.filter { it.sess === sess } }

    private fun killRunnersOf(sess: Sess) {
        val active = synchronized(runners) {
            val list = runners.filter { it.sess === sess }
            runners.removeAll { it.sess === sess }
            list
        }
        active.forEach {
            it.kick = true
            it.retired = true
            try { it.client?.close() } catch (_: Exception) {}
        }
    }

    /** Сессия-владелец для менеджера: создаёт воркеры, принимает события. */
    private val sessionOwner = object : ConnectionManager.Owner {
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

        override fun autoBalance(): Boolean = claimedOf(sess.profile.uri).isBlank()
    }
    /** Спидтест не молотит при каждом READY. */
    @Volatile private var speedTestBusy = false
    /** Ждун сброса лимита для авто-переподключения. */
    @Volatile private var limitWaitThread: Thread? = null

    private val clientListener = object : RrpClient.Listener {
        /** Сессия, владеющая клиентом (v1.5.0: тегирование логов per-сессия). */
        private fun sessOf(client: RrpClient): Sess? =
            synchronized(runners) { runners.firstOrNull { it.client === client }?.sess }

        override fun onLog(client: RrpClient, message: String) {
            Log.d(TAG, "${client.host}:${client.port}: $message")
            val sess = sessOf(client)
            if (sess != null) {
                manager?.workerLog(sess.id, "${client.host}:${client.port}: $message", LogKind.INFO)
                    ?: pushLog("[${sess.profile.name}] ${client.host}:${client.port}: $message")
            } else {
                pushLog("${client.host}:${client.port}: $message")
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
    private fun fmtBytes(b: Long): String = Formats.bytes(this, b)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
        ensureStore()
        lifetime = AtomicLong(prefs().getLong(KEY_TRAFFIC_LIFETIME, 0L))
    }

    /** Ленивая инициализация SessionStore + ОДНОРАЗОВАЯ миграция v1.3→v1.5. */
    private fun ensureStore() {
        if (!::sessionStore.isInitialized) {
            sessionStore = SessionStore(PrefsBackend(prefs()))
            val migrated = sessionStore.migrateLegacy(prefs().getString(KEY_CONFIG, null))
            if (migrated != null) {
                pushLog(Msgs.SESSION_MIGRATED.t(migrated.name), LogKind.OK)
            }
        }
    }

    /** Профиль по id (или null). */
    private fun profileById(id: String?): SessionStore.Profile? =
        if (::sessionStore.isInitialized) sessionStore.byId(id) else null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_SWITCH_PROTO -> {
                val p = RrpProtocols.normalize(intent.getStringExtra(EXTRA_PROTO))
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
                val link = prefs().getString(KEY_CONFIG, null)
                val updated = newPin?.let { RrpUri.replacePin(link ?: "", it) }
                if (updated != null) {
                    // v1.5.0: пин обновляется в URI PRIMARY-профиля + зеркало
                    commitPrimaryUri(updated)
                    pushLog(Msgs.PIN_ACCEPTED.t(newPin ?: ""), LogKind.WARN)
                    startTunnel()
                } else {
                    pushLog(Msgs.SEND_FAILED.t("pin update failed"), LogKind.ERR)
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

    /**
     * v0.9.2 (R2): ЕДИНЫЙ источник правды протокола — ССЫЛКА (proto=).
     * Раньше протокол читался из отдельного KEY_PROTO, который перекрывал
     * вставленную ссылку: после смены протокола новая ссылка с proto=rrp1
     * продолжала подключаться mtproto2. Теперь proto всегда из ссылки;
     * KEY_PROTO выведен из употребления (не читается).
     */
    /** Протокол ИЗ URI профиля (исполняемая нормализация) — v1.5.0. */
    internal fun protoOf(uri: String): String = try {
        RrpProtocols.normalizeExecutable(RrpUri.parse(uri).proto)
    } catch (_: Exception) {
        RrpProtocols.PREFERRED_AUTO
    }

    /** Заявленный протокол ИЗ URI профиля ("" = AUTO) — v1.5.0. */
    internal fun claimedOf(uri: String): String = try {
        RrpUri.parse(uri).proto.trim()
    } catch (_: Exception) {
        ""
    }

    /** Честное имя протокола для статусов: AUTO — словом, остальное — меткой. */
    internal fun protoDisplayName(id: String): String =
        if (id == PROTO_AUTO || id.isBlank()) getString(R.string.proto_auto_label)
        else RrpProtocols.labelWithVer(id)

    internal fun currentProto(): String {
        val cfg = try {
            RrpUri.parse(prefs().getString(KEY_CONFIG, null) ?: "")
        } catch (_: Exception) {
            null
        }
        return RrpProtocols.normalizeExecutable(cfg?.proto)
    }

    /**
     * Заявленный (отображаемый) протокол из ссылки: новый протокол модуля
     * честно виден в GUI, даже если эта сборка ещё не умеет его исполнять
     * (тогда коннект идёт на rrp1 — см. RrpProtocols.normalizeExecutable).
     */
    internal fun claimedProto(): String {
        val cfg = try {
            RrpUri.parse(prefs().getString(KEY_CONFIG, null) ?: "")
        } catch (_: Exception) {
            null
        }
        // v0.9.5: возвращаем КАК В ССЫЛКЕ ("" = AUTO) — GUI честно показывает
        // режим AUTO, warning «не исполняется» только для явных протоколов.
        return cfg?.proto?.trim() ?: ""
    }

    private fun startTunnel() {
        ensureStore()
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

    /** Старт одной сессии (изолированно: неудача не роняет другие). */
    private fun startSession(p: SessionStore.Profile) {
        manager?.start(p)
    }

    /** Все сессии из реестра (для kickAll-поднятия после Wi-Fi). */
    private fun startAllSessions() {
        for (p in sessionStore.profiles()) {
            if (p.enabled || p.id == sessionStore.activeId()) {
                if (sessById.containsKey(p.id)) continue
                if (sessById.size >= ConnectionManager.MAX_SESSIONS) break
                startSession(p)
            }
        }
    }

    /** Раннеры ОДНОЙ сессии (по портам профиля) — v1.5.0. */
    private fun spawnRunnersFor(sess: Sess) {
        val cfg = try {
            RrpUri.parse(sess.profile.uri)
        } catch (_: Exception) {
            return
        }
        val proto = protoOf(sess.profile.uri)
        for (port in cfg.ports) {
            val r = Runner(Target(cfg.host, port))
            r.sess = sess
            synchronized(runners) { runners.add(r) }
            val stateKey = "${sess.id}|$port"
            Thread({
                runnerStateKey.set(stateKey)
                try {
                    runLoop(r, proto)
                } finally {
                    sessionStates.remove(stateKey)
                }
            }, "rrp-conn-${sess.id.take(4)}-$port").start()
        }
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

    /** Реалтайм-статистика трафика: раз в 500 мс шлёт ACTION_STATS (байт/с). */
    private fun startStatsLoop() {
        if (statsThread?.isAlive == true) return
        lastTx = 0
        lastRx = 0
        val t = Thread({
            var persistTick = 0
            while (!stopping) {
                try {
                    Thread.sleep(STATS_INTERVAL_MS)
                } catch (_: InterruptedException) {
                    return@Thread
                }
                var tx = 0L
                var rx = 0L
                var pk = longArrayOf(0, 0, 0, 0)
                var kind = ""
                synchronized(runners) {
                    runners.forEach { r ->
                        r.client?.bytesSnapshot()?.let { (a, b) -> tx += a; rx += b }
                        r.client?.packetsSnapshot()?.let { p ->
                            pk[0] += p[0]; pk[1] += p[1]; pk[2] = p[2]; pk[3] = p[3]
                        }
                        if (r.client?.lastPacketKind?.isNotEmpty() == true) kind = r.client!!.lastPacketKind
                    }
                }
                val dtx = tx - lastTx
                val drx = rx - lastRx
                lastTx = tx
                lastRx = rx
                // v1.5.0: per-сессионный снапшот для дашборда (JSON в extra)
                val sessionsJson = sessionsJson()
                // v0.9.2 (R4): история графика живёт в сервисе — переживает recreate

                // v0.8: счётчик за всё время (канон: RAM, запись на диск пореже)
                prefs().edit()
                    .putLong(KEY_TRAFFIC_LIFETIME, lifetime.addAndGet(drx + dtx)).apply()
                // v0.7.4/v0.8: учёт лимита трафика (сумма вход+выход за период)
                val usage = accountTraffic(drx + dtx)

                sendBroadcast(
                    Intent(ACTION_STATS)
                        .setPackage(packageName)
                        .putExtra(EXTRA_TX_RATE, dtx * 1000L / STATS_INTERVAL_MS)
                        .putExtra(EXTRA_RX_RATE, drx * 1000L / STATS_INTERVAL_MS)
                        .putExtra(EXTRA_TX_TOTAL, tx)
                        .putExtra(EXTRA_RX_TOTAL, rx)
                        .putExtra(EXTRA_SESSIONS, sessionsJson)
                        .putExtra(EXTRA_PKT_TX_COUNT, pk[0])
                        .putExtra(EXTRA_PKT_RX_COUNT, pk[1])
                        .putExtra(EXTRA_PKT_TX_SIZE, pk[2])
                        .putExtra(EXTRA_PKT_RX_SIZE, pk[3])
                        .putExtra(EXTRA_PKT_KIND, kind)
                        .putExtra(EXTRA_USAGE_BYTES, usage.used)
                        .putExtra(EXTRA_USAGE_LIMIT, usage.limit)
                )
                if (usage.limit > 0 && usage.used >= usage.limit) {
                    // КАНОН «ЛИМИТ — КОРОЛЬ»: ровно ноль байт от нас.
                    updateStatus(STATE_ERROR, getString(R.string.status_limit_reached))
                    pushLog(getString(R.string.status_limit_reached), LogKind.ERR)
                    sendBroadcast(
                        Intent(ACTION_STATUS).setPackage(packageName)
                            .putExtra(EXTRA_STATE, STATE_LIMIT_REACHED)
                            .putExtra(EXTRA_STATUS, getString(R.string.status_limit_reached))
                            .putExtra(EXTRA_USAGE_BYTES, usage.used)
                            .putExtra(EXTRA_USAGE_LIMIT, usage.limit)
                    )
                    stopTunnel() // туннель и все коннекты умирают — ноль байт
                    maybeWaitLimitReset()
                    return@Thread
                }
                // персистим счётчик РАЗ В МИНУТУ (дисциплина SSD/памяти, v0.8)
                if (++persistTick >= PERSIST_EVERY_TICKS) {
                    persistTick = 0
                    persistUsage()
                }
            }
        }, "rrp-stats").apply { isDaemon = true; start() }
        statsThread = t
    }

    /**
     * v1.5.0: JSON-снапшот всех сессий для дашборда (EXTRA_SESSIONS):
     * state/rates/totals/proto/rtt/реконнекты/ошибки/аптайм — по сессии.
     */
    private fun sessionsJson(): String {
        val mgr = manager ?: return "[]"
        val now = System.currentTimeMillis()
        val arr = org.json.JSONArray()
        for (s in mgr.all()) {
            val proto = try { s.worker.negotiatedProto() } catch (_: Exception) { "" }
            arr.put(
                org.json.JSONObject()
                    .put("id", s.id)
                    .put("name", s.profile.name)
                    .put("state", s.state)
                    .put("rx_rate", s.rxRate)
                    .put("tx_rate", s.txRate)
                    .put("rx_total", s.rxTotal)
                    .put("tx_total", s.txTotal)
                    .put("proto", proto)
                    .put("rtt_ms", s.lastRttMs)
                    .put("reconnects", s.reconnects.get())
                    .put("errors", s.errors.get())
                    .put("switches", s.protoSwitches.get())
                    .put("uptime_ms", if (s.startedAtMs.get() > 0) now - s.startedAtMs.get() else 0)
                    .put("primary", s.id == sessionStore.activeId()),
            )
        }
        return arr.toString()
    }

    /**
     * Обновить URI PRIMARY-профиля + зеркало KEY_CONFIG (единая точка для
     * всех legacy-писателей конфига: accept-pin, вставка ссылки в UI).
     */
    private fun commitPrimaryUri(canonical: String) {
        ensureStore()
        prefs().edit().putString(KEY_CONFIG, canonical).apply()
        val active = sessionStore.active() ?: return
        sessionStore.update(active.copy(uri = canonical))
    }

    // ---------- лимит трафика ----------

    private data class Usage(val used: Long, val limit: Long)

    /**
     * Ожидание сброса лимита (авто-реконнект вкл): вычисляем дату следующего
     * сброса и ждём её, не тратя батарейку/трафик (грубые проверки раз в
     * минуту). По сбросу — реконнект. Выключаемо нитью stopTunnel().
     */
    private fun maybeWaitLimitReset() {
        if (!prefs().getBoolean(KEY_AUTO_RECONNECT, false)) return
        if (limitWaitThread?.isAlive == true) return
        val period = prefs().getString(KEY_LIMIT_PERIOD, PERIOD_DAY) ?: PERIOD_DAY
        val day = prefs().getInt(KEY_LIMIT_RESET_DAY, 1)
        val at = nextResetAtMs(period, day)
        val hours = ((at - System.currentTimeMillis()) / 3_600_000L).coerceAtLeast(0)
        pushLog(getString(R.string.status_limit_wait, hours), LogKind.WARN)
        updateStatus(STATE_LIMIT_REACHED, getString(R.string.status_limit_reached))
        val t = Thread {
            while (!stopping) {
                val usage = accountTraffic(0)
                if (usage.limit <= 0) {
                    pushLog(getString(R.string.log_limit_removed), LogKind.OK)
                    startTunnel()
                    return@Thread
                }
                if (System.currentTimeMillis() >= at) {
                    pushLog(getString(R.string.log_limit_period), LogKind.OK)
                    startTunnel()
                    return@Thread
                }
                try {
                    Thread.sleep(LIMIT_POLL_MS)
                } catch (_: InterruptedException) {
                    return@Thread
                }
            }
        }
        t.isDaemon = true
        limitWaitThread = t
        t.start()
    }

    /** Следующая дата сброса: сутки — завтра в это же время; месяц — день сброса. */
    internal fun nextResetAtMs(period: String, day: Int): Long {
        val cal = Calendar.getInstance()
        if (period == PERIOD_MONTH) {
            cal.add(Calendar.MONTH, 1)
            cal.set(Calendar.DAY_OF_MONTH, day.coerceIn(1, 28))
        } else {
            cal.add(Calendar.DAY_OF_YEAR, 1)
        }
        cal.set(Calendar.HOUR_OF_DAY, 0)
        cal.set(Calendar.MINUTE, 0)
        cal.set(Calendar.SECOND, 0)
        cal.set(Calendar.MILLISECOND, 0)
        return cal.timeInMillis
    }

    /** Сбрасывает счётчик при смене периода, возвращает [used, limit]. */
    private fun accountTraffic(delta: Long): Usage {
        val p = prefs()
        val limit = p.getLong(KEY_TRAFFIC_LIMIT, 0L)
        val period = p.getString(KEY_LIMIT_PERIOD, PERIOD_DAY) ?: PERIOD_DAY
        val key = usagePeriodKey(period)
        var used = p.getLong(KEY_TRAFFIC_USED, 0L)
        if (p.getString(KEY_USAGE_PERIOD, null) != key) {
            used = 0
            p.edit().putString(KEY_USAGE_PERIOD, key).apply()
        }
        if (delta > 0) used += delta
        return Usage(used, limit)
    }

    private fun persistUsage() {
        val usage = accountTraffic(0)
        prefs().edit().putLong(KEY_TRAFFIC_USED, usage.used).apply()
    }

    /** Ключ периода: "2026-10-08" для суток, "2026-10" для месяца. */
    private fun usagePeriodKey(period: String): String {
        val fmt = if (period == PERIOD_MONTH) "yyyy-MM" else "yyyy-MM-dd"
        return SimpleDateFormat(fmt, Locale.ROOT).format(Date())
    }

    private fun wifiOnly(): Boolean = prefs().getBoolean(KEY_WIFI_ONLY, false)

    /** Подключение сейчас по Wi-Fi? (API 21+: capabilities; 14–20: legacy тип). */
    @Suppress("DEPRECATION")
    private fun isOnWifi(): Boolean {
        val cm = applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        return try {
            if (Build.VERSION.SDK_INT >= 23) {
                val net = cm.activeNetwork ?: return false
                val caps = cm.getNetworkCapabilities(net) ?: return false
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
            } else {
                val info = cm.activeNetworkInfo
                info != null && info.type == ConnectivityManager.TYPE_WIFI && info.isConnected
            }
        } catch (_: Exception) {
            false
        }
    }

    // ---------- смена протокола (валидация → коммит, иначе откат) ----------

    /**
     * Валидационная смена протокола:
     * 1) provisional-коннект с новым протоколом + PROBE реального хоста;
     * 2) успех → коммит: сохраняем протокол и обновляем ссылку в конфиге;
     * 3) неудача (3 ретрая) → мгновенный откат UI на текущий протокол,
     *    ссылка НЕ меняется; cooldown, чтобы не молотить по rate-limit.
     */
    private fun switchProtocol(newProtoRaw: String) {
        // v0.9.5: "auto" — явный режим «лучший общий протокол» (ссылка без proto=).
        val isAuto = newProtoRaw == PROTO_AUTO
        val newProto = if (isAuto) PROTO_AUTO else RrpProtocols.normalize(newProtoRaw)
        val oldProto = currentProto()
        val p = prefs()
        if (isAuto && claimedProto().isBlank()) {
            updateStatus(STATE_INFO, getString(R.string.status_switch_same, protoDisplayName(PROTO_AUTO)))
            return
        }
        if (switchingProto) {
            updateStatus(STATE_INFO, getString(R.string.status_switch_busy))
            return
        }
        val now = System.currentTimeMillis()
        if (now < nextSwitchAllowedAt) {
            updateStatus(STATE_INFO, getString(R.string.status_switch_cooldown, (nextSwitchAllowedAt - now) / 1000))
            return
        }
        if (!isAuto && newProto == oldProto) {
            updateStatus(STATE_INFO, getString(R.string.status_switch_same, RrpProtocols.labelWithVer(newProto)))
            return
        }
        // v0.9.5: "auto" — режим без proto= в ссылке; валидируем предпочтительным,
        // в ссылку AUTO не пишем (proto= не появляется).
        val commitProtoId = if (newProto == PROTO_AUTO) "" else newProto
        val validateProto = if (newProto == PROTO_AUTO) RrpProtocols.PREFERRED_AUTO else newProto
        switchingProto = true
        // v1.5.0: смена протокола — ОПЕРАЦИЯ НАД PRIMARY (главная кнопка/пикер);
        // другие сессии живут своей жизнью (изоляция).
        val primarySess = sessionStore.activeId()?.let { sessById[it] }
        switchingSessionId = sessionStore.activeId()
        try {
            val cfg = try {
                RrpUri.parse(p.getString(KEY_CONFIG, null) ?: "")
            } catch (e: Exception) {
                updateStatus(STATE_ERROR, getString(R.string.status_no_config))
                return
            }
            updateStatus(STATE_CONNECTING, getString(R.string.status_switch_trying, protoDisplayName(newProto)))
            // v0.9.2 (R1): АТОМАРНОСТЬ ПЕРЕКЛЮЧЕНИЯ — старые коннекты PRIMARY
            // гарантированно закрыты ДО provisional-коннекта с новым протоколом.
            // Теперь: kill → validate → commit → spawn (только PRIMARY-сессия).
            primarySess?.let { killRunnersOf(it) }
            var lastErr = ""
            for (attempt in 1..SWITCH_RETRIES) {
                val client = buildClient(cfg, validateProto, validate = true)
                try {
                    client.connect()
                    // валидация (PROBE) уже прошла внутри connect() — коммитим
                    commitProto(commitProtoId, cfg, primarySess)
                    updateStatus(STATE_CONNECTED, getString(R.string.status_switch_done, protoDisplayName(commitProtoId)))
                    try { client.close() } catch (_: Exception) {}
                    primarySess?.let { spawnRunnersFor(it) }
                    return
                } catch (e: Exception) {
                    lastErr = e.message ?: "?"
                    pushLog(getString(R.string.log_proto_attempt, attempt, SWITCH_RETRIES, lastErr))
                    updateStatus(STATE_ERROR, getString(R.string.status_switch_fail, protoDisplayName(newProto), lastErr))
                } finally {
                    try { client.close() } catch (_: Exception) {}
                }
                if (attempt < SWITCH_RETRIES) {
                    try { Thread.sleep(SWITCH_RETRY_PAUSE_MS) } catch (_: InterruptedException) { break }
                }
            }
            // откат: UI вернёт выбор на старый протокол сразу, не дожидаясь реконнекта
            nextSwitchAllowedAt = System.currentTimeMillis() + SWITCH_COOLDOWN_MS
            updateStatus(STATE_ERROR, getString(R.string.status_switch_rolled_back, protoDisplayName(newProto), RrpProtocols.labelWithVer(oldProto), lastErr))
            sendBroadcast(
                Intent(ACTION_STATUS).setPackage(packageName)
                    .putExtra(EXTRA_STATE, STATE_PROTO_ROLLBACK)
                    .putExtra(EXTRA_STATUS, getString(R.string.status_switch_rolled_back, newProto, oldProto, lastErr))
                    .putExtra(EXTRA_PROTO, oldProto)
            )
            // v0.9.2 (R1): откат — рабочие коннекты старого протокола возрождаются
            if (!stopping) primarySess?.let { spawnRunnersFor(it) }
        } finally {
            switchingProto = false
            switchingSessionId = null
        }
    }

    /**
     * Коммит ПОСЛЕ успешной валидации: протокол отражается в ссылке
     * (v0.9.2: единый источник — ссылка, KEY_PROTO больше не пишется).
     */
    /**
     * Коммит ПОСЛЕ успешной валидации: протокол отражается в URI профиля
     * (v1.5.0: профиль — источник правды; зеркало KEY_CONFIG — для PRIMARY).
     */
    private fun commitProto(proto: String, cfg: RrpUriConfig, sess: Sess?) {
        val updated = cfg.copy(proto = proto).serialize()
        if (sess != null) {
            sessionStore.update(sess.profile.copy(uri = updated))
            if (sess.id == sessionStore.activeId()) {
                prefs().edit().putString(KEY_CONFIG, updated).apply()
            }
        } else {
            prefs().edit().putString(KEY_CONFIG, updated).apply()
        }
        pushLog(getString(R.string.log_proto_applied, proto))
    }

    /** Перезапуск рабочих коннектов с новым протоколом (без смены статуса). */
    private fun restartRunnersQuietly() {
        if (stopping) return
        // v1.5.0: сессий может быть несколько — перезапускаем все живые
        val sess = sessById.values.toList()
        sess.forEach { killRunnersOf(it) }
        sess.forEach { spawnRunnersFor(it) }
    }

    private fun buildClient(cfg: RrpUriConfig, proto: String, validate: Boolean): RrpClient {
        // v1.0.0: гейт UDP-релея — единая точка для боевого и валидационного клиентов
        val client = RrpClient(
            host = cfg.host,
            port = cfg.ports.firstOrNull() ?: 4433,
            token = cfg.token,
            pin = cfg.pin,
            allowLan = allowLan(),
            listener = clientListener,
            deviceName = cfg.name?.takeIf { it.isNotBlank() } ?: "phone-1",
            transport = cfg.transport,
            agentName = "ReverseRay-Android/" + appVersion(),
            noisePolicy = buildNoisePolicy(),
            protoId = proto,
            validateProbeTarget = if (validate) prefs().getString(KEY_PROBE_TARGET, DEFAULT_PROBE_TARGET) else null,
            initialCamCtl = camCtlFlag(),
        )
        client.udpEnabled = prefs().getBoolean(KEY_UDP_ENABLED, true)
        return client
    }

    /**
     * v0.8.2: политика шума камуфляжа «API Mask» из ОБЩЕГО манифеста
     * (включён манифестом + подтверждён сервером в READY). Шаблоны строк
     * лога — на языке приложения (ресурсы), честно: сколько байт, бюджет.
     */
    private fun buildNoisePolicy(): Apimask.NoisePolicy? {
        val cfg = RrpProtocols.camouflageConfig()
        // v0.9.5: локальный выбор клиента (0x2A) — выключено ⇒ шума нет вообще.
        if (prefs().getBoolean(KEY_CAMO_OFF, false)) return null
        // v1.6.0: proto=apimask — камуфляж КАК ПРОТОКОЛ (изначальный замысел):
        // пользователь ЯВНО выбрал имитацию API — шум работает даже без
        // манифест-конфига (дефолтный бюджет 256КБ/день, как в манифесте).
        if (!cfg.enabled && claimedProto() == Apimask.FEATURE) {
            return apimaskDefaultPolicy()
        }
        if (!cfg.enabled) return null
        val engine = Apimask.Engine(cfg)
        val label = RrpProtocols.camouflageLabel()
        return Apimask.NoisePolicy(engine) { bytes, used, budget ->
            if (bytes > 0) {
                getString(R.string.apimask_beat, label, bytes, fmtBytes(used), fmtBytes(budget.toLong()))
            } else {
                getString(R.string.apimask_budget_done, label, fmtBytes(used), fmtBytes(budget.toLong()))
            }
        }
    }

    /**
     * v0.9.5: начальный кадр 0x2A при подключении: отправляем ТОЛЬКО когда
     * локальный выбор существует (contains). Выбор персистентен на сервере:
     * переживает офлайн клиента, применяется будущим сессиям.
     */
    private fun camCtlFlag(): Boolean? =
        if (claimedProto() == Apimask.FEATURE) {
            // v1.6.0: proto=apimask — серверный шум включаем сразу (0x2A on),
            // выбор персистентен на сервере; явное 0x2A off от GUI всё ещё
            // выключает (переписывает выбор).
            true
        } else if (prefs().contains(KEY_CAMO_OFF)) !prefs().getBoolean(KEY_CAMO_OFF, false) else null

    /** v1.6.0: дефолтная политика шума для proto=apimask (без манифеста). */
    private fun apimaskDefaultPolicy(): Apimask.NoisePolicy {
        val cfg = Apimask.Config(Apimask.FEATURE, "API Mask", "1", true, 300, 900, 256 * 1024)
        val engine = Apimask.Engine(cfg)
        return Apimask.NoisePolicy(engine) { bytes, used, budget ->
            if (bytes > 0) {
                getString(R.string.apimask_beat, cfg.name, bytes, fmtBytes(used), fmtBytes(budget.toLong()))
            } else {
                getString(R.string.apimask_budget_done, cfg.name, fmtBytes(used), fmtBytes(budget.toLong()))
            }
        }
    }

    /**
     * Управление камуфляжем из GUI (v0.9.5): сохранить выбор + честный лог +
     * немедленный кадр 0x2A живой сессии (если есть); иначе применится при
     * следующем подключении. GUI показывает итог тостом.
     */
    private fun applyCamouflage(enabled: Boolean, done: (String) -> Unit) {
        prefs().edit().putBoolean(KEY_CAMO_OFF, !enabled).apply()
        val label = RrpProtocols.camouflageLabel()
        val what = getString(if (enabled) R.string.modules_camo_on else R.string.modules_camo_off, label)
        pushLog(what, if (enabled) LogKind.INFO else LogKind.WARN)
        var sent = false
        synchronized(runners) {
            runners.forEach { r ->
                val c = r.client
                if (c != null && c.state == RrpClient.State.READY) {
                    try {
                        c.sendCamCtl(enabled)
                        sent = true
                    } catch (_: Exception) {
                    }
                }
            }
        }
        done(if (sent) getString(R.string.modules_camo_applied) else getString(R.string.modules_camo_deferred))
    }

    private fun appVersion(): String = try {
        packageManager.getPackageInfo(packageName, 0).versionName ?: "?"
    } catch (_: Exception) {
        "?"
    }

    private fun runLoop(r: Runner, proto: String) {
        var lastError = "?"
        // v0.8.1: подряд идущие неудачи на ТЕКУЩЕМ протоколе (для фоллбека)
        var failStreak = 0
        // v0.9.7: дедуп уведомления о согласовании — одна и та же пара
        // «просили → дали» не спамит при каждом реконнекте
        var lastNegotiationNotice: String? = null
        while (!stopping) {
            // v1.5.0: конфиг сессии — ИЗ ПРОФИЛЯ (не из зеркала KEY_CONFIG;
            // зеркало держим синхронным только для legacy-кода).
            val profile = r.sess?.profile ?: return
            val cfg = try {
                RrpUri.parse(profile.uri)
            } catch (_: Exception) {
                return
            }
            // v0.9.2 (R1): ГЕЙТ смены протокола — во время валидационного
            // provisional-коннекта СЕССИИ-СВИТЧА реконнект-луп не молотит свои
            // попытки (атомарность: kill → validate → commit → spawn);
            // другие сессии живут своей жизнью (изоляция v1.5.0).
            while (switchingProto && r.sess?.id == switchingSessionId && !stopping) {
                try { Thread.sleep(200) } catch (_: InterruptedException) { return }
            }
            if (stopping || r.retired) return
            // протокол перечитываем КАЖДУЮ итерацию: так подхватывается
            // и смена протокола, и фоллбек, и заморозка обновлений (без пересоздания)
            val useProto = protoOf(profile.uri)
            val claimed = claimedOf(profile.uri)
            // v0.9.2 (R9): честный лог — протокол заявлен модулем/ссылкой,
            // но эта сборка его ещё не исполняет → коннект на rrp1.
            if (claimed.isNotBlank() && claimed != useProto) {
                pushLog(
                    getString(R.string.log_proto_not_executable, RrpProtocols.labelWithVer(claimed), RrpProtocols.labelWithVer(useProto)),
                    LogKind.WARN,
                )
            }
            val client = RrpClient(
                host = r.target.host,
                port = r.target.port,
                token = cfg.token,
                pin = cfg.pin,
                allowLan = allowLan(),
                listener = clientListener,
                deviceName = (cfg.name?.takeIf { it.isNotBlank() } ?: profile.name)?.takeIf { it.isNotBlank() } ?: "phone-1",
                transport = cfg.transport,
                agentName = "ReverseRay-Android/" + appVersion(),
                noisePolicy = buildNoisePolicy(),
                protoId = useProto,
                initialCamCtl = camCtlFlag(),
            )
            r.client = client
            try {
                client.connect()
                // v1.5.0: успех коннекта — сброс пер-сессионного backoff
                r.sess?.id?.let { manager?.workerConnected(it) }
                // v0.9.7 (канон «явные статусы согласования»): сервер ответил
                // ДРУГИМ протоколом, чем запрошен (AUTO-предпочтение или явный
                // proto=) — честный WARN вместо молчаливого даунгрейда.
                Negotiation.notice(useProto, client.negotiatedProto, claimed)?.let { notice ->
                    if (notice != lastNegotiationNotice) {
                        lastNegotiationNotice = notice
                        pushLog(notice, LogKind.WARN)
                    }
                }
                failStreak = 0
                updateStatus(STATE_CONNECTED, getString(R.string.status_connected, r.target.port))
                while (!stopping && !switchingProto && client.state == RrpClient.State.READY) {
                    try {
                        Thread.sleep(500)
                    } catch (_: InterruptedException) {
                        break
                    }
                }
            } catch (e: RrpAuthException) {
                // v0.9.4 КАНОН: auth failed — токен/ссылка устарели, это НЕ сетевой
                // сбой. Ретраи бессмысленны и зарабатывают IP-локаут на сервере
                // (5 неудач → клиент видит «TLS handshake_failure(40)» вместо
                // причины). Останавливаем авто-реконнект честным статусом;
                // обновление ссылки + кнопка Старт начинают новую серию.
                lastError = e.message ?: "?"
                pushLog(getString(R.string.status_auth_failed), LogKind.ERR)
                updateStatus(STATE_ERROR, getString(R.string.status_auth_failed))
                r.client = null
                r.sess?.id?.let { manager?.workerFatal(it, getString(R.string.status_auth_failed)) }
                return
            } catch (e: Exception) {
                lastError = e.message ?: "?"
                failStreak++
                // v1.5.1 FIX: счётчик/backoff ведёт ТОЛЬКО workerFailed ниже
                // (после цикла) — двойной инкремент задваивал errors и
                // разгонял backoff вдвое быстрее (выглядело как «не подключается»).
                updateStatus(STATE_ERROR, getString(R.string.status_error, r.target.port, lastError))
                // v0.8.1 КАНОН ФОЛЛБЕКА: новый модуль протокола сломал клиент →
                // откатываемся на предыдущий рабочий (rrp1). Сервер НЕ откатываем
                // (анти-цикл: обновления рассинхронизированы, авто-обновление
                // может быть отключено — модули заморожены, это не должно ломать).
                // v0.9.2 (R1): во время смены протокола фоллбек не срабатывает —
                // откат сделает switchProtocol после валидации.
                if (r.sess?.id != switchingSessionId && ProtoFallback.shouldFallback(useProto, failStreak)) {
                    pushLog(ProtoFallback.fallbackReason(useProto), LogKind.WARN)
                    applyProtoFallback(r.sess, useProto)
                    return
                }
            } finally {
                try { client.close() } catch (_: Exception) {}
            }
            r.client = null
            if (stopping || r.retired) return
            if (r.sess?.id == switchingSessionId) {
                // переход занят валидацией: попытка не считается, backoff сбросится
                failStreak = 0
                continue
            }
            // v1.5.0: пер-сессионный backoff ведёт ConnectionManager
            val delay = r.sess?.let { manager?.workerFailed(it.id, lastError) }
                ?: RrpClient.backoffDelayMs(0, rnd)
            // ERROR держится на экране минимум HOLD_ERROR_MS, чтобы юзер
            // успел прочитать причину, а не мигал «реконнект».
            try { Thread.sleep(ERROR_HOLD_MS) } catch (_: InterruptedException) {}
            if (stopping) break
            updateStatus(STATE_RETRY, getString(R.string.status_retry_last, r.target.port, delay / 1000, lastError))
            sleepWithKick(r, delay)
        }
    }

    /**
     * v0.8.1: клиентский фоллбек на фундамент (rrp1) — сохраняем протокол и
     * ссылку (proto= отражает реально работающий), перезапускаем коннекты.
     * UI получает STATE_PROTO_ROLLBACK и обновляет строку протокола.
     */
    /**
     * v0.8.1: клиентский фоллбек на фундамент (rrp1) — SCOPE ОДНОЙ СЕССИИ
     * (v1.5.0): протокол отражается в URI профиля (и в зеркале — если сессия
     * PRIMARY), перезапускаются только раннеры этой сессии.
     */
    private fun applyProtoFallback(sess: Sess?, brokenProto: String) {
        // v0.9.2 (R2): протокол живёт только в ссылке
        try {
            val cfg = RrpUri.parse(sess?.profile?.uri ?: "")
            if (cfg.proto != RrpProtocols.DEFAULT) {
                val updated = cfg.copy(proto = RrpProtocols.DEFAULT).serialize()
                if (sess != null) {
                    sessionStore.update(sess.profile.copy(uri = updated))
                    if (sess.id == sessionStore.activeId()) {
                        prefs().edit().putString(KEY_CONFIG, updated).apply()
                    }
                }
            }
        } catch (_: Exception) {
        }
        sendBroadcast(
            Intent(ACTION_STATUS).setPackage(packageName)
                .putExtra(EXTRA_STATE, STATE_PROTO_ROLLBACK)
                .putExtra(EXTRA_STATUS, ProtoFallback.fallbackReason(brokenProto))
                .putExtra(EXTRA_PROTO, RrpProtocols.DEFAULT)
        )
        if (!stopping && sess != null) {
            killRunnersOf(sess)
            spawnRunnersFor(sess)
        }
    }

    /** Сон с прерыванием по kick (мгновенный retry после появления сети). */
    private fun sleepWithKick(r: Runner, ms: Long) {
        val deadline = System.currentTimeMillis() + ms
        while (!stopping) {
            if (r.kick) {
                r.kick = false
                return
            }
            val now = System.currentTimeMillis()
            if (now >= deadline) return
            try {
                Thread.sleep(minOf(250L, deadline - now))
            } catch (_: InterruptedException) {
                return
            }
        }
    }

    private fun stopTunnel() {
        stopping = true
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
        updateStatus(STATE_STOPPED, getString(R.string.status_stopped))
    }

    private fun persistUsageSafely() {
        try { persistUsage() } catch (_: Exception) {}
    }

    // ---------- сеть ----------

    private fun registerNetworkWatching() {
        val cm = applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        if (Build.VERSION.SDK_INT >= 21) {
            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    kickAll()
                }
            }
            try {
                val req = if (Build.VERSION.SDK_INT >= 23 && wifiOnly()) {
                    NetworkRequest.Builder()
                        .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                        .build()
                } else {
                    NetworkRequest.Builder().build()
                }
                cm.registerNetworkCallback(req, cb)
                networkCallback = cb
            } catch (e: Exception) {
                Log.w(TAG, getString(R.string.log_netcallback_failed, e.message))
            }
        } else {
            // Фолбэк для API 14..20: легаси-броадкаст
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) {
                    if (intent?.action == ConnectivityManager.CONNECTIVITY_ACTION) kickAll()
                }
            }
            registerReceiver(receiver, IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION))
            legacyReceiver = receiver
        }
    }

    /** Мгновенный retry всех коннектов с cooldown 3 c. */
    private fun kickAll() {
        val now = System.currentTimeMillis()
        val last = lastNetKick.get()
        if (now - last < NET_RETRY_COOLDOWN_MS) return
        if (!lastNetKick.compareAndSet(last, now)) return
        Log.d(TAG, getString(R.string.log_network_back))
        // wifi-only: kick только если мы на Wi-Fi
        if (wifiOnly() && !isOnWifi()) {
            updateStatus(STATE_INFO, getString(R.string.status_wait_wifi))
            return
        }
        manager?.kickAll()
        // если туннель ещё не поднимался из-за отсутствия Wi-Fi — поднимаем
        if (manager == null && sessById.isEmpty() && !stopping) {
            manager = ConnectionManager(sessionOwner)
            startAllSessions()
        }
    }

    private fun unregisterNetworkWatching() {
        networkCallback?.let {
            if (Build.VERSION.SDK_INT >= 21) {
                try {
                    (applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager)
                        .unregisterNetworkCallback(it)
                } catch (_: Exception) {
                }
            }
        }
        networkCallback = null
        legacyReceiver?.let { try { unregisterReceiver(it) } catch (_: Exception) {} }
        legacyReceiver = null
    }

    // ---------- foreground / уведомления ----------

    private fun startForegroundCompat(text: String) {
        val notification = buildNotification(text)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notification)
        }
    }

    @Suppress("DEPRECATION")
    private fun buildNotification(text: String): Notification {
        val contentIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            Notification.Builder(this)
        }
        builder
            .setSmallIcon(R.drawable.ic_stat_reverseray)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(text)
            .setContentIntent(contentIntent)
            .setOngoing(true)
        // v1.5.0: групповая нотификация — построчное состояние сессий (канал один)
        val lines = manager?.all().orEmpty()
        if (lines.size > 1 && Build.VERSION.SDK_INT >= 16) {
            val style = Notification.InboxStyle()
            for (s in lines) {
                val mark = when (s.state) {
                    STATE_CONNECTED, STATE_PROTO -> "●"
                    STATE_CONNECTING, STATE_RETRY -> "◌"
                    STATE_STOPPED -> "–"
                    else -> "✕"
                }
                style.addLine("$mark ${s.profile.name}: ${sessionStateShort(s.state)}")
            }
            builder.setStyle(style)
        }
        return if (Build.VERSION.SDK_INT >= 16) {
            builder.build()
        } else {
            @Suppress("DEPRECATION")
            builder.getNotification() // API 14-15: build() ещё нет
        }
    }

    /** Короткая метка состояния сессии для строки уведомления. */
    private fun sessionStateShort(state: String): String = when (state) {
        STATE_CONNECTED, STATE_PROTO -> getString(R.string.notif_session_up)
        STATE_CONNECTING, STATE_RETRY -> getString(R.string.notif_session_connecting)
        STATE_STOPPED -> getString(R.string.notif_session_off)
        else -> getString(R.string.notif_session_error)
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            val nm = applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.notif_channel_name),
                    NotificationManager.IMPORTANCE_LOW,
                )
            )
        }
    }

    // ---------- wake lock ----------

    @SuppressLint("WakelockTimeout")
    private fun acquireWakeLock() {
        val pm = applicationContext.getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "reverseray:tunnel").apply {
            setReferenceCounted(false)
            acquire()
        }
        // v0.9.6: Wi-Fi-lock HIGH_PERF — туннель живёт в фоне без сна радио.
        // Держится только пока поднят туннель; доп. разрешений не требует.
        try {
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as android.net.wifi.WifiManager
            @Suppress("DEPRECATION")
            val mode = android.net.wifi.WifiManager.WIFI_MODE_FULL_HIGH_PERF
            wifiLock = wm.createWifiLock(mode, "reverseray:wifi").apply {
                setReferenceCounted(false)
                acquire()
            }
        } catch (e: Exception) {
            pushLog(Msgs.WIFI_LOCK_FAILED.t(e.message ?: "?"), LogKind.WARN)
        }
    }

    private fun releaseWakeLock() {
        try {
            wakeLock?.takeIf { it.isHeld }?.release()
        } catch (_: Exception) {
        }
        wakeLock = null
        try {
            wifiLock?.takeIf { it.isHeld }?.release()
        } catch (_: Exception) {
        }
        wifiLock = null
    }

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

    private fun updateStatus(state: String, text: String) {
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
        lastProto = claimedProto()
        // цветовая роль по состоянию (канон единого консольного окна v0.8)
        val kind = when (state) {
            STATE_CONNECTED, STATE_PROTO -> LogKind.OK
            STATE_ERROR, STATE_STOPPED, STATE_LIMIT_REACHED -> LogKind.ERR
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

    /**
     * v1.5.0: команды дашборда по сессии: connect/disconnect/reconnect/probe/
     * primary. Изолированно — затрагивается только одна сессия.
     */
    private fun handleSessionCommand(id: String, cmd: String) {
        val profile = profileById(id) ?: return
        val mgr = manager
        when (cmd) {
            "connect" -> {
                if (mgr == null || !sessById.containsKey(id)) {
                    if (mgr != null && mgr.count() >= ConnectionManager.MAX_SESSIONS) {
                        pushLog(getString(R.string.dash_sessions_limit, ConnectionManager.MAX_SESSIONS), LogKind.WARN)
                        return
                    }
                    sessionStore.setEnabled(id, true)
                    if (mgr != null) mgr.start(sessionStore.byId(id) ?: return)
                    else startTunnel()
                }
            }
            "disconnect" -> {
                sessionStore.setEnabled(id, false)
                mgr?.stop(id)
                sessById.remove(id)
            }
            "reconnect" -> {
                sessionStore.setEnabled(id, true)
                mgr?.stop(id)
                sessById.remove(id)
                if (mgr == null) startTunnel() else mgr.start(sessionStore.byId(id) ?: return)
            }
            "probe" -> probeProfile(sessionStore.byId(id) ?: return)
            "primary" -> {
                sessionStore.setActive(id)
                pushLog(getString(R.string.sess_primary_set, profile.name), LogKind.WARN)
                sendBroadcast(
                    Intent(ACTION_STATUS).setPackage(packageName)
                        .putExtra(EXTRA_STATE, STATE_INFO)
                        .putExtra(EXTRA_STATUS, getString(R.string.sess_primary_set, profile.name))
                        .putExtra(EXTRA_SESSION_ID, id)
                        .putExtra(EXTRA_PROFILE_NAME, profile.name),
                )
            }
        }
    }

    /** Валидационный прогон профиля (TCP+TLS+пин+HELLO+PROBE) без подъёма сессии. */
    private fun probeProfile(profile: SessionStore.Profile) {
        val cfg = try {
            RrpUri.parse(profile.uri)
        } catch (e: Exception) {
            pushLog("[${profile.name}] ${e.message}", LogKind.ERR)
            return
        }
        pushLog("[${profile.name}] ${getString(R.string.log_probe_running)}")
        val client = buildClient(cfg, RrpProtocols.PREFERRED_AUTO, validate = true)
        try {
            client.connect()
            pushLog("[${profile.name}] ${getString(R.string.log_probe_ok)}", LogKind.OK)
        } catch (e: Exception) {
            pushLog("[${profile.name}] ${e.message}", LogKind.ERR)
        } finally {
            try { client.close() } catch (_: Exception) {}
        }
    }

    private fun prefs(): SharedPreferences = getSharedPreferences(PREFS, MODE_PRIVATE)

    private fun allowLan(): Boolean = prefs().getBoolean(KEY_ALLOW_LAN, false)

    companion object {
        private const val TAG = "ReverseRay"

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
        const val KEY_PROBE_TARGET = "probe_target"
        const val KEY_AUTO_UPDATE = "auto_update"          // проверка обновлений раз в 24 ч
        const val KEY_THEME = "theme"                      // v0.8.1: auto|dark|light
        // v0.8:
        /** v0.9.5: сентинел режима AUTO (ссылка без proto=). */
        const val PROTO_AUTO = "auto"

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
        private const val STATS_INTERVAL_MS = 500L
        /** v0.10: тик умного балансера (5с — только СБОР данных, решение — по гистерезису). */
        private const val BAL_TICK_MS = 5_000L
        private const val ERROR_HOLD_MS = 1_500L
        private const val PERSIST_EVERY_TICKS = 120 // ~60 c — дисциплина SSD/памяти (v0.8)
        private const val LIMIT_POLL_MS = 60_000L // проверка сброса лимита раз в минуту

        private const val CHANNEL_ID = "tunnel"
        private const val NOTIF_ID = 1
        private const val NET_RETRY_COOLDOWN_MS = 3_000L

        // смена протокола: ретраи/паузы/cooldown — защита от rate-limit циклов
        private const val SWITCH_RETRIES = 3
        private const val SWITCH_RETRY_PAUSE_MS = 5_000L
        private const val SWITCH_COOLDOWN_MS = 60_000L
        @Volatile private var nextSwitchAllowedAt = 0L

        @Volatile var lastStatus: String = ""
        /** v0.9.2 (R3): последнее состояние/протокол — для мгновенной
         * синхронизации UI после пересоздания Activity (кнопка/статус). */
        @Volatile var lastState: String = STATE_STOPPED

        /** v0.9.9: актуальный согласованный протокол сессии (UI переживает recreate). */
        @Volatile var lastNegotiatedProto: String = ""

        /** v0.9.9: живая ли сессия (для показа согласованного протокола в UI). */
        fun isSessionState(s: String): Boolean =
            s == STATE_CONNECTED || s == STATE_PROTO
        @Volatile var lastProto: String = ""

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
         * Логирование изменения настройки: вызывается ТОЛЬКО когда значение
         * реально изменилось (проверка на стороне MainActivity). Попадает и в
         * журнал, и в статусную строку главного экрана.
         */
        fun logSettingChange(name: String, from: String, to: String) {
            if (from == to) return // не менялось — не пишем
            val line = Msgs.LOG_SETTING_CHANGE.t(name, from, to) // companion без Context — типизированный каталог core
            pushLog(line, LogKind.WARN) // важное (тёмно-жёлтое): изменение настроек
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
