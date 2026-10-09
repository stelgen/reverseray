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
import dev.stelgen.reverseray.core.LogStore
import dev.stelgen.reverseray.core.Msgs
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
        @Volatile var kick = false
        /** v0.9.2: раннер выведен из эксплуатации (смена протокола) — поток
         * runLoop обязан завершиться, а не пересоздать коннект (иначе
         * двойные коннекты: старый+новый набор на один порт). */
        @Volatile var retired = false
        /** активный клиент — для форс-закрытия при stopTunnel (иначе стоп ждёт handshake-таймаут до 20с) */
        @Volatile var client: RrpClient? = null
    }

    private val runners = mutableListOf<Runner>()
    private val rnd = Random()
    private val lastNetKick = AtomicLong(0)
    @Volatile private var statsThread: Thread? = null
    private var lastTx = 0L
    private var lastRx = 0L

    @Volatile private var config: RrpUriConfig? = null
    @Volatile private var stopping = true
    private var wakeLock: PowerManager.WakeLock? = null
    /** v0.9.6: Wi-Fi-lock — радио не засыпает в фоне (Android 4+, из коробки). */
    private var wifiLock: android.net.wifi.WifiManager.WifiLock? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var legacyReceiver: BroadcastReceiver? = null

    /** Идёт ли сейчас валидационная смена протокола. */
    @Volatile private var switchingProto = false
    /** Спидтест не молотит при каждом READY. */
    @Volatile private var speedTestBusy = false
    /** Ждун сброса лимита для авто-переподключения. */
    @Volatile private var limitWaitThread: Thread? = null

    private val clientListener = object : RrpClient.Listener {
        override fun onLog(client: RrpClient, message: String) {
            Log.d(TAG, "${client.host}:${client.port}: $message")
            pushLog("${client.host}:${client.port}: $message")
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
                if (client.mtProtoActive) {
                    pushLog(getString(R.string.log_mtp_keys), LogKind.OK)
                }
                sendBroadcast(
                    Intent(ACTION_STATUS).setPackage(packageName)
                        .putExtra(EXTRA_STATUS, client.negotiatedProto)
                        .putExtra(EXTRA_STATE, STATE_PROTO)
                        .putExtra(EXTRA_PROTO, client.negotiatedProto)
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
            r.endpoints.forEach { pushLog(getString(R.string.log_speedtest_line, it)) }
                val line = if (r.ok) {
                val mbs = String.format(Locale.US, "%.2f", r.bytesPerSec / 1024.0 / 1024.0)
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
            sendBroadcast(
                Intent(ACTION_STATS).setPackage(packageName)
                    .putExtra(EXTRA_SPEEDTEST_TEXT, line)
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
        lifetime = AtomicLong(prefs().getLong(KEY_TRAFFIC_LIFETIME, 0L))
    }

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
            ACTION_ACCEPT_PIN -> {
                // v0.9.0: владелец ЯВНО принял новый пин CA — обновляем ссылку,
                // пишем в журнал и реконнектим. Никакого молчаливого доверия.
                val newPin = intent.getStringExtra(EXTRA_REAL_PIN)
                val link = prefs().getString(KEY_CONFIG, null)
                val updated = newPin?.let { RrpUri.replacePin(link ?: "", it) }
                if (updated != null) {
                    prefs().edit().putString(KEY_CONFIG, updated).apply()
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
        if (!stopping && runners.isNotEmpty()) {
            updateStatus(STATE_INFO, getString(R.string.status_already_running))
            return
        }
        val cfg = try {
            prefs().getString(KEY_CONFIG, null)?.let { RrpUri.parse(it) }
        } catch (e: Exception) {
            Log.w(TAG, getString(R.string.log_config_parse_failed, e.message))
            null
        }
        if (cfg == null) {
            updateStatus(STATE_ERROR, getString(R.string.status_no_config))
            stopSelf()
            return
        }
        config = cfg
        stopping = false
        startForegroundCompat(getString(R.string.notif_starting))
        acquireWakeLock()
        logDevicePreamble(cfg)

        // v0.7.4: «только по Wi-Fi» — в мобильной сети туннель не поднимаем;
        // NetworkCallback дёрнет kickAll при появлении Wi-Fi.
        if (wifiOnly() && !isOnWifi()) {
            updateStatus(STATE_INFO, getString(R.string.status_wait_wifi))
            registerNetworkWatching()
            startStatsLoop()
            return
        }

        spawnRunners()
        registerNetworkWatching()
        resetGraphHistory()
        startStatsLoop()
        updateStatus(STATE_CONNECTING, getString(R.string.status_connecting, cfg.host))
    }

    private fun spawnRunners() {
        val cfg = config ?: return
        val proto = currentProto()
        for (port in cfg.ports) {
            val r = Runner(Target(cfg.host, port))
            synchronized(runners) { runners.add(r) }
            Thread({ runLoop(r, proto) }, "rrp-conn-$port").start()
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
                // v0.9.2 (R4): история графика живёт в сервисе — переживает recreate
                addGraphSample(drx * 1000f / STATS_INTERVAL_MS, dtx * 1000f / STATS_INTERVAL_MS)

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
        try {
            val cfg = try {
                RrpUri.parse(p.getString(KEY_CONFIG, null) ?: "")
            } catch (e: Exception) {
                updateStatus(STATE_ERROR, getString(R.string.status_no_config))
                return
            }
            updateStatus(STATE_CONNECTING, getString(R.string.status_switch_trying, protoDisplayName(newProto)))
            // v0.9.2 (R1): АТОМАРНОСТЬ ПЕРЕКЛЮЧЕНИЯ — старые коннекты
            // гарантированно закрыты ДО provisional-коннекта с новым протоколом.
            // Раньше валидационный коннект шёл поверх живых runners: сервер
            // держал две сессии, реконнект-луп параллельно молотил свой набор
            // коннектов (в логах «Already running», двойные AUTH, фоллбек в
            // середине свитча). Теперь: kill → validate → commit → spawn.
            killRunners()
            var lastErr = ""
            for (attempt in 1..SWITCH_RETRIES) {
                val client = buildClient(cfg, validateProto, validate = true)
                try {
                    client.connect()
                    // валидация (PROBE) уже прошла внутри connect() — коммитим
                    commitProto(commitProtoId, cfg)
                    updateStatus(STATE_CONNECTED, getString(R.string.status_switch_done, protoDisplayName(commitProtoId)))
                    try { client.close() } catch (_: Exception) {}
                    spawnRunners()
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
            if (!stopping) spawnRunners()
        } finally {
            switchingProto = false
        }
    }

    /**
     * Коммит ПОСЛЕ успешной валидации: протокол отражается в ссылке
     * (v0.9.2: единый источник — ссылка, KEY_PROTO больше не пишется).
     */
    private fun commitProto(proto: String, cfg: RrpUriConfig) {
        val updated = cfg.copy(proto = proto).serialize()
        prefs().edit().putString(KEY_CONFIG, updated).apply()
        pushLog(getString(R.string.log_proto_applied, proto))
    }

    /**
     * v0.9.2 (R1): kill всех рабочих коннектов БЕЗ перезапуска — идёт
     * валидационная смена протокола. Раннеры получают retired=true:
     * их потоки runLoop завершаются, а не пересоздают коннекты.
     */
    private fun killRunners() {
        val active: List<Runner>
        synchronized(runners) {
            active = runners.toList()
            runners.clear()
        }
        active.forEach {
            it.kick = true
            it.retired = true
            try { it.client?.close() } catch (_: Exception) {}
        }
    }

    /** Перезапуск рабочих коннектов с новым протоколом (без смены статуса). */
    private fun restartRunnersQuietly() {
        if (stopping) return
        killRunners()
        spawnRunners()
    }

    private fun buildClient(cfg: RrpUriConfig, proto: String, validate: Boolean): RrpClient {
        return RrpClient(
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
        if (prefs().contains(KEY_CAMO_OFF)) !prefs().getBoolean(KEY_CAMO_OFF, false) else null

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
        var attempt = 0
        var lastError = "?"
        // v0.8.1: подряд идущие неудачи на ТЕКУЩЕМ протоколе (для фоллбека)
        var failStreak = 0
        while (!stopping) {
            val cfg = config ?: break
            // v0.9.2 (R1): ГЕЙТ смены протокола — во время валидационного
            // provisional-коннекта реконнект-луп не молотит свои попытки
            // (атомарность: kill → validate → commit → spawn).
            while (switchingProto && !stopping) {
                try { Thread.sleep(200) } catch (_: InterruptedException) { return }
            }
            if (stopping || r.retired) return
            // протокол перечитываем КАЖДУЮ итерацию: так подхватывается
            // и смена протокола, и фоллбек, и заморозка обновлений (без пересоздания)
            // v0.9.2 (R2): протокол — только из ссылки (proto=), не из KEY_PROTO
            val useProto = currentProto()
            val claimed = claimedProto()
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
                deviceName = cfg.name?.takeIf { it.isNotBlank() } ?: "phone-1",
                transport = cfg.transport,
                agentName = "ReverseRay-Android/" + appVersion(),
                noisePolicy = buildNoisePolicy(),
                protoId = useProto,
                initialCamCtl = camCtlFlag(),
            )
            r.client = client
            try {
                client.connect()
                failStreak = 0
                attempt = 0
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
                return
            } catch (e: Exception) {
                lastError = e.message ?: "?"
                failStreak++
                updateStatus(STATE_ERROR, getString(R.string.status_error, r.target.port, lastError))
                // v0.8.1 КАНОН ФОЛЛБЕКА: новый модуль протокола сломал клиент →
                // откатываемся на предыдущий рабочий (rrp1). Сервер НЕ откатываем
                // (анти-цикл: обновления рассинхронизированы, авто-обновление
                // может быть отключено — модули заморожены, это не должно ломать).
                // v0.9.2 (R1): во время смены протокола фоллбек не срабатывает —
                // откат сделает switchProtocol после валидации.
                if (!switchingProto && ProtoFallback.shouldFallback(useProto, failStreak)) {
                    pushLog(ProtoFallback.fallbackReason(useProto), LogKind.WARN)
                    applyProtoFallback(useProto)
                    return
                }
            } finally {
                try { client.close() } catch (_: Exception) {}
            }
            r.client = null
            if (stopping || r.retired) return
            if (switchingProto) {
                // переход занят валидацией: попытка не считается, backoff сбросится
                attempt = 0
                failStreak = 0
                continue
            }
            attempt++
            val delay = RrpClient.backoffDelayMs(attempt - 1, rnd)
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
    private fun applyProtoFallback(brokenProto: String) {
        val p = prefs()
        // v0.9.2 (R2): протокол живёт только в ссылке
        try {
            val cfg = RrpUri.parse(p.getString(KEY_CONFIG, "") ?: "")
            if (cfg.proto != RrpProtocols.DEFAULT) {
                p.edit().putString(KEY_CONFIG, cfg.copy(proto = RrpProtocols.DEFAULT).serialize()).apply()
            }
        } catch (_: Exception) {
        }
        sendBroadcast(
            Intent(ACTION_STATUS).setPackage(packageName)
                .putExtra(EXTRA_STATE, STATE_PROTO_ROLLBACK)
                .putExtra(EXTRA_STATUS, ProtoFallback.fallbackReason(brokenProto))
                .putExtra(EXTRA_PROTO, RrpProtocols.DEFAULT)
        )
        if (!stopping) {
            restartRunnersQuietly()
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
        resetGraphHistory()
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
        synchronized(runners) { runners.forEach { it.kick = true } }
        // если туннель ещё не поднимался из-за отсутствия Wi-Fi — поднимаем
        if (runners.isEmpty() && !stopping) spawnRunners()
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
        return if (Build.VERSION.SDK_INT >= 16) {
            builder.build()
        } else {
            @Suppress("DEPRECATION")
            builder.getNotification() // API 14-15: build() ещё нет
        }
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

    private fun updateStatus(state: String, text: String) {
        lastStatus = text
        // v0.9.2 (R3): источник истины для UI — сервис (переживает recreate):
        // MainActivity синхронизируется из lastState/lastStatus/lastProto
        // сразу после пересоздания, не дожидаясь очередного broadcast.
        lastState = state
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
                .putExtra(EXTRA_STATE, state)
        )
        sendBroadcast(Intent(ACTION_STATUS).setPackage(packageName).putExtra(EXTRA_STATUS, text))
        try {
            (applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .notify(NOTIF_ID, buildNotification(text))
        } catch (_: Exception) {
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
        private const val STATS_INTERVAL_MS = 500L
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
        @Volatile var lastProto: String = ""

        /** v0.9.2 (R4): буфер графика живёт В СЕРВИСЕ (переживает recreate).
         * Чередование [rx, tx], индекс головы, число валидных сэмплов (500мс).
         * Служебные метрики: EMA-среднее и пик по окну истории. */
        private const val GRAPH_SAMPLES = 120 // 60 c при 500 мс
        private val graphLock = Any()
        private val graph = FloatArray(GRAPH_SAMPLES * 2)
        private var graphHead = 0
        private var graphCount = 0
        @Volatile private var graphAvgRxEma = 0f
        @Volatile private var graphAvgTxEma = 0f
        @Volatile private var graphPeak = 0f

        /** Сэмпл скорости в историю графика (вызывается из stats-лупа). */
        fun addGraphSample(rxRate: Float, txRate: Float) {
            synchronized(graphLock) {
                graphHead = (graphHead + 1) % GRAPH_SAMPLES
                graph[graphHead * 2] = rxRate.coerceAtLeast(0f)
                graph[graphHead * 2 + 1] = txRate.coerceAtLeast(0f)
                if (graphCount < GRAPH_SAMPLES) graphCount++
                graphAvgRxEma = graphAvgRxEma * 0.75f + rxRate.coerceAtLeast(0f) * 0.25f
                graphAvgTxEma = graphAvgTxEma * 0.75f + txRate.coerceAtLeast(0f) * 0.25f
                val peakNow = maxOf(rxRate, txRate).coerceAtLeast(0f)
                if (peakNow > graphPeak) graphPeak = peakNow
            }
        }

        /** Снимок истории для восстановления графика после recreate.
         * Возвращает [rx, tx]-чередование, head, count. */
        fun graphHistory(): Triple<FloatArray, Int, Int> {
            synchronized(graphLock) {
                return Triple(graph.copyOf(), graphHead, graphCount)
            }
        }

        /** [avgRx, avgTx, peak] — сводка для подписей (байт/с). */
        fun graphStats(): FloatArray = floatArrayOf(graphAvgRxEma, graphAvgTxEma, graphPeak)

        /** Полный сброс истории (старт/стоп туннеля). */
        fun resetGraphHistory() {
            synchronized(graphLock) {
                graph.fill(0f)
                graphHead = 0
                graphCount = 0
            }
            graphAvgRxEma = 0f
            graphAvgTxEma = 0f
            graphPeak = 0f
        }

        // v0.9.6: журнал ОДИН на всё приложение — LogStore (канал STATUS).
        // Окна (главная/обновление/лог) берут из него сообщения своего типа.
        fun snapshotLogs(): List<LogStore.Entry> = LogStore.snapshot(LogStore.Channel.STATUS)

        fun pushLog(line: String, kind: LogKind = LogKind.INFO) {
            LogStore.push(line, kind, LogStore.Channel.STATUS)
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
