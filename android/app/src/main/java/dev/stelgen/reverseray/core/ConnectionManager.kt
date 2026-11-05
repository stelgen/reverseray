package dev.stelgen.reverseray.core

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Менеджер N одновременных сессий (v1.5.0 «Multi-Server Core»).
 *
 * Каждая сессия = один профиль [SessionStore.Profile]:
 *  - сетевой воркер [Worker] (создаёт владелец; в APK — раннеры TunnelService
 *    по портам профиля; в тестах — фейки);
 *  - СОБСТВЕННЫЙ экземпляр [AutoBalancer] (гистерезис одного не мешает другому);
 *  - СОБСТВЕННОЕ backoff/реконнект-состояние (attempt-счётчик, kick);
 *  - агрегатор статистики (rate/total, RTT, реконнекты, ошибки);
 *  - кольцевой буфер последних [LOG_BUFFER] строк лога сессии.
 *
 * ИЗОЛИРОВАННОСТЬ (канон v1.5.0): падение/рестарт/фатальная ошибка одной
 * сессии не роняет и не трогает другие — менеджер ловит все исключения воркера
 * per-call и помечает состояние только этой сессии.
 *
 * ПОТОКИ: пул на менеджер ([scheduler], 2 daemon-нити: тикеры балансеров
 * + stats-помпа 500 мс) — НИ ОДНОГО потока на сессию: N×250 мс pump'ов
 * воркеров живут внутри своих релеев, менеджер только агрегирует сэмплы.
 *
 * ЛИМИТ: максимум [MAX_SESSIONS] одновременных сессий (guardrail, константа).
 *
 * Чистый Kotlin — тестируется фейковыми воркерами без сети и Android.
 */
class ConnectionManager(private val owner: Owner) {

    /** Владелец (TunnelService / тест-харнесс): точка входа событий сессий. */
    interface Owner {
        /** Создать сетевого воркера для профиля (назначается id сессии). */
        fun createWorker(profile: SessionStore.Profile, sessionId: String): Worker

        /** Строка лога сессии (владелец пишет в LogStore с тегом сессии). */
        fun onSessionLog(session: Session, message: String, kind: LogKind)

        /** Смена состояния сессии (STARTED/CONNECTING/CONNECTED/ERROR/STOPPED/...). */
        fun onSessionState(session: Session, state: String)

        /** Тик статистики по сессии (rate/total; помпа 500 мс). */
        fun onSessionStats(session: Session, rxRate: Long, txRate: Long)

        /** РЕШЕНИЕ балансера сессии: смена протокола (владелец исполняет свитч). */
        fun onBalancerSwitch(session: Session, target: String, reason: String)
    }

    /**
     * Сетевой воркер одной сессии: инкапсулирует раннеры по портам, runLoop
     * с backoff, реконнекты. Менеджер только командует start/stop/kick и
     * читает сэмплы; вся сетевая логика — внутри воркера (изолированность).
     */
    interface Worker {
        fun start()
        fun stop()
        /** Мгновенный retry (появилась сеть). */
        fun kick()
        /** Снимок [tx, rx] байт payload'ов с момента старта сессии. */
        fun bytesSnapshot(): Pair<Long, Long>
        /** Снимок качества для балансера (null — нет живого клиента). */
        fun healthSample(): AutoBalancer.Sample?
        /** Согласованный протокол живой сессии ("" — неизвестен). */
        fun negotiatedProto(): String
        /** Реестр протоколов сервера (для кандидатов балансера). */
        fun serverProtocols(): List<String>
        /** Бесшовная смена протокола (0x2C). */
        fun switchProto(target: String): Boolean
        /** Воркер жив (есть хотя бы один запущенный раннер). */
        fun isRunning(): Boolean
        /** AUTO-режим ссылки (без proto=) — нужен ли пер-сессионный балансер. */
        fun autoBalance(): Boolean
    }

    /** Гардpeйл: максимум одновременных сессий. */
    companion object {
        const val MAX_SESSIONS = 4
        /** Кольцевой буфер лога на сессию (строк; UI берёт дашборд-хвост отсюда). */
        const val LOG_BUFFER = 120
        /** Тик балансера (сбор данных; решение — по гистерезису AutoBalancer). */
        const val BAL_TICK_MS = 5_000L
        /** Тик помпы статистики. */
        const val STATS_TICK_MS = 500L
    }

    /** Живая сессия менеджера. */
    class Session(
        val id: String,
        val profile: SessionStore.Profile,
        internal val worker: Worker,
    ) {
        /** Пер-сессионный балансер (анти-мигание каждого независимо). */
        val balancer = AutoBalancer()

        /** Backoff-состояние (attempt 0-based; сбрасывается при успешном коннекте). */
        val backoffAttempt = AtomicLong(0)

        /** Счётчики дашборда. */
        val reconnects = AtomicLong(0)
        val errors = AtomicLong(0)
        val protoSwitches = AtomicLong(0)
        val startedAtMs = AtomicLong(0)

        /** Последний RTT (мс; из пингов воркера). */
        @Volatile var lastRttMs: Long = 0

        /** Состояние сессии (строки STATE_* владельца; для дашборда/уведомления). */
        @Volatile var state: String = "STOPPED"
            internal set

        @Volatile var stateText: String = ""
            internal set

        /** Суммарные байты за сессию (обновляет помпа менеджера). */
        @Volatile var txTotal: Long = 0
        @Volatile var rxTotal: Long = 0

        /** Последние rate (байт/с). */
        @Volatile var rxRate: Long = 0
        @Volatile var txRate: Long = 0

        /** Кольцевой буфер последних строк лога сессии («[Name] …» без префикса). */
        private val logBuf = ArrayDeque<String>(LOG_BUFFER)

        fun logSnapshot(): List<String> = synchronized(logBuf) { logBuf.toList() }

        internal fun pushLogLine(line: String) {
            synchronized(logBuf) {
                logBuf.addLast(line)
                while (logBuf.size > LOG_BUFFER) logBuf.removeFirst()
            }
        }

        internal fun resetTraffic() {
            txTotal = 0
            rxTotal = 0
            rxRate = 0
            txRate = 0
        }
    }

    // ------------------------------------------------------------ состояние

    private val sessions = ConcurrentHashMap<String, Session>()
    private val rnd = java.util.Random()
    private val scheduler: ScheduledExecutorService =
        Executors.newScheduledThreadPool(2) { r ->
            Thread(r, "rrp-mgr").apply { isDaemon = true }
        }
    private val balTasks = HashMap<String, ScheduledFuture<*>>()
    private val statsTask = AtomicReference<ScheduledFuture<*>?>(null)
    @Volatile private var started = false

    /** Все живые сессии (снимок). */
    fun all(): List<Session> = sessions.values.sortedBy { it.profile.createdAt }

    fun byId(id: String?): Session? = id?.let { sessions[it] }

    fun count(): Int = sessions.size

    fun isRunning(id: String): Boolean = sessions[id]?.worker?.isRunning() == true

    // ------------------------------------------------------------ lifecycle

    /**
     * Запустить сессию профиля. false — лимит [MAX_SESSIONS] исчерпан, сессия
     * уже запущена или воркер отвергнут. Исключения createWorker/start
     * изолированы (сессия помечается ERROR, другие не затрагиваются).
     */
    fun start(profile: SessionStore.Profile): Session? {
        if (sessions.containsKey(profile.id)) return null
        if (sessions.size >= MAX_SESSIONS) {
            owner.onSessionLog(
                Session("limit", profile, NoopWorker),
                "session limit $MAX_SESSIONS reached — ${profile.name} not started",
                LogKind.WARN,
            )
            return null
        }
        return try {
            val w = owner.createWorker(profile, profile.id)
            val s = Session(profile.id, profile, w)
            // сохраняем ДО start: события воркера могут прилететь раньше
            val raced = sessions.putIfAbsent(profile.id, s)
            if (raced != null) return null
            s.startedAtMs.set(System.currentTimeMillis())
            s.state = "CONNECTING"
            // балансер — только для AUTO-ссылок (канон v0.10: явный proto= не трогаем)
            if (w.autoBalance()) startBalTick(s)
            ensureStatsPump()
            started = true
            try {
                w.start()
            } catch (e: Exception) {
                sessionError(s, e.message ?: "?")
            }
            owner.onSessionState(s, s.state)
            s
        } catch (e: Exception) {
            owner.onSessionLog(
                Session("failed", profile, NoopWorker),
                "start failed: ${e.message}",
                LogKind.ERR,
            )
            null
        }
    }

    /** Остановить и вывести из реестра одну сессию (изолированно). */
    fun stop(id: String) {
        val s = sessions.remove(id) ?: return
        balTasks.remove(id)?.cancel(false)
        try {
            s.worker.stop()
        } catch (_: Exception) {
        }
        s.state = "STOPPED"
        owner.onSessionState(s, s.state)
    }

    /** Остановить всё (сервис стоп). */
    fun stopAll() {
        started = false
        for (s in all()) stop(s.id)
        balTasks.clear()
        statsTask.getAndSet(null)?.cancel(false)
    }

    /** Мгновенный retry всех сессий (появилась сеть); cooldown у владельца. */
    fun kickAll() {
        for (s in sessions.values) {
            try {
                s.worker.kick()
            } catch (_: Exception) {
            }
        }
    }

    // ------------------------------------------------------------ события воркера

    /**
     * Воркер доложил смену состояния (пробрасывает владелец из колбеков
     * клиента). Backoff/реконнекты ЗДЕСЬ не трогаются — их считает
     * [workerConnected]/[workerFailed] (однозначный источник успеха/сбоя).
     */
    fun workerState(id: String, state: String, text: String, proto: String) {
        val s = sessions[id] ?: return
        s.state = state
        s.stateText = text
        if (proto.isNotBlank()) s.balancer.current = proto
        owner.onSessionState(s, state)
    }

    /** Воркер доложил строку лога сессии. */
    fun workerLog(id: String, message: String, kind: LogKind) {
        val s = sessions[id] ?: return
        s.pushLogLine(message)
        owner.onSessionLog(s, message, kind)
    }

    /** Воркер доложил успех коннекта (сброс backoff, счётчик реконнектов). */
    fun workerConnected(id: String) {
        val s = sessions[id] ?: return
        if (s.backoffAttempt.get() > 0) s.reconnects.incrementAndGet()
        s.backoffAttempt.set(0)
        s.balancer.reset(System.currentTimeMillis())
    }

    /**
     * Воркер доложил сбой коннекта: пер-сессионный backoff. Возвращает
     * задержку до следующей попытки (мс; 0 — не ждать).
     */
    fun workerFailed(id: String, reason: String): Long {
        val s = sessions[id] ?: return 0
        s.errors.incrementAndGet()
        val attempt = s.backoffAttempt.incrementAndGet()
        val delay = RrpClient.backoffDelayMs((attempt - 1).toInt().coerceIn(0, 6), rnd)
        s.state = "RETRY"
        s.stateText = reason
        owner.onSessionState(s, s.state)
        return delay
    }

    /** Фатальный сбой сессии (auth/пин): ретраи бессмысленны, состояние ERROR. */
    fun workerFatal(id: String, reason: String) {
        val s = sessions[id] ?: return
        s.errors.incrementAndGet()
        s.state = "ERROR"
        s.stateText = reason
        owner.onSessionState(s, s.state)
    }

    /** Сессия доложила ошибку без срыва коннекта (например SSRF). */
    private fun sessionError(s: Session, reason: String) {
        s.errors.incrementAndGet()
        s.state = "ERROR"
        s.stateText = reason
    }

    /** Бесшовная смена протокола конкретной сессии (0x2C). */
    fun switchProto(id: String, target: String): Boolean {
        val s = sessions[id] ?: return false
        return try {
            val ok = s.worker.switchProto(target)
            if (ok) s.protoSwitches.incrementAndGet()
            ok
        } catch (_: Exception) {
            false
        }
    }

    // ------------------------------------------------------------ тикеры

    private fun startBalTick(s: Session) {
        try {
            balTasks[s.id] = scheduler.scheduleWithFixedDelay({
                balTick(s)
            }, BAL_TICK_MS, BAL_TICK_MS, TimeUnit.MILLISECONDS)
        } catch (_: Exception) {
        }
    }

    /** Тик балансера одной сессии: сэмпл → решение (исполняет владелец). */
    private fun balTick(s: Session) {
        try {
            val sample = s.worker.healthSample() ?: return
            s.lastRttMs = sample.rttMs ?: s.lastRttMs
            val candidates = RrpProtocols.EXECUTABLE.filter {
                it != RrpProtocols.DEFAULT && s.worker.serverProtocols().contains(it)
            }
            s.balancer.candidates = candidates
            s.balancer.current = s.worker.negotiatedProto().ifBlank { s.balancer.current }
            when (val d = s.balancer.onSample(sample)) {
                is AutoBalancer.Decision.Switch ->
                    owner.onBalancerSwitch(s, d.target, d.reason)
                else -> {}
            }
        } catch (_: Exception) {
        }
    }

    /** Помпа статистики: ОДНА на менеджер (не на сессию). */
    private fun ensureStatsPump() {
        if (statsTask.get() != null) return
        val f = scheduler.scheduleWithFixedDelay({
            try {
                statsPump()
            } catch (_: Exception) {
            }
        }, STATS_TICK_MS, STATS_TICK_MS, TimeUnit.MILLISECONDS)
        statsTask.compareAndSet(null, f)
    }

    private fun statsPump() {
        for (s in sessions.values) {
            val (tx, rx) = try {
                s.worker.bytesSnapshot()
            } catch (_: Exception) {
                continue
            }
            val drx = rx - s.rxTotal
            val dtx = tx - s.txTotal
            s.rxTotal = rx
            s.txTotal = tx
            s.rxRate = drx * 1000L / STATS_TICK_MS
            s.txRate = dtx * 1000L / STATS_TICK_MS
            owner.onSessionStats(s, s.rxRate, s.txRate)
        }
    }

    /** Пустышка для событий сессий вне реестра (лог лимита/старт-фейла). */
    private object NoopWorker : Worker {
        override fun start() {}
        override fun stop() {}
        override fun kick() {}
        override fun bytesSnapshot(): Pair<Long, Long> = 0L to 0L
        override fun healthSample(): AutoBalancer.Sample? = null
        override fun negotiatedProto(): String = ""
        override fun serverProtocols(): List<String> = emptyList()
        override fun switchProto(target: String): Boolean = false
        override fun isRunning(): Boolean = false
        override fun autoBalance(): Boolean = false
    }
}
