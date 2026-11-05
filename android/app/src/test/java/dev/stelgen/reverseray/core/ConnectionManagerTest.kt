package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * v1.5.0: менеджер N сессий — изолированность (kill одной не роняет другие),
 * пер-сессионный backoff, лимит 4, stats-события с sessionId.
 */
class ConnectionManagerTest {

    /** Профиль-пустышка (валидной ссылки не нужно — воркеры фейковые). */
    private fun profile(i: Int) = SessionStore.Profile(
        id = "s$i",
        name = "S$i",
        uri = "rrp://t$i@h$i:443/",
        enabled = true,
        createdAt = 1000L + i,
    )

    /** Управляемый фейк-воркер: ошибки/стопы — по флагам из теста. */
    private class FakeWorker(
        val shared: Shared,
        val sessionId: String,
    ) : ConnectionManager.Worker {
        @Volatile var running = false
        var bytes = 0L to 0L
        var failOnStart = false

        override fun start() {
            if (failOnStart) throw RuntimeException("boom-$sessionId")
            running = true
            shared.started.incrementAndGet()
        }

        override fun stop() {
            if (shared.throwOnStop.remove(sessionId)) throw RuntimeException("stop-throw-$sessionId")
            running = false
            shared.stopped.incrementAndGet()
        }

        override fun kick() {
            shared.kicks.incrementAndGet()
        }

        override fun bytesSnapshot(): Pair<Long, Long> = bytes

        override fun healthSample(): AutoBalancer.Sample? = null
        override fun negotiatedProto(): String = ""
        override fun serverProtocols(): List<String> = emptyList()
        override fun switchProto(target: String): Boolean = false
        override fun isRunning(): Boolean = running
        override fun autoBalance(): Boolean = false
    }

    private class Shared {
        val started = AtomicInteger(0)
        val stopped = AtomicInteger(0)
        val kicks = AtomicInteger(0)
        val throwOnStop = mutableSetOf<String>()
    }

    /** Owner-харнесс: собирает события, линки фейк-воркеров. */
    private class Harness : ConnectionManager.Owner {
        val shared = Shared()
        val workers = HashMap<String, FakeWorker>()
        val stats = mutableListOf<Triple<String, Long, Long>>()
        val states = mutableListOf<Pair<String, String>>()
        val statsLatch = CountDownLatch(1)

        override fun createWorker(profile: SessionStore.Profile, sessionId: String): ConnectionManager.Worker {
            val w = FakeWorker(shared, sessionId)
            workers[sessionId] = w
            return w
        }

        override fun onSessionLog(session: ConnectionManager.Session, message: String, kind: LogKind) {}
        override fun onSessionState(session: ConnectionManager.Session, state: String) {
            states.add(session.id to state)
        }

        override fun onSessionStats(session: ConnectionManager.Session, rxRate: Long, txRate: Long) {
            synchronized(stats) { stats.add(Triple(session.id, rxRate, txRate)) }
            statsLatch.countDown()
        }

        override fun onBalancerSwitch(session: ConnectionManager.Session, target: String, reason: String) {}
    }

    @Test
    fun threeSessions_isolation_killOneOthersAlive() {
        val h = Harness()
        val m = ConnectionManager(h)
        for (i in 1..3) assertNotNull(m.start(profile(i)))
        assertEquals(3, m.count())
        // kill средней сессии
        m.stop("s2")
        assertEquals(2, m.count())
        assertNull(m.byId("s2"))
        // остальные живы и изолированы
        assertNotNull(m.byId("s1"))
        assertNotNull(m.byId("s3"))
        assertTrue(m.isRunning("s1"))
        assertTrue(m.isRunning("s3"))
        // stop чужого воркера с исключением НЕ роняет менеджер/других
        h.shared.throwOnStop.add("s1")
        m.stop("s1")
        assertEquals(1, m.count())
        assertTrue(m.isRunning("s3"))
        m.stopAll()
    }

    @Test
    fun limitFour_simultaneousGuardrail() {
        val h = Harness()
        val m = ConnectionManager(h)
        for (i in 1..ConnectionManager.MAX_SESSIONS) assertNotNull(m.start(profile(i)))
        assertNull(m.start(profile(99))) // пятая — отказ
        assertEquals(ConnectionManager.MAX_SESSIONS, m.count())
        m.stopAll()
        assertEquals(0, m.count())
    }

    @Test
    fun perSessionBackoff_independent() {
        val h = Harness()
        val m = ConnectionManager(h)
        assertNotNull(m.start(profile(1)))
        assertNotNull(m.start(profile(2)))
        // сессия 1 фейлит дважды
        val d1a = m.workerFailed("s1", "net down")
        val d1b = m.workerFailed("s1", "net down")
        assertTrue(d1b > d1a) // экспонента растёт
        assertEquals(2, m.byId("s1")!!.backoffAttempt.get())
        // сессия 2 независима: попытка 0, её коннект не трогает сессию 1
        assertEquals(0, m.byId("s2")!!.backoffAttempt.get())
        m.workerConnected("s2")
        assertEquals(0, m.byId("s2")!!.backoffAttempt.get())
        assertEquals(2, m.byId("s1")!!.backoffAttempt.get())
        assertEquals(0, m.byId("s2")!!.reconnects.get())
        assertEquals(0, m.byId("s1")!!.reconnects.get())
        // реконнект после backoff-а — засчитывается только в своей сессии
        m.workerFailed("s2", "x")
        m.workerConnected("s2")
        assertEquals(1, m.byId("s2")!!.reconnects.get())
        assertEquals(2, m.byId("s1")!!.backoffAttempt.get())
        // фатал у s1 — ERROR, s2 не затронута (у s2 свой RETRY после сбоя)
        m.workerFatal("s1", "auth failed")
        assertEquals("ERROR", m.byId("s1")!!.state)
        assertEquals("RETRY", m.byId("s2")!!.state)
        m.stopAll()
    }

    @Test
    fun startFailure_isolated() {
        val h = Harness()
        val m = ConnectionManager(h)
        val bad = profile(1)
        h.workers[bad.id]?.failOnStart = true // воркер ещё не создан — флаг в createWorker ниже
        // NOTE: флаг ставим через хук: createWorker вернёт фейк, старт упадёт
        // внутри manager.start → исключение изолировано
        val failing = object : ConnectionManager.Owner by h {
            override fun createWorker(profile: SessionStore.Profile, sessionId: String): ConnectionManager.Worker {
                return object : ConnectionManager.Worker by FakeWorker(h.shared, sessionId) {
                    override fun start() = throw RuntimeException("boom")
                }
            }
        }
        val mf = ConnectionManager(failing)
        // старт воркера упал — сессия изолированно в ERROR (не исключение наружу)
        val failed = mf.start(profile(1))
        assertNotNull(failed)
        assertEquals("ERROR", failed!!.state)
        // после фейла старта менеджер продолжает принимать сессии
        assertNotNull(mf.start(profile(2)))
        assertEquals(2, mf.count()) // упавшая сессия остаётся в реестре с ERROR
        mf.stopAll()
    }

    @Test
    fun statsEvents_carrySessionId() {
        val h = Harness()
        val m = ConnectionManager(h)
        assertNotNull(m.start(profile(1)))
        assertNotNull(m.start(profile(2)))
        h.workers["s1"]!!.bytes = 1000L to 2000L
        h.workers["s2"]!!.bytes = 3000L to 0L
        // помпа 500 мс — ждём до 3 с
        assertTrue(h.statsLatch.await(3, TimeUnit.SECONDS))
        Thread.sleep(600) // второй тик для ненулевых rate
        val ids = synchronized(h.stats) { h.stats.map { it.first } }
        assertTrue(ids.contains("s1"))
        assertTrue(ids.contains("s2"))
        assertEquals(1000L, m.byId("s1")!!.txTotal)
        assertEquals(2000L, m.byId("s1")!!.rxTotal)
        assertEquals(3000L, m.byId("s2")!!.txTotal)
        m.stopAll()
    }

    @Test
    fun workerState_updatesSession_backoffOnlyViaConnected() {
        val h = Harness()
        val m = ConnectionManager(h)
        assertNotNull(m.start(profile(1)))
        m.workerFailed("s1", "x")
        assertEquals(1, m.byId("s1")!!.backoffAttempt.get())
        // workerState НЕ трогает backoff (однозначный источник — workerConnected)
        m.workerState("s1", "CONNECTED", "ok", "rrp1")
        assertEquals(1, m.byId("s1")!!.backoffAttempt.get())
        assertEquals("CONNECTED", m.byId("s1")!!.state)
        // workerConnected сбрасывает backoff и считает реконнект после сбоя
        m.workerConnected("s1")
        assertEquals(0, m.byId("s1")!!.backoffAttempt.get())
        assertEquals(1, m.byId("s1")!!.reconnects.get())
        m.stopAll()
    }

    @Test
    fun logBuffer_ringPerSession() {
        val h = Harness()
        val m = ConnectionManager(h)
        assertNotNull(m.start(profile(1)))
        repeat(ConnectionManager.LOG_BUFFER + 10) { m.workerLog("s1", "line$it", LogKind.INFO) }
        val snap = m.byId("s1")!!.logSnapshot()
        assertEquals(ConnectionManager.LOG_BUFFER, snap.size)
        assertEquals("line${ConnectionManager.LOG_BUFFER + 9}", snap.last())
        assertFalse(snap.contains("line0"))
        m.stopAll()
    }
}
