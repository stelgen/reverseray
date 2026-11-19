package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * v1.8.3: тесты очереди паркинга смены протокола (SwitchParking) —
 * канон v1.3.0 «буфер в RAM без дропов, backpressure»:
 * park/offer/unpark, переполнение окна (блокировка отправителя),
 * смерть сессии (close разблокирует), возобновление.
 */
class SwitchParkingTest {

    private fun data(id: Long) = RrpFrame.Data(id, 0, byteArrayOf(1, 2, 3))

    @Test
    fun `offer without park takes the normal path`() {
        val p = SwitchParking(4)
        assertFalse(p.isParked())
        assertFalse(p.offer(data(1L)) { true })
        assertTrue(p.unpark().isEmpty())
    }

    @Test
    fun `park queues frames and unpark drains in order`() {
        val p = SwitchParking(4)
        p.park()
        assertTrue(p.isParked())
        assertTrue(p.offer(data(1L)) { true })
        assertTrue(p.offer(data(2L)) { true })
        assertTrue(p.offer(data(3L)) { true })
        val queued = p.unpark()
        assertEquals(3, queued.size)
        assertEquals(1L, (queued[0] as RrpFrame.Data).streamId)
        assertEquals(2L, (queued[1] as RrpFrame.Data).streamId)
        assertEquals(3L, (queued[2] as RrpFrame.Data).streamId)
        assertFalse(p.isParked())
        // повторный unpark — пусто (паркинг снят)
        assertTrue(p.unpark().isEmpty())
    }

    @Test
    fun `overflow blocks the sender until unpark (backpressure)`() {
        val p = SwitchParking(2)
        p.park()
        assertTrue(p.offer(data(1L)) { true })
        assertTrue(p.offer(data(2L)) { true })
        // очередь полна: offer в другом потоке блокируется
        val started = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val blocked = Thread {
            started.countDown()
            p.offer(data(3L)) { true }
            finished.countDown()
        }
        blocked.isDaemon = true
        blocked.start()
        assertTrue(started.await(2, TimeUnit.SECONDS))
        assertFalse(finished.await(200, TimeUnit.MILLISECONDS)) // ждёт — backpressure
        val queued = p.unpark()
        assertEquals(2, queued.size)
        assertTrue(finished.await(3, TimeUnit.SECONDS)) // разблокирован снятием паркинга
        blocked.join(3000)
        // после снятия паркинга offer идёт обычным путём
        assertFalse(p.offer(data(4L)) { true })
    }

    @Test
    fun `unparked mid-wait takes the normal path`() {
        val p = SwitchParking(1)
        p.park()
        assertTrue(p.offer(data(1L)) { true })
        val finished = CountDownLatch(1)
        val result = arrayOf(false)
        val blocked = Thread {
            result[0] = p.offer(data(2L)) { true }
            finished.countDown()
        }
        blocked.isDaemon = true
        blocked.start()
        Thread.sleep(200)
        p.unpark() // снимаем паркинг — заблокированный отправитель уходит обычным путём
        assertTrue(finished.await(3, TimeUnit.SECONDS))
        assertFalse(result[0])
    }

    @Test
    fun `close clears the queue and unblocks the blocked sender`() {
        val p = SwitchParking(1)
        p.park()
        assertTrue(p.offer(data(1L)) { true })
        val started = CountDownLatch(1)
        val err = arrayOfNulls<Exception>(1)
        val blocked = Thread {
            started.countDown()
            try {
                p.offer(data(2L)) { true }
            } catch (e: Exception) {
                err[0] = e
            }
        }
        blocked.isDaemon = true
        blocked.start()
        assertTrue(started.await(2, TimeUnit.SECONDS))
        Thread.sleep(100)
        p.close() // смерть сессии
        blocked.join(3000)
        assertTrue(err[0] is RrpClientException)
        assertTrue(p.unpark().isEmpty())
    }

    @Test
    fun `dead session throws instead of waiting forever`() {
        val p = SwitchParking(1)
        p.park()
        assertTrue(p.offer(data(1L)) { true })
        var thrown: Exception? = null
        try {
            p.offer(data(2L)) { false } // сессия мертва — ждать нечего
        } catch (e: Exception) {
            thrown = e
        }
        assertTrue(thrown is RrpClientException)
    }

    @Test
    fun `parked frames max default and env bounds`() {
        assertEquals(256, RrpClient.DEFAULT_PARKED_FRAMES_MAX)
        // resolveParkedFramesMax без env-переменной — дефолт (env в CI-окружении не задан)
        val resolved = RrpClient.resolveParkedFramesMax()
        assertTrue(resolved in 16..4096)
    }
}
