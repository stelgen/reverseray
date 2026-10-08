package dev.stelgen.reverseray.core

import dev.stelgen.reverseray.LimitReset
import dev.stelgen.reverseray.service.TunnelService
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Calendar

/**
 * Лимит трафика — «король» (v0.8): дата следующего сброса считается по
 * канону (сутки — завтра в 00:00; месяц — день сброса в 00:00).
 * Правило нуля байт проверяется на серверной стороне и в сервисе;
 * тут — бизнес-логика даты, от которой зависит «ждать или подключаться».
 */
class LimitResetTest {

    @Test
    fun `daily reset is tomorrow midnight`() {
        val now = Calendar.getInstance()
        val at = Calendar.getInstance()
        at.timeInMillis = LimitReset.nextResetAtMs(TunnelService.PERIOD_DAY, 1)
        // завтра
        val expected = (now.clone() as Calendar).apply {
            add(Calendar.DAY_OF_YEAR, 1)
            set(Calendar.HOUR_OF_DAY, 0)
            set(Calendar.MINUTE, 0)
            set(Calendar.SECOND, 0)
            set(Calendar.MILLISECOND, 0)
        }
        assertEquals(expected.timeInMillis, at.timeInMillis)
    }

    @Test
    fun `monthly reset uses reset day`() {
        val at = Calendar.getInstance()
        at.timeInMillis = LimitReset.nextResetAtMs(TunnelService.PERIOD_MONTH, 15)
        assertEquals(15, at.get(Calendar.DAY_OF_MONTH))
        assertEquals(0, at.get(Calendar.HOUR_OF_DAY))
        assertEquals(0, at.get(Calendar.MINUTE))
        assertEquals(0, at.get(Calendar.SECOND))
        // дата в будущем
        assertTrue(at.timeInMillis > System.currentTimeMillis())
    }

    @Test
    fun `reset day clamped to 28`() {
        val at = Calendar.getInstance()
        at.timeInMillis = LimitReset.nextResetAtMs(TunnelService.PERIOD_MONTH, 31)
        assertEquals(28, at.get(Calendar.DAY_OF_MONTH))
    }
}