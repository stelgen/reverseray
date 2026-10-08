package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * v0.8.1: тема — авто/тёмная/светлая. АВТО берёт настройку телефона
 * (Android 10+); на старых Android, где системной тёмной темы нет,
 * авто = чёрная по умолчанию.
 */
class ThemeModeTest {

    @Test
    fun `auto follows system on modern android`() {
        assertEquals(ThemeMode.NIGHT_FOLLOW_SYSTEM, ThemeMode.resolveNightMode(ThemeMode.AUTO, 29))
        assertEquals(ThemeMode.NIGHT_FOLLOW_SYSTEM, ThemeMode.resolveNightMode(ThemeMode.AUTO, 34))
    }

    @Test
    fun `auto is black on old android`() {
        // до API 29 системной тёмной темы нет — авто = чёрная (канон)
        assertEquals(ThemeMode.NIGHT_YES, ThemeMode.resolveNightMode(ThemeMode.AUTO, 14))
        assertEquals(ThemeMode.NIGHT_YES, ThemeMode.resolveNightMode(ThemeMode.AUTO, 21))
        assertEquals(ThemeMode.NIGHT_YES, ThemeMode.resolveNightMode(ThemeMode.AUTO, 28))
    }

    @Test
    fun `explicit choices always win`() {
        assertEquals(ThemeMode.NIGHT_YES, ThemeMode.resolveNightMode(ThemeMode.DARK, 34))
        assertEquals(ThemeMode.NIGHT_YES, ThemeMode.resolveNightMode(ThemeMode.DARK, 14))
        assertEquals(ThemeMode.NIGHT_NO, ThemeMode.resolveNightMode(ThemeMode.LIGHT, 34))
        assertEquals(ThemeMode.NIGHT_NO, ThemeMode.resolveNightMode(ThemeMode.LIGHT, 14))
    }

    @Test
    fun `garbage value normalizes to auto`() {
        assertEquals(ThemeMode.AUTO, ThemeMode.normalize(null))
        assertEquals(ThemeMode.AUTO, ThemeMode.normalize(""))
        assertEquals(ThemeMode.AUTO, ThemeMode.normalize("bagel"))
        assertEquals(ThemeMode.DARK, ThemeMode.normalize("dark"))
        assertEquals(ThemeMode.LIGHT, ThemeMode.normalize("light"))
    }
}
