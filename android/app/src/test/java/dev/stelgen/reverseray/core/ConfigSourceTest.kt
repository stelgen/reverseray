package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * v1.8.4: тесты ЕДИНОЙ точки валидации конфига (ConfigSource) — все зоны
 * (главная кнопка, пикеры, вставка ссылки, сервис при смене протокола)
 * обязаны резолвить конфиг только через неё.
 */
class ConfigSourceTest {

    /** Реальная пользовательская ссылка (реплика жалобы #2/#3). */
    private val realLink =
        "rrp://Nwp8i_0QQ6M5zjtVMlKec8T8PW7xnT4BxTq82v2aZb8@94.198.110.135:4433/" +
            "?pin=3_a4YLvdiBcfYkDC7MRhZLaXFuX86AL7l6FnktzxaKw&name=phone-1"

    @Test
    fun validLink_parsesAndCanonicalizes() {
        val res = ConfigSource.validate(realLink)
        assertTrue(res is ConfigResult.Valid)
        res as ConfigResult.Valid
        assertEquals("94.198.110.135", res.cfg.host)
        assertEquals(listOf(4433), res.cfg.ports)
        assertEquals("phone-1", res.cfg.name)
        // повторная валидация канона — идемпотентна (тот же канон)
        val again = ConfigSource.validate(res.canonical)
        assertTrue(again is ConfigResult.Valid)
        assertEquals(res.canonical, (again as ConfigResult.Valid).canonical)
    }

    @Test
    fun emptyOrNull_isEmpty_notInvalid() {
        assertEquals(ConfigResult.Empty, ConfigSource.validate(null))
        assertEquals(ConfigResult.Empty, ConfigSource.validate(""))
        assertEquals(ConfigResult.Empty, ConfigSource.validate("   "))
    }

    @Test
    fun garbage_isInvalidWithReason() {
        val res = ConfigSource.validate("rrp://@:/")
        assertTrue(res is ConfigResult.Invalid)
        assertTrue((res as ConfigResult.Invalid).reason.isNotBlank())
    }

    @Test
    fun firstValid_prefersProfileOverMirror_andExplainsFailures() {
        // профиль валиден → выигрывает даже при битом зеркале
        val res = ConfigSource.firstValid(realLink, "rrp://@:/")
        assertTrue(res is ConfigResult.Valid)

        // профиль битый, зеркало валидно → зеркало
        val res2 = ConfigSource.firstValid("rrp://@:/", realLink)
        assertTrue(res2 is ConfigResult.Valid)

        // оба пусты → Empty
        assertEquals(ConfigResult.Empty, ConfigSource.firstValid(null, ""))

        // оба битые → первый Invalid с причиной
        val res3 = ConfigSource.firstValid("rrp://@:/", "rrp://@:/")
        assertTrue(res3 is ConfigResult.Invalid)
    }
}
