package dev.stelgen.reverseray.i18n

import dev.stelgen.reverseray.core.L10n
import dev.stelgen.reverseray.core.Lang
import dev.stelgen.reverseray.core.Msg
import dev.stelgen.reverseray.core.Msgs
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.Locale

/**
 * v0.8.3: ГЕЙТ хардкода — в src/main не должно остаться ни одного строкового
 * литерала с кириллицей ВНЕ каталога Msgs.kt (UI — ресурсы, core — Msgs).
 * Упавший тест печатает файл:строку:литерал — «какие поля пропущены» видно сразу.
 *
 * Плюс валидация каталога: en не пустой, ru — null (легальный EN-фолбэк)
 * или не пустой; фолбэк реально работает.
 */
class StringsGateTest {

    private fun sourceRoot(): File {
        var dir = File(System.getProperty("user.dir")!!)
        repeat(4) {
            if (File(dir, "src/main/java/dev/stelgen/reverseray").exists()) return dir
            dir = dir.parentFile ?: dir
        }
        error("src/main/java not found from ${System.getProperty("user.dir")}")
    }

    private val cyr = Regex("[\\u0400-\\u04FF]")
    private val literal = Regex("\"(?:\\\\.|[^\"\\\\\\n])*\"")

    @Test
    fun `no hardcoded cyrillic literals outside Msgs katalog`() {
        val root = sourceRoot()
        val offenders = mutableListOf<String>()
        root.resolve("src/main/java").walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .forEach { f ->
                if (f.name == "Msgs.kt") return@forEach // каталог переводов — легитимное место
                f.readLines().forEachIndexed { idx, line ->
                    literal.findAll(line).forEach { m ->
                        if (cyr.containsMatchIn(m.value)) {
                            offenders += "${f.relativeTo(root)}:${idx + 1}: ${m.value.take(80)}"
                        }
                    }
                }
            }
        assertTrue(
            "Хардкод-кириллица вне каталога (переведи в ресурсы или Msgs):\n" + offenders.joinToString("\n"),
            offenders.isEmpty(),
        )
    }

    @Test
    fun `every Msgs entry has non-blank en and valid ru`() {
        val fields = Msgs::class.java.declaredFields
        assertTrue("каталог пуст?", fields.isNotEmpty())
        val bad = mutableListOf<String>()
        for (f in fields) {
            f.isAccessible = true
            val msg = f.get(Msgs) as? Msg ?: continue
            if (msg.en.isBlank()) bad += "${f.name}: en is blank"
            if (msg.ru != null && msg.ru!!.isBlank()) bad += "${f.name}: ru is blank (используй null = фолбэк EN)"
        }
        assertTrue("битые записи каталога: $bad", bad.isEmpty())
    }

    @Test
    fun `fallback works - missing ru falls back to en`() {
        val saved = L10n.lang
        try {
            val m = Msg("Only English", null)
            L10n.lang = Lang.RU
            assertEquals("Only English", m.t())
            L10n.lang = Lang.EN
            assertEquals("Only English", m.t())

            val withRu = Msg("Hello", "Привет")
            L10n.lang = Lang.RU
            assertEquals("Привет", withRu.t())
            L10n.lang = Lang.EN
            assertEquals("Hello", withRu.t())
        } finally {
            L10n.lang = saved
        }
    }

    @Test
    fun `format uses US locale regardless of default`() {
        val saved = L10n.lang
        try {
            Locale.setDefault(Locale("ru", "RU")) // в ru-RU десятичный разделитель — запятая
            L10n.lang = Lang.EN
            // String.format(L10n.locale=US): 1.5 → "1.5", не "1,5"
            assertEquals("x = 1.5", Msg("x = %.1f", "x = %.1f").t(1.5))
        } finally {
            Locale.setDefault(Locale.US)
            L10n.lang = saved
        }
    }

    @Test
    fun `L10n resolve - ru to RU, garbage to EN`() {
        assertEquals(Lang.RU, L10n.resolve("ru"))
        assertEquals(Lang.RU, L10n.resolve("ru-RU"))
        assertEquals(Lang.RU, L10n.resolve("RU"))
        assertEquals(Lang.EN, L10n.resolve("en"))
        assertEquals(Lang.EN, L10n.resolve("en-US"))
        assertEquals(Lang.EN, L10n.resolve(null))
        assertEquals(Lang.EN, L10n.resolve(""))
        assertEquals(Lang.EN, L10n.resolve("de"))
        assertEquals(Lang.EN, L10n.resolve(";&drop table"))
    }
}