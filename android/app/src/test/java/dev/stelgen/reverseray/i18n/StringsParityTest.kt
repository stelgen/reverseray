package dev.stelgen.reverseray.i18n

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * v0.8.3: ГЕЙТ многоязычности перед деплоем — «какой язык, какие поля
 * пропущены» видно сразу из сообщения упавшего теста.
 *
 * 1) Паритет RU↔EN: identical key sets; формат-аргументы (%1$s, %2$d…)
 *    обязаны совпадать у каждой пары (иначе крэш в рантайме на одной локали).
 * 2) Дефолт (values/) — английский: канон «фолбэк = EN».
 */
class StringsParityTest {

    private fun moduleDir(): File {
        var dir = File(System.getProperty("user.dir")!!)
        repeat(4) {
            if (File(dir, "src/main/res/values/strings.xml").exists()) return dir
            dir = dir.parentFile ?: dir
        }
        error("strings.xml not found from ${System.getProperty("user.dir")}")
    }

    private fun parse(path: File): Map<String, Pair<String, List<String>>> {
        val xml = path.readText()
        val re = Regex("<string name=\"([^\"]+)\"[^>]*>(.*?)</string>", RegexOption.DOT_MATCHES_ALL)
        val argRe = Regex("%\\d+\\$[sd]")
        val out = linkedMapOf<String, Pair<String, List<String>>>()
        for (m in re.findAll(xml)) {
            val name = m.groupValues[1]
            val value = m.groupValues[2]
            require(name !in out) { "duplicate key $name in ${path.name}" }
            out[name] = value to argRe.findAll(value).map { it.value }.sorted().toList()
        }
        return out
    }

    @Test
    fun `default locale is English (canon fallback)`() {
        val def = moduleDir().resolve("src/main/res/values/strings.xml").readText()
        assertTrue(def.contains("no limits"))
        assertTrue(!File(moduleDir(), "src/main/res/values-en").exists()) // values-en удалён (EN теперь default)
    }

    @Test
    fun `ru and default key sets are identical`() {
        val root = moduleDir()
        val en = parse(root.resolve("src/main/res/values/strings.xml"))
        val ru = parse(root.resolve("src/main/res/values-ru/strings.xml"))
        val onlyEn = en.keys - ru.keys
        val onlyRu = ru.keys - en.keys
        assertTrue("ключи только в EN (нет перевода RU): $onlyEn", onlyEn.isEmpty())
        assertTrue("ключи только в RU (нет ключа в EN): $onlyRu", onlyRu.isEmpty())
    }

    @Test
    fun `format args match between locales for every key`() {
        val root = moduleDir()
        val en = parse(root.resolve("src/main/res/values/strings.xml"))
        val ru = parse(root.resolve("src/main/res/values-ru/strings.xml"))
        val bad = en.keys.filter { k -> en[k]!!.second != ru[k]?.second }
        assertTrue("формат-аргументы не совпадают у ключей: $bad", bad.isEmpty())
    }

    @Test
    fun `no duplicate keys inside a locale file`() {
        val root = moduleDir()
        for (f in listOf("src/main/res/values/strings.xml", "src/main/res/values-ru/strings.xml")) {
            val names = Regex("name=\"([^\"]+)\"").findAll(root.resolve(f).readText()).map { it.groupValues[1] }.toList()
            val dup = names.groupBy { it }.filter { it.value.size > 1 }.keys
            assertTrue("дубликаты ключей в $f: $dup", dup.isEmpty())
        }
    }

    @Test
    fun `both locales carry the language picker strings`() {
        val root = moduleDir()
        val en = parse(root.resolve("src/main/res/values/strings.xml"))
        val ru = parse(root.resolve("src/main/res/values-ru/strings.xml"))
        for (k in listOf("settings_language", "lang_system", "lang_ru", "lang_en", "settings_language_saved")) {
            assertTrue("нет ключа $k в EN", en.containsKey(k))
            assertTrue("нет ключа $k в RU", ru.containsKey(k))
        }
        assertEquals("Language", en["settings_language"]!!.first)
        assertEquals("Язык", ru["settings_language"]!!.first)
    }
}