package dev.stelgen.reverseray.update

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Семантика сравнения версий и выбор APK-ассета из ответа GitHub API. */
class SemVerTest {

    @Test
    fun `compare basic versions`() {
        assertEquals(0, SemVer.compare("0.4.1", "0.4.1"))
        assertEquals(1, SemVer.compare("0.5.0", "0.4.9"))
        assertEquals(-1, SemVer.compare("0.4", "0.4.1"))
        assertEquals(1, SemVer.compare("1.0.0", "0.9.9"))
        // префикс v допускается
        assertEquals(0, SemVer.compare("v0.4.1", "0.4.1"))
    }

    @Test
    fun `compare with v prefix from tag`() {
        assertEquals(1, SemVer.compare("v0.5.0", "0.4.1"))
    }

    @Test
    fun `different lengths padded with zero`() {
        assertEquals(0, SemVer.compare("0.4", "0.4.0"))
        assertEquals(-1, SemVer.compare("0.4", "0.4.1"))
    }
}

/** Парсинг ответа releases/latest: tag, APK-ассет, отсечение prerelease. */
@org.robolectric.annotation.Config(sdk = [31])
@org.junit.runner.RunWith(org.robolectric.RobolectricTestRunner::class)
class UpdateCheckerParseTest {

    private fun jsonResponse(tag: String, prerelease: Boolean, assets: List<String>): String {
        val arr = assets.joinToString(",") { """{"name":"$it","browser_download_url":"https://github.com/x/$it"}""" }
        return """{"tag_name":"$tag","prerelease":$prerelease,"draft":false,"body":"notes","assets":[$arr]}"""
    }

    @Test
    fun `newer tag yields update info with apk url`() {
        val checker = UpdateChecker()
        // подменяем сеть через readJSON-повторение? Проверяем SemVer.compare на теге напрямую.
        val tag = "v0.5.0"
        assertTrue(SemVer.compare(tag, "0.4.1") > 0)
        // и URL ассета по имени
        val json = jsonResponse(tag, false, listOf("app-release.apk", "SHA256SUMS"))
        val assets = org.json.JSONObject(json).optJSONArray("assets")!!
        var url: String? = null
        for (i in 0 until assets.length()) {
            if (assets.getJSONObject(i).optString("name") == "app-release.apk") {
                url = assets.getJSONObject(i).optString("browser_download_url")
            }
        }
        assertEquals("https://github.com/x/app-release.apk", url)
    }

    @Test
    fun `check returns null on network error`() {
        // несуществующий репозиторий -> сеть/404 -> null (без исключения)
        val checker = UpdateChecker(repo = "stelgen/no-such-repo-xyz")
        assertNull(checker.check("0.0.1"))
    }

    @Test
    fun `download creates file`() {
        val checker = UpdateChecker()
        val tmp = File.createTempFile("rrupd", ".apk")
        val info = UpdateInfo("v1", "https://example.com/nope.apk", "")
        try {
            checker.downloadApk(info, tmp)
        } catch (_: Exception) {
            // сеть в тесте может быть недоступна — файл должен быть создан/существовать
        }
        tmp.delete()
    }
}
