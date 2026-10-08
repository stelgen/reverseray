package dev.stelgen.reverseray.update

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

/** v0.8.1: верификация APK по SHA256SUMS релиза (анти-подмена). */
@RunWith(RobolectricTestRunner::class) // org.json в unit-тестах живёт в Robolectric
@Config(sdk = [31])
class UpdateCheckerSumTest {

    @Test
    fun `pickSumsAsset finds SHA256SUMS`() {
        val assets = org.json.JSONArray(
            """[
              {"name":"reverseray-0.8.1.apk","browser_download_url":"https://github.com/x/reverseray-0.8.1.apk"},
              {"name":"SHA256SUMS","browser_download_url":"https://github.com/x/SHA256SUMS"}
            ]""",
        )
        assertEquals("https://github.com/x/SHA256SUMS", UpdateChecker.pickSumsAsset(assets))
    }

    @Test
    fun `pickSumsAsset returns null when absent`() {
        val assets = org.json.JSONArray("""[{"name":"x.apk","browser_download_url":"https://x/x.apk"}]""")
        assertNull(UpdateChecker.pickSumsAsset(assets))
    }

    @Test
    fun `expectedSha256For parses canonical sums`() {
        val h1 = "a".repeat(64)
        val h2 = "b".repeat(64)
        val sums = "$h1  reverseray-0.8.1.apk\n$h2  other.apk\n"
        assertEquals(h1, UpdateChecker.expectedSha256For(sums, "reverseray-0.8.1.apk"))
        assertNull(UpdateChecker.expectedSha256For(sums, "missing.apk"))
        // не-хеш (не 64 hex) не принимается
        assertNull(UpdateChecker.expectedSha256For("abc123  reverseray-0.8.1.apk", "reverseray-0.8.1.apk"))
    }

    @Test
    fun `verifyApk accepts matching sum`() {
        val f = File.createTempFile("rr-test", ".apk")
        try {
            f.writeText("apk-bytes")
            val real = UpdateChecker.sha256Hex(f)
            assertEquals(
                "совпадающая сумма — установка разрешена",
                null,
                UpdateChecker().verifyApk(f, "$real  ${f.name}\n"),
            )
        } finally {
            f.delete()
        }
    }

    @Test
    fun `verifyApk rejects mismatched sum`() {
        val f = File.createTempFile("rr-test", ".apk")
        try {
            f.writeText("apk-bytes")
            val wrong = "f".repeat(64)
            val err = UpdateChecker().verifyApk(f, "$wrong  ${f.name}\n")
            assertTrue("несовпадение должно отменять установку", err != null && err.contains("SHA256"))
        } finally {
            f.delete()
        }
    }
    @Test
    fun `verifyApk without sums is best-effort pass`() {
        val f = File.createTempFile("rr-test", ".apk")
        try {
            f.writeText("apk-bytes")
            assertNull(UpdateChecker().verifyApk(f, null))
            assertNull(UpdateChecker().verifyApk(f, ""))
            // файл есть в релизе, но наш ассет не описан — не блокируем
            assertNull(UpdateChecker().verifyApk(f, "abc  other.apk"))
        } finally {
            f.delete()
        }
    }
}
