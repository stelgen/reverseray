package dev.stelgen.reverseray.update

import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/** Простое сравнение версий "0.4.1" — лексикографически по числовым сегментам. */
object SemVer {
    /** >0 если a новее b; 0 — равны; <0 — старее. Нечисловые сегменты сравниваются как строки. */
    fun compare(a: String, b: String): Int {
        val pa = a.trim().removePrefix("v").split('.').map { it.toIntOrNull() ?: 0 }
        val pb = b.trim().removePrefix("v").split('.').map { it.toIntOrNull() ?: 0 }
        val n = maxOf(pa.size, pb.size)
        for (i in 0 until n) {
            val x = pa.getOrElse(i) { 0 }
            val y = pb.getOrElse(i) { 0 }
            if (x != y) return x.compareTo(y)
        }
        return 0
    }
}

/** Результат проверки обновления. */
data class UpdateInfo(
    val latestTag: String,
    val apkUrl: String,
    val notes: String,
    /** v0.8.1: URL файла SHA256SUMS релиза — верификация APK перед установкой. */
    val sumsUrl: String = "",
)

/**
 * Проверка и загрузка обновления с GitHub Releases:
 *  - GET https://api.github.com/repos/{repo}/releases/latest
 *  - если tag новее текущей версии — возвращает UpdateInfo
 *  - downloadApk() качает APK-ассет в кэш для установки.
 *
 * v0.7.2 ФИКС: апдейтер искал ассет с именем "app-release.apk", а релизы
 * публикуют "reverseray-<версия>.apk" (переименование из v0.4.1) — из-за
 * этого апдейтер никогда не находил APK. Теперь берём ЛЮБОЙ *.apk-ассет
 * (предпочитая тот, что содержит "reverseray").
 *
 * v0.8.1 (анти-подмена): после скачивания APK сверяется с SHA256SUMS релиза
 * (verifyApk). Несовпадение → установка ОТМЕНЯЕТСЯ (TLS GitHub'а — первая
 * линия, сумма — вторая).
 */
class UpdateChecker(
    private val repo: String = "stelgen/reverseray",
) {

    /** Сравнивает последний релиз с текущей версией. null — апдейта нет/ошибка сети. */
    fun check(currentVersion: String): UpdateInfo? {
        return try {
            val conn = open("https://api.github.com/repos/$repo/releases/latest")
            if (conn.responseCode != 200) return null
            val body = conn.inputStream.use { it.bufferedReader().readText() }
            val json = JSONObject(body)
            if (json.optBoolean("prerelease", false) || json.optBoolean("draft", false)) return null
            val tag = json.optString("tag_name", "").removePrefix("v")
            if (tag.isEmpty() || SemVer.compare(tag, currentVersion) <= 0) return null
            val assets = json.optJSONArray("assets") ?: return null
            val apkUrl = pickApkAsset(assets) ?: return null
            val sumsUrl = pickSumsAsset(assets)
            UpdateInfo(tag, apkUrl, json.optString("body", ""), sumsUrl ?: "")
        } catch (_: Exception) {
            null
        }
    }

    /** Скачивает APK во временный файл (cacheDir). */
    fun downloadApk(info: UpdateInfo, dest: File): File {
        val conn = open(info.apkUrl)
        conn.connect()
        conn.inputStream.use { input ->
            dest.outputStream().use { output ->
                input.copyTo(output, 64 * 1024)
            }
        }
        return dest
    }

    /**
     * v0.8.1: верификация скачанного APK по SHA256SUMS релиза.
     * @return null — проверка пройдена (или SUMS недоступен: проверка best-effort
     *   по причине отсутствия ассета, но при СОВПАДЕНИИ всегда true);
     *   строка — причина отказа установки (подмена/битый файл).
     */
    fun verifyApk(apk: File, sumsBody: String?): String? {
        if (sumsBody.isNullOrBlank()) return null // SUMS нет в релизе — не блокируем
        val expected = expectedSha256For(sumsBody, apk.name) ?: return null // нет записи о нашем файле
        val actual = sha256Hex(apk)
        if (!MessageDigest.isEqual(
                expected.toByteArray(Charsets.US_ASCII),
                actual.toByteArray(Charsets.US_ASCII),
            )
        ) {
            return "SHA256 APK не совпал с SHA256SUMS релиза ($actual ≠ $expected) — установка отменена (возможна подмена)"
        }
        return null
    }

    /** Скачивает SHA256SUMS (если ассет есть). null — нет/недоступен. */
    fun downloadSums(sumsUrl: String): String? {
        if (sumsUrl.isEmpty()) return null
        return try {
            val conn = open(sumsUrl)
            if (conn.responseCode != 200) return null
            conn.inputStream.use { it.bufferedReader().readText() }
        } catch (_: Exception) {
            null
        }
    }

    companion object {
        /** URL первого *.apk-ассета (предпочтение "reverseray*"). null — апк нет. */
        fun pickApkAsset(assets: org.json.JSONArray): String? {
            var fallback: String? = null
            for (i in 0 until assets.length()) {
                val a = assets.getJSONObject(i)
                val name = a.optString("name", "")
                if (!name.endsWith(".apk", ignoreCase = true)) continue
                val url = a.optString("browser_download_url", "")
                if (url.isEmpty()) continue
                if (name.contains("reverseray", ignoreCase = true)) return url
                if (fallback == null) fallback = url
            }
            return fallback
        }

        /** URL ассета SHA256SUMS (v0.8.1). null — ассета нет. */
        fun pickSumsAsset(assets: org.json.JSONArray): String? {
            for (i in 0 until assets.length()) {
                val a = assets.getJSONObject(i)
                val name = a.optString("name", "")
                if (name.equals("SHA256SUMS", ignoreCase = true) || name.endsWith(".sha256", ignoreCase = true)) {
                    val url = a.optString("browser_download_url", "")
                    if (url.isNotEmpty()) return url
                }
            }
            return null
        }

        /** Извлекает sha256 для файла [name] из текста SHA256SUMS ("<hash>  <name>"). */
        fun expectedSha256For(sumsBody: String, name: String): String? {
            for (line in sumsBody.lineSequence()) {
                val parts = line.trim().split(Regex("\\s+"), limit = 2)
                if (parts.size == 2 && (parts[1] == name || parts[1] == "*$name")) {
                    val h = parts[0].lowercase()
                    if (h.matches(Regex("^[0-9a-f]{64}$"))) return h
                }
            }
            return null
        }

        /** SHA256 файла в hex. */
        fun sha256Hex(file: File): String {
            val md = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    md.update(buf, 0, n)
                }
            }
            return md.digest().joinToString("") { String.format("%02x", it) }
        }
    }

    private fun open(url: String): HttpURLConnection {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = 10_000
        conn.readTimeout = 15_000
        conn.setRequestProperty("Accept", "application/vnd.github+json")
        return conn
    }
}
