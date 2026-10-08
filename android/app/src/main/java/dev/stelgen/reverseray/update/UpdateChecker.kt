package dev.stelgen.reverseray.update

import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

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
            UpdateInfo(tag, apkUrl, json.optString("body", ""))
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
    }

    private fun open(url: String): HttpURLConnection {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = 10_000
        conn.readTimeout = 15_000
        conn.setRequestProperty("Accept", "application/vnd.github+json")
        return conn
    }
}
