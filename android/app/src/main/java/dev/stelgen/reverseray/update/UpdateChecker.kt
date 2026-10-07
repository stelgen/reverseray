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
 *  - downloadApk() качает app-release.apk в кэш для установки.
 */
class UpdateChecker(
    private val repo: String = "stelgen/reverseray",
    private val apkAssetName: String = "app-release.apk",
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
            var apkUrl: String? = null
            for (i in 0 until assets.length()) {
                val a = assets.getJSONObject(i)
                if (a.optString("name") == apkAssetName) {
                    apkUrl = a.optString("browser_download_url")
                    break
                }
            }
            if (apkUrl.isNullOrEmpty()) return null
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

    private fun open(url: String): HttpURLConnection {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = 10_000
        conn.readTimeout = 15_000
        conn.setRequestProperty("Accept", "application/vnd.github+json")
        return conn
    }
}
