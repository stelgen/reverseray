package dev.stelgen.reverseray.ui

import android.content.Context
import dev.stelgen.reverseray.R
import java.util.Locale

/**
 * v0.8.3: общие форматтеры (до этого fmtBytes дублировался в MainActivity и
 * TunnelService с ХАРДКОДОМ единиц «ГБ/МБ/КБ/Б» — теперь единицы из ресурсов,
 * язык динамический; дубликат удалён — канон единого кода).
 */
object Formats {

    /** Байты → «1.23 GB» / «12.3 MB» / «456 KB» / «789 B» (единицы из ресурсов). */
    fun bytes(ctx: Context, b: Long): String = when {
        b >= 1L shl 30 -> String.format(Locale.US, ctx.getString(R.string.fmt_bytes_gb), b / 1073741824.0)
        b >= 1L shl 20 -> String.format(Locale.US, ctx.getString(R.string.fmt_bytes_mb), b / 1048576.0)
        b >= 1L shl 10 -> String.format(Locale.US, ctx.getString(R.string.fmt_bytes_kb), b / 1024.0)
        else -> String.format(Locale.US, ctx.getString(R.string.fmt_bytes_b), b)
    }

    /** Скорость → «123 KB/s» (из ресурсов). */
    fun kbps(ctx: Context, kbps: Double): String =
        String.format(Locale.US, ctx.getString(R.string.fmt_speed_kbps), kbps)

    /** Скорость в байт/с → «B/s / KB/s / MB/s» (v0.9.2: ось графика и подписи). */
    fun rate(ctx: Context, bytesPerSec: Long): String = when {
        bytesPerSec >= 1L shl 20 -> String.format(Locale.US, ctx.getString(R.string.rate_mb), bytesPerSec / (1024f * 1024f))
        bytesPerSec >= 1L shl 10 -> String.format(Locale.US, ctx.getString(R.string.rate_kb), bytesPerSec / 1024f)
        else -> String.format(Locale.US, ctx.getString(R.string.rate_b), bytesPerSec)
    }
}