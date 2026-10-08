package dev.stelgen.reverseray

import android.app.Application
import android.content.Context
import android.os.Build
import androidx.appcompat.app.AppCompatDelegate
import androidx.multidex.MultiDex
import dev.stelgen.reverseray.core.ThemeMode
import dev.stelgen.reverseray.service.TunnelService

/**
 * Application-класс: legacy multidex для API 14–20
 * (AGP требует multiDexEnabled при core desugaring; на 21+ dex2art нативный).
 *
 * v0.8.1: тема применяется до создания любой Activity:
 *  - «авто» (по умолчанию) — берём настройку телефона (Android 10+);
 *    на старых Android, где системной тёмной темы нет, авто = чёрная;
 *  - «тёмная»/«светлая» — явный выбор пользователя (Настройки → Тема).
 */
class App : Application() {
    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(base)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            MultiDex.install(this)
        }
    }

    override fun onCreate() {
        super.onCreate()
        applySavedTheme()
    }

    private fun applySavedTheme() {
        try {
            val saved = getSharedPreferences(TunnelService.PREFS, MODE_PRIVATE)
                .getString(TunnelService.KEY_THEME, ThemeMode.AUTO)
            AppCompatDelegate.setDefaultNightMode(
                ThemeMode.resolveNightMode(saved, Build.VERSION.SDK_INT),
            )
        } catch (_: Exception) {
            // тема — не критичный путь: приложение работает и без неё
        }
    }
}
