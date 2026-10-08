package dev.stelgen.reverseray

import android.content.Context
import android.content.res.Configuration
import android.os.Build
import dev.stelgen.reverseray.core.L10n
import dev.stelgen.reverseray.core.Lang
import dev.stelgen.reverseray.service.TunnelService
import java.util.Locale

/**
 * v0.8.3: выбор языка интерфейса (канон i18n).
 *
 * Хранение: prefs [TunnelService.PREFS] → [KEY_LANG] = system|ru|en
 * (дефолт — system). Применение — через createConfigurationContext в
 * attachBaseContext у App/MainActivity/TunnelService: covers Activity,
 * сервис и уведомления единообразно, работает с API 14 без appcompat-магии.
 *
 * Фолбэк канона: если у строки нет перевода, ресурс-дефолт (values/) —
 * английский; для core-сообщений — Msg с en-фолбэком.
 *
 * Ядро ([L10n.lang]) переключается сразу в [applyCore] — новые строки лога
 * уходят на выбранном языке без перезапуска процесса.
 */
object L10nUi {

    const val KEY_LANG = "app_lang"
    const val LANG_SYSTEM = "system"
    const val LANG_RU = "ru"
    const val LANG_EN = "en"

    /** Нормализация сохранённого значения: мусор → system (никогда не ошибка). */
    fun normalize(raw: String?): String = when (raw) {
        LANG_RU -> LANG_RU
        LANG_EN -> LANG_EN
        else -> LANG_SYSTEM
    }

    /** Читает сохранённый выбор (без падений: prefs могут быть недоступны). */
    fun saved(base: Context): String =
        try {
            normalize(base.getSharedPreferences(TunnelService.PREFS, Context.MODE_PRIVATE).getString(KEY_LANG, LANG_SYSTEM))
        } catch (_: Exception) {
            LANG_SYSTEM
        }

    /**
     * Оборачивает базовый контекст выбранной локалью (ru/en); system —
     * возвращает base как есть. Вызывается из attachBaseContext.
     */
    fun wrap(base: Context): Context {
        val tag = when (saved(base)) {
            LANG_RU -> "ru"
            LANG_EN -> "en"
            else -> return base
        }
        val loc = Locale.forLanguageTag(tag)
        val cfg = Configuration(base.resources.configuration)
        if (Build.VERSION.SDK_INT >= 17) cfg.setLocale(loc) else @Suppress("DEPRECATION") cfg.locale = loc
        return base.createConfigurationContext(cfg)
    }

    /**
     * Синхронизирует язык ядра ([L10n.lang]) с выбором пользователя.
     * system → резолвим по текущей локали контекста; вызывается в App.onCreate
     * и при смене языка.
     */
    fun applyCore(ctx: Context): Lang {
        val lang = when (saved(ctx)) {
            LANG_RU -> Lang.RU
            LANG_EN -> Lang.EN
            else -> {
                val locale = if (Build.VERSION.SDK_INT >= 24) {
                    ctx.resources.configuration.locales[0]
                } else {
                    @Suppress("DEPRECATION") ctx.resources.configuration.locale
                }
                L10n.resolve(locale?.language)
            }
        }
        L10n.lang = lang
        return lang
    }

    /** Сохранить выбор и обновить ядро. Возвращает нормализованное значение. */
    fun save(ctx: Context, raw: String): String {
        val norm = normalize(raw)
        ctx.getSharedPreferences(TunnelService.PREFS, Context.MODE_PRIVATE)
            .edit().putString(KEY_LANG, norm).apply()
        applyCore(ctx)
        return norm
    }
}