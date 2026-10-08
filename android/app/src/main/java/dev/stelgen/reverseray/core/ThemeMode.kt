package dev.stelgen.reverseray.core

/**
 * v0.8.1: Тема оформления — тёмная / светлая / АВТО.
 *
 * АВТО (по умолчанию) берёт текущую настройку телефона. На старых Android,
 * где системной тёмной темы нет (до API 29 — официальный общесистемный
 * режим), авто = чёрная по умолчанию (канон: «если системе нечего сказать —
 * не слепим юзера белым»).
 *
 * Логика вынесена в чистую функцию (тестируется без android.*): значения
 * совместимы с AppCompatDelegate.setDefaultNightMode().
 */
object ThemeMode {

    const val AUTO = "auto"
    const val DARK = "dark"
    const val LIGHT = "light"

    /** AppCompatDelegate.MODE_NIGHT_* (int-константы дублированы для чистоты тестов). */
    const val NIGHT_FOLLOW_SYSTEM = -1
    const val NIGHT_YES = 2
    const val NIGHT_NO = 1

    /** Нормализация сохранённого значения: мусор → AUTO (никогда не ошибка). */
    fun normalize(raw: String?): String = when (raw) {
        DARK -> DARK
        LIGHT -> LIGHT
        else -> AUTO
    }

    /**
     * Какой night-mode применить.
     * @param saved сохранённый выбор (null/мусор = AUTO)
     * @param sdkInt Build.VERSION.SDK_INT (параметр — для чистых тестов)
     */
    fun resolveNightMode(saved: String?, sdkInt: Int): Int = when (normalize(saved)) {
        DARK -> NIGHT_YES
        LIGHT -> NIGHT_NO
        else ->
            if (sdkInt >= 29) NIGHT_FOLLOW_SYSTEM // системная тёмная тема (Android 10+)
            else NIGHT_YES // старый Android: авто = чёрная по умолчанию
    }
}
