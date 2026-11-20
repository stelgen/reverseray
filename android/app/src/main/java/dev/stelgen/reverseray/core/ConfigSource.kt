package dev.stelgen.reverseray.core

/**
 * v1.8.4 — ЕДИНАЯ ТОЧКА ВАЛИДАЦИИ КОНФИГА-ССЫЛКИ.
 *
 * Ранее каждая зона (главная кнопка, пикеры протокола/транспорта, вставка
 * ссылки, сервис при смене протокола) валидировала строку сама через
 * try/catch RrpUri.parse — одинаковая логика была размазана по 7+ местам.
 * Теперь все зоны зовут ConfigSource.validate(): sanitize → parse → канон.
 *
 * Резолв для зон, у которых есть несколько источников (активный PRIMARY-
 * профиль реестра сессий и legacy-зеркало KEY_CONFIG): ConfigSource.
 * firstValid() возвращает первый ВАЛИДНЫЙ кандидат, иначе самое
 * информативное объяснение (первая Invalid или Empty).
 *
 * Pure Kotlin (канон core: без android.*), потокобезопасно (без состояния).
 */
sealed class ConfigResult {

    /** Валидный конфиг: разобранный + канонический вид ссылки. */
    class Valid(val cfg: RrpUriConfig, val canonical: String) : ConfigResult()

    /** Пусто/не задано — честный «нет конфига» (не ошибка парсера). */
    object Empty : ConfigResult()

    /** Ссылка не распознана: понятная причина (текст RrpUriException). */
    class Invalid(val reason: String) : ConfigResult()
}

object ConfigSource {

    /**
     * Единственная валидация строки конфига: бронепарсер (sanitize+parse)
     * чинит мусор сам; успех — канонический вид через serialize().
     */
    fun validate(raw: String?): ConfigResult {
        if (raw.isNullOrBlank()) return ConfigResult.Empty
        return try {
            val cfg = RrpUri.parse(raw)
            ConfigResult.Valid(cfg, cfg.serialize())
        } catch (e: Exception) {
            ConfigResult.Invalid(e.message ?: e.javaClass.simpleName)
        }
    }

    /**
     * Первый валидный кандидат слева направо (канон «активный профиль —
     * источник правды, зеркало KEY_CONFIG — его отражение»).
     * Ни один не валиден → первый Invalid (понятная причина) или Empty.
     */
    fun firstValid(vararg raws: String?): ConfigResult {
        var firstInvalid: ConfigResult.Invalid? = null
        for (raw in raws) {
            when (val res = validate(raw)) {
                is ConfigResult.Valid -> return res
                is ConfigResult.Invalid -> if (firstInvalid == null) firstInvalid = res
                ConfigResult.Empty -> {}
            }
        }
        return firstInvalid ?: ConfigResult.Empty
    }
}
