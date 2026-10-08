package dev.stelgen.reverseray.core

import java.util.Locale

/**
 * v0.8.3: типизированная многоязычность core-слоя (канон i18n).
 *
 * Core-слой (RrpClient/RrpFrame/MtProto/...) — pure Kotlin без android.*:
 * у него нет Context и доступа к ресурсам. Поэтому его сообщения живут в
 * типизированном каталоге [Msgs] (объекты [Msg]), а не в ресурсах.
 *
 * Правила канона:
 *  - EN — канонический фолбэк: если RU-перевод не задан (null), всегда EN;
 *  - язык выбирается один раз в App.onCreate (из prefs) и при смене языка
 *    пользователем; core-статика читает [L10n.lang] на момент события —
 *    новые строки лога сразу на выбранном языке (старые записи не переписываются);
 *  - новый код ОБЯЗАН использовать Msgs.* для любых пользовательских строк
 *    (гейт-тест StringsGateTest не даёт протащить хардкод-кириллицу в src/main).
 */
enum class Lang { EN, RU }

object L10n {

    /** Текущий язык core-слоя. EN по умолчанию (канон: фолбэк = английский). */
    @Volatile
    var lang: Lang = Lang.EN

    /** Locale для String.format: числа/даты всегда ASCII-стабильные (не зависят от локали устройства). */
    val locale: Locale get() = Locale.US

    /**
     * Резолв языка из BCP-47 тега (или названия локали): "ru*" → RU, всё
     * прочее (включая мусор/пустое) → EN. Никогда не бросает.
     */
    fun resolve(languageTag: String?): Lang =
        if (!languageTag.isNullOrBlank() && languageTag.lowercase(Locale.US).startsWith("ru")) Lang.RU else Lang.EN
}

/**
 * Типизированное сообщение: [en] обязателен и служит фолбэком, [ru]
 * опционален (null = «перевода нет → EN»). Плейсхолдеры — %s/%d
 * (String.format с [L10n.locale]).
 */
class Msg(val en: String, val ru: String? = null) {

    /** Формат с аргументами (или без — для статических строк). */
    fun t(vararg args: Any?): String {
        val tpl = if (L10n.lang == Lang.RU) (ru ?: en) else en
        return if (args.isEmpty()) tpl else String.format(L10n.locale, tpl, *args)
    }
}