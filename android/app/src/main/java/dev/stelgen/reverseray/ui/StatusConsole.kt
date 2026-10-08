package dev.stelgen.reverseray.ui

import android.content.Context
import android.graphics.Typeface
import android.os.Build
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.util.AttributeSet
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView

/**
 * Единое окно статуса/лога (v0.8) — один и тот же компонент на всех
 * вкладках: Главная, Обновление, Лог. Канон консистентности UI:
 *
 *  - тёмный «девопс-терминал», моно-шрифт, листается колесом/пальцем;
 *  - кнопка «↧ live» ВНУТРИ шапки бара: пользователь проскроллил вверх —
 *    автопрокрутка отключается, нажал live — вернулись в реалтайм;
 *  - положение сохраняется при сворачивании/переключении вкладок
 *    (компонент один, содержимое не пересоздаётся);
 *  - цветовые роли строк: зелёный — подключилось/туннель поднялся,
 *    красный — падал/ошибка, тёмно-жёлтый — важное уведомление,
 *    белый — информационная беготня;
 *  - ничего не прячем: всё, что делаем с сетью/данными юзера, пишется
 *    сюда же (канон приватности).
 */
class StatusConsole @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : LinearLayout(context, attrs) {

    /** Роль строки: цвет по канону. */
    enum class Role { INFO, OK, WARN, ERR }

    class Line(val text: String, val role: Role = Role.INFO)

    private val header = LinearLayout(context).apply {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setBackgroundColor(0xFF141B2E.toInt())
        setPadding(dp(10), dp(4), dp(6), dp(4))
    }
    private val headerSpinner = ProgressBar(context).apply {
        layoutParams = LinearLayout.LayoutParams(dp(16), dp(16)).apply { setMargins(0, 0, dp(8), 0) }
        isIndeterminate = true
        // API 21+: метод добавлен в Lollipop — на API 14-20 вызов упал бы
        if (Build.VERSION.SDK_INT >= 21) {
            indeterminateTintList = android.content.res.ColorStateList.valueOf(0xFFF9A825.toInt())
        }
        visibility = View.GONE
    }
    private val headerIcon = TextView(context).apply {
        textSize = 13f
        setTypeface(typeface, Typeface.BOLD)
        setPadding(0, 0, dp(6), 0)
    }
    private val headerTitle = TextView(context).apply {
        textSize = 12f
        setTextColor(0xFF8FA3D9.toInt())
        layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        maxLines = 1
        ellipsize = android.text.TextUtils.TruncateAt.END
    }
    private val liveBtn = TextView(context).apply {
        // v0.8.2: подпись кнопки — на языке приложения (не хардкод)
        text = context.getString(dev.stelgen.reverseray.R.string.console_live)
        textSize = 11f
        setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
        setPadding(dp(8), dp(2), dp(8), dp(2))
        setTextColor(0xFF8BD17C.toInt())
        // «кнопка в баре», не отдельная огромная кнопка
        setBackgroundResource(android.R.drawable.list_selector_background)
        setOnClickListener { followLive() }
    }
    private val scroll = ScrollView(context).apply {
        setBackgroundColor(0xFF0B1020.toInt())
        isVerticalScrollBarEnabled = true
    }
    private val body = TextView(context).apply {
        typeface = Typeface.MONOSPACE
        textSize = 11f
        setTextColor(0xFFD8DCE6.toInt())
        setPadding(dp(10), dp(8), dp(10), dp(10))
        setTextIsSelectable(true)
    }

    private val lines = mutableListOf<Line>()
    private val maxLines = 300
    private var follow = true
    private var baseHeightDp = 150

    init {
        orientation = VERTICAL
        header.addView(headerSpinner)
        header.addView(headerIcon)
        header.addView(headerTitle)
        header.addView(liveBtn)
        addView(header, LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT))
        scroll.addView(body)
        addView(
            scroll,
            LayoutParams(LayoutParams.MATCH_PARENT, dp(baseHeightDp)).apply {
                weight = 1f
            },
        )
        // палец вверх по телу = выйти из live-режима
        scroll.setOnTouchListener { v, ev ->
            if (ev.action == MotionEvent.ACTION_UP && !atBottom()) {
                follow = false
                liveBtn.setTextColor(0xFFF9A825.toInt())
                liveBtn.text = context.getString(dev.stelgen.reverseray.R.string.console_to_live)
            }
            v.performClick()
            false
        }
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun atBottom(): Boolean {
        val sh = scroll
        return sh.scrollY + sh.height >= body.height - dp(24)
    }

    /** Возврат к отображению в реалтайм (кнопка live в шапке). */
    fun followLive() {
        follow = true
        liveBtn.setTextColor(0xFF8BD17C.toInt())
        liveBtn.text = context.getString(dev.stelgen.reverseray.R.string.console_live)
        scrollToBottom()
    }

    private fun scrollToBottom() {
        scroll.post { scroll.fullScroll(View.FOCUS_DOWN) }
    }

    /** Высота тела в dp (не меняет положение при переключении вкладок). */
    fun setBodyHeight(dpValue: Int) {
        baseHeightDp = dpValue
        (scroll.layoutParams as? LayoutParams)?.height = dp(dpValue)
        (scroll.layoutParams as? LayoutParams)?.weight = 0f
        scroll.layoutParams = scroll.layoutParams
    }

    fun setTitle(title: String) {
        headerTitle.text = title
    }

    /** Шапка: спиннер + иконка состояния (как на главной, зеркально). */
    fun setHeaderState(icon: String?, color: Int, spinning: Boolean) {
        headerSpinner.visibility = if (spinning) View.VISIBLE else View.GONE
        headerIcon.visibility = if (spinning || icon == null) View.GONE else View.VISIBLE
        if (icon != null) headerIcon.text = icon
        headerIcon.setTextColor(color)
    }

    /** Полная замена содержимого (снапшоты из сервиса). */
    fun render(newLines: List<Line>) {
        synchronized(lines) {
            lines.clear()
            lines.addAll(newLines.takeLast(maxLines))
            body.text = buildSpannable()
        }
        if (follow) scrollToBottom()
    }

    /** Инкрементальная добавка (реалтайм, дёшево). */
    fun append(line: Line) {
        synchronized(lines) {
            lines.add(line)
            while (lines.size > maxLines) lines.removeAt(0)
            body.text = buildSpannable()
        }
        if (follow) scrollToBottom()
    }

    fun snapshotText(): String = synchronized(lines) { lines.joinToString("\n") { it.text } }

    private fun buildSpannable(): SpannableStringBuilder {
        val sb = SpannableStringBuilder()
        synchronized(lines) {
            for (i in lines.indices) {
                if (i > 0) sb.append('\n')
                val start = sb.length
                sb.append(lines[i].text)
                val color = when (lines[i].role) {
                    Role.OK -> 0xFF39D98A.toInt()
                    Role.WARN -> 0xFFC79A2A.toInt() // тёмно-жёлтый: важное, не крикливое
                    Role.ERR -> 0xFFFF6B6B.toInt()
                    Role.INFO -> 0xFFD8DCE6.toInt() // белая «беготня»
                }
                sb.setSpan(
                    ForegroundColorSpan(color),
                    start,
                    sb.length,
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE,
                )
            }
        }
        return sb
    }
}