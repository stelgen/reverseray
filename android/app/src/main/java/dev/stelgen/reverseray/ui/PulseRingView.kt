package dev.stelgen.reverseray.ui

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.view.View
import android.view.animation.LinearInterpolator
import kotlin.math.min
import kotlin.math.sin

/**
 * v0.9.3: кольца состояния кнопки Старт — канон анимаций 2026:
 *  - CONNECTING: современный indeterminate — дуга с «дышащим» размахом
 *    (sweep 60°..300° по синусоиде) плавно вращается по трек-кольцу
 *    (LinearInterpolator, 1400мс — без дёрганья и без прыжков фазы);
 *  - CONNECTED: два «дыхательных» кольца со сдвигом фазы π (лёгкий
 *    scale + затухание альфы, 1800мс — спокойная индикация живого туннеля);
 *  - IDLE: не рисует ничего.
 *
 * ValueAnimator + Canvas — доступно с API 14 (канон Android 4.0).
 * Цвета задаёт владелец (тема/режим кнопки), вью не знает про бизнес-логику.
 */
class PulseRingView(context: Context) : View(context) {

    enum class Kind { IDLE, CONNECTING, CONNECTED }

    var kind = Kind.IDLE
        private set

    private var accent = 0xFF39D98A.toInt()
    private var track = 0x26888888
    private var strokePx = 4f

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        isDither = false
    }
    private val arcRect = RectF()
    private var animator: ValueAnimator? = null
    private var phase = 0f

    /** Цвет дуги/колец и едва заметного трека (ARGB). */
    fun setColors(accentColor: Int, trackColor: Int = track) {
        accent = accentColor
        track = trackColor
        invalidate()
    }

    fun setStrokeWidthPx(px: Float) {
        strokePx = px
        invalidate()
    }

    /** Переключение режима: смена вида анимации без визуального скачка. */
    fun start(newKind: Kind) {
        if (kind == newKind && animator?.isRunning == true) return
        kind = newKind
        restartLoop()
    }

    fun stop() {
        if (kind == Kind.IDLE && animator == null) return
        kind = Kind.IDLE
        animator?.cancel()
        animator = null
        phase = 0f
        invalidate()
    }

    private fun restartLoop() {
        animator?.cancel()
        val loopMs = if (kind == Kind.CONNECTING) 1400L else 1800L
        animator = ValueAnimator.ofFloat(0f, 1f).apply {
            duration = loopMs
            repeatCount = ValueAnimator.INFINITE
            interpolator = LinearInterpolator()
            addUpdateListener { a ->
                phase = a.animatedValue as Float
                invalidate()
            }
            start()
        }
    }

    override fun onVisibilityAggregated(isVisible: Boolean) {
        super.onVisibilityAggregated(isVisible)
        // API 24+: экономия батареи — не крутить аниматор, когда вью невидимо.
        if (kind != Kind.IDLE) {
            if (isVisible && animator?.isRunning != true) restartLoop()
            if (!isVisible) animator?.cancel()
        }
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (kind == Kind.IDLE) return
        val cx = width / 2f
        val cy = height / 2f
        val baseR = min(cx, cy) - strokePx
        if (baseR <= strokePx) return
        when (kind) {
            Kind.CONNECTING -> {
                paint.strokeWidth = strokePx
                paint.alpha = 255
                paint.color = track
                canvas.drawCircle(cx, cy, baseR, paint)
                // «Дыхание» размаха дуги: 60°..300° по синусоиде — современный
                // indeterminate без резких переключений направления.
                val breath = (sin(phase * 2.0 * Math.PI).toFloat() + 1f) / 2f
                val sweep = 60f + 240f * breath
                val from = 360f * phase
                paint.color = accent
                arcRect.set(cx - baseR, cy - baseR, cx + baseR, cy + baseR)
                canvas.drawArc(arcRect, from, sweep, false, paint)
            }
            Kind.CONNECTED -> {
                paint.strokeWidth = strokePx
                // Два кольца со сдвигом фазы π: расходятся волной, гаснут, повтор.
                for (i in 0..1) {
                    val p = (phase + i * 0.5f) % 1f
                    val r = baseR * (1f + 0.07f * p)
                    paint.color = accent
                    paint.alpha = ((1f - p) * 0.55f * 255f).toInt().coerceIn(0, 255)
                    canvas.drawCircle(cx, cy, r, paint)
                }
                paint.alpha = 255
            }
            Kind.IDLE -> {}
        }
    }

    override fun onDetachedFromWindow() {
        animator?.cancel()
        animator = null
        super.onDetachedFromWindow()
    }
}