package dev.stelgen.reverseray.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
import android.graphics.Shader
import android.view.View

import dev.stelgen.reverseray.R

/**
 * Реалтайм-график трафика (v0.7 → pro v1.5.1): две области — приём (rx,
 * зелёный) и отправка (tx, синий) в байт/с. Чистый Canvas — работает от
 * API 14, без дополнительных зависимостей.
 *
 * v1.5.1 «PRO»:
 *  - СГЛАЖЕННАЯ автошкала: максимум окна не «прыгает» — при всплеске
 *    поднимается мгновенно, спадает EMA-затуханием (кадры без дёрганья);
 *  - сетка из 4 пунктирных уровней с ЧЕЛОВЕЧЕСКИМИ подписями bps (max,
 *    3/4, 1/2, 1/4) справа;
 *  - легенда «▼ приём / ▲ отправка» слева сверху;
 *  - метка окна истории (CAPACITY × 500 мс) справа снизу;
 *  - EMA-сглаживание линий (плавная отрисовка без «пилы»);
 *  - градиентная заливка областей.
 */
class TrafficGraphView(context: Context) : View(context) {

    private val slots = FloatArray(MAX_SAMPLES * 2) // [rx, tx] чередование
    private var head = 0
    private var count = 0

    private val paintTxLine = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 2f
        color = 0xFF1E88E5.toInt()
    }
    private val paintRxLine = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 2f
        color = 0xFF2E7D32.toInt()
    }
    private val paintAxis = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 1f
        color = 0x3FFFFFFF
        pathEffect = android.graphics.DashPathEffect(floatArrayOf(6f, 6f), 0f)
    }
    private val paintAxisText = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0x88FFFFFF.toInt()
        textSize = 22f
        textAlign = Paint.Align.RIGHT
    }
    private val paintLegend = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0xCCFFFFFF.toInt()
        textSize = 20f
        textAlign = Paint.Align.LEFT
    }
    private val paintLegendDot = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
    }
    private val paintWindowLabel = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0x66FFFFFF.toInt()
        textSize = 18f
        textAlign = Paint.Align.RIGHT
    }

    // Градиенты создаются на размер (onSizeChanged).
    private var txGradient: Shader? = null
    private var rxGradient: Shader? = null
    private val paintTxFill = Paint(Paint.ANTI_ALIAS_FLAG)
    private val paintRxFill = Paint(Paint.ANTI_ALIAS_FLAG)

    /**
     * v1.5.1 PRO: сглаженная автошкала. Целевой максимум окна поднимается
     * мгновенно (спайк всегда виден), спад — 3% за кадр (шкала не «дёргается»).
     * Волатильно: читается/пишется только из onDraw (UI-поток).
     */
    private var scaleMax = 1f

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        if (w <= 0 || h <= 0) return
        txGradient = LinearGradient(0f, 0f, 0f, h.toFloat(), 0x551E88E5.toInt(), 0x111E88E5.toInt(), Shader.TileMode.CLAMP)
        rxGradient = LinearGradient(0f, 0f, 0f, h.toFloat(), 0x552E7D32.toInt(), 0x112E7D32.toInt(), Shader.TileMode.CLAMP)
        paintTxFill.shader = txGradient
        paintRxFill.shader = rxGradient
    }

    /** Добавляет сэмпл [rxRate, txRate] (байт/с) и перерисовывается. */
    fun addSample(rxRate: Float, txRate: Float) {
        head = (head + 1) % MAX_SAMPLES
        slots[head * 2] = rxRate.coerceAtLeast(0f)
        slots[head * 2 + 1] = txRate.coerceAtLeast(0f)
        if (count < MAX_SAMPLES) count++
        postInvalidate()
    }

    /**
     * v0.9.2 (R4): восстановление истории после recreate.
     * @param buffer [rx, tx]-чередование длиной 2*MAX_SAMPLES, head — индекс
     * нового сэмпла, valid — число валидных сэмплов.
     */
    fun setHistory(buffer: FloatArray, head: Int, valid: Int) {
        if (buffer.size < slots.size) return
        System.arraycopy(buffer, 0, slots, 0, slots.size)
        this.head = head.coerceIn(0, MAX_SAMPLES - 1)
        count = valid.coerceIn(0, MAX_SAMPLES)
        postInvalidate()
    }

    /** v0.9.7 (GUI-финал): есть ли данные — для схлопывания пустого графика. */
    fun hasData(): Boolean = count > 0

    fun reset() {
        head = 0
        count = 0
        slots.fill(0f)
        postInvalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val w = width.toFloat()
        val h = height.toFloat()
        if (w <= 0f || h <= 0f) return

        if (count > 0) {
            var target = 1f
            for (i in 0 until count) {
                if (slots[i * 2] > target) target = slots[i * 2]
                if (slots[i * 2 + 1] > target) target = slots[i * 2 + 1]
            }
            target *= 1.15f
            // сглаженная автошкала: вверх мгновенно, вниз — затуханием 3%/кадр
            scaleMax = if (target >= scaleMax) target else (scaleMax * 0.97f + target * 0.03f).coerceAtLeast(target)
            val max = scaleMax

            // --- сетка: 4 уровня с подписями (max, 3/4, 1/2, 1/4) ---
            val topPad = 26f
            val levels = intArrayOf(4, 3, 2, 1)
            for (lvl in levels) {
                val y = h - (h - topPad) * lvl / 4f - 2f
                canvas.drawLine(0f, y, w, y, paintAxis)
                canvas.drawText(Formats.rate(context, (max * lvl / 4f).toLong()), w - 4f, y - 4f, paintAxisText)
            }

            val series = intArrayOf(1, 0) // tx, rx
            val linePaints = arrayOf(paintTxLine, paintRxLine)
            val fillPaints = arrayOf(paintTxFill, paintRxFill)
            val step = w / (MAX_SAMPLES - 1).coerceAtLeast(1)

            for (s in series.indices) {
                val offset = series[s]
                val path = Path()
                var started = false
                var x = w
                var prevY = 0f
                // новые сэмплы справа: идём от головы назад по кольцу
                for (i in 0 until count) {
                    val idx = ((head - i) % MAX_SAMPLES + MAX_SAMPLES) % MAX_SAMPLES
                    val v = slots[idx * 2 + offset]
                    // EMA-сглаживание: текущий сэмпл 40% + предыдущая точка 60%
                    val pos = h - (v / max) * (h - topPad) - 2f
                    val y = if (!started) pos else prevY * 0.6f + pos * 0.4f
                    if (!started) {
                        path.moveTo(x, y)
                        started = true
                    } else {
                        path.lineTo(x, y)
                    }
                    prevY = y
                    x -= step
                }
                if (!started) continue
                val fill = Path(path)
                fill.lineTo(x + step, h)
                fill.lineTo(w, h)
                fill.close()
                canvas.drawPath(fill, fillPaints[s])
                canvas.drawPath(path, linePaints[s])
            }

            // --- легенда: ▼ приём (rx, зелёный) · ▲ отправка (tx, синий) ---
            var lx = 6f
            paintLegendDot.color = 0xFF2E7D32.toInt()
            canvas.drawCircle(lx + 6f, 14f, 5f, paintLegendDot)
            canvas.drawText(context.getString(R.string.graph_legend_rx), lx + 15f, 19f, paintLegend)
            lx += 15f + paintLegend.measureText(context.getString(R.string.graph_legend_rx)) + 14f
            paintLegendDot.color = 0xFF1E88E5.toInt()
            canvas.drawCircle(lx + 6f, 14f, 5f, paintLegendDot)
            canvas.drawText(context.getString(R.string.graph_legend_tx), lx + 15f, 19f, paintLegend)

            // --- метка окна истории ---
            canvas.drawText(
                context.getString(R.string.graph_window, MAX_SAMPLES / 2),
                w - 4f,
                h - 4f,
                paintWindowLabel,
            )
        }
    }

    companion object {
        const val MAX_SAMPLES = 120 // 60 секунд при 500 мс
    }
}
