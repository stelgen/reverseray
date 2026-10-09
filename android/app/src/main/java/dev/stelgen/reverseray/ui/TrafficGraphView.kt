package dev.stelgen.reverseray.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
import android.graphics.Shader
import android.view.View

/**
 * Реалтайм-график трафика (v0.7, richer v0.9.2): две области — приём (rx,
 * зелёный) и отправка (tx, синий) в байт/с. Чистый Canvas — работает от
 * API 14, без дополнительных зависимостей.
 *
 * v0.9.2 (R4): история живёт В СЕРВИСЕ (TunnelService.graphHistory) —
 * пересоздание Activity больше не сбрасывает график; view только рендер:
 *  - EMA-сглаживание линий (плавная отрисовка без «пилы»);
 *  - градиентная заливка областей;
 *  - ось: пунктирные уровни + подпись максимума (bps, из ресурсов);
 *  - подписи current/avg/peak рисует активность из TunnelService.graphStats().
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

    // Градиенты создаются на размер (onSizeChanged).
    private var txGradient: Shader? = null
    private var rxGradient: Shader? = null
    private val paintTxFill = Paint(Paint.ANTI_ALIAS_FLAG)
    private val paintRxFill = Paint(Paint.ANTI_ALIAS_FLAG)

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
     * v0.9.2 (R4): восстановление истории из сервиса после recreate.
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
            var max = 1f
            for (i in 0 until count) {
                if (slots[i * 2] > max) max = slots[i * 2]
                if (slots[i * 2 + 1] > max) max = slots[i * 2 + 1]
            }
            max *= 1.15f

            // Ось: уровень максимума + половина (пунктир) и подпись bps.
            // v0.9.2 (R4): подпись оси — максимум окна истории, «X B/s» из ресурсов
            val maxLabel = Formats.rate(context, max.toLong())
            canvas.drawText(maxLabel, w - 4f, 22f, paintAxisText)
            canvas.drawLine(0f, 26f, w, 26f, paintAxis)
            canvas.drawLine(0f, (h + 26f) / 2f, w, (h + 26f) / 2f, paintAxis)

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
                    val target = h - (v / max) * (h - 4f) - 2f
                    val y = if (!started) target else prevY * 0.6f + target * 0.4f
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
        }
    }

    companion object {
        const val MAX_SAMPLES = 120 // 60 секунд при 500 мс
    }
}