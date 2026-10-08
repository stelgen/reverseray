package dev.stelgen.reverseray.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Path
import android.view.View

/**
 * Реалтайм-график трафика (v0.7): две области — приём (rx, зелёный) и
 * отправка (tx, синий) в байт/с. Чистый Canvas — работает от API 14,
 * без дополнительных зависимостей. Сэмплы приходят из TunnelService
 * (ACTION_STATS каждые 500 мс).
 */
class TrafficGraphView(context: Context) : View(context) {

    private val slots = IntArray(MAX_SAMPLES)
    private val slotsTx = FloatArray(MAX_SAMPLES)
    private val slotsRx = FloatArray(MAX_SAMPLES)
    private var head = 0
    private var count = 0

    private val paintTxLine = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 2f
        color = 0xFF1E88E5.toInt()
    }
    private val paintTxFill = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0x331E88E5
    }
    private val paintRxLine = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 2f
        color = 0xFF2E7D32.toInt()
    }
    private val paintRxFill = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0x332E7D32
    }

    /** Добавляет сэмпл [rxRate, txRate] (байт/с) и перерисовывается. */
    fun addSample(rxRate: Float, txRate: Float) {
        head = (head + 1) % MAX_SAMPLES
        slotsTx[head] = txRate.coerceAtLeast(0f)
        slotsRx[head] = rxRate.coerceAtLeast(0f)
        if (count < MAX_SAMPLES) count++
        postInvalidate()
    }

    fun reset() {
        head = 0
        count = 0
        slotsTx.fill(0f)
        slotsRx.fill(0f)
        postInvalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (count == 0) return
        val w = width.toFloat()
        val h = height.toFloat()
        var max = 1f
        for (i in 0 until count) {
            if (slotsTx[i] > max) max = slotsTx[i]
            if (slotsRx[i] > max) max = slotsRx[i]
        }
        max *= 1.15f

        val series = arrayOf(slotsTx, slotsRx)
        val linePaints = arrayOf(paintTxLine, paintRxLine)
        val fillPaints = arrayOf(paintTxFill, paintRxFill)
        val step = w / (MAX_SAMPLES - 1).coerceAtLeast(1)

        for (s in series.indices) {
            val data = series[s]
            val path = Path()
            var started = false
            var x = w
            // новые сэмплы справа: идём от головы назад по кольцу
            for (i in 0 until count) {
                val idx = ((head - i) % MAX_SAMPLES + MAX_SAMPLES) % MAX_SAMPLES
                val y = h - (data[idx] / max) * (h - 4f) - 2f
                if (!started) {
                    path.moveTo(x, y)
                    started = true
                } else {
                    path.lineTo(x, y)
                }
                x -= step
            }
            val fill = Path(path)
            fill.lineTo(x + step, h)
            fill.lineTo(w, h)
            fill.close()
            canvas.drawPath(fill, fillPaints[s])
            canvas.drawPath(path, linePaints[s])
        }
    }

    companion object {
        const val MAX_SAMPLES = 120 // 60 секунд при 500 мс
    }
}
