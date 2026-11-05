package dev.stelgen.reverseray.ui

import android.content.Context
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.View
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.TextView

import dev.stelgen.reverseray.R

/**
 * Дашборд мульти-серверного ядра (v1.5.0): KPI-карточки по сессиям.
 *
 *  - агрегат «Все серверы» сверху (суммарные rx/tx rate);
 *  - карточка на сессию: state, rates, totals, uptime, proto (+число
 *    переключений), RTT, реконнекты, ошибки;
 *  - per-сессионный TrafficGraphView со СВОЕЙ историей сэмплов (RAM,
 *    кольцевые буферы внутри view; бюджет ≤ 2 МБ на 4 сессии с запасом:
 *    120 сэмплов × 2 × 4 Б ≈ 1 КБ на сессию);
 *  - действия по сессии: connect/disconnect/reconnect/probe/primary —
 *    через [onAction] (id, cmd).
 *
 * Чистый Views (без новых зависимостей), API 14+; рендер идемпотентен —
 * вызывается на каждом stats-тике (500 мс).
 */
class DashboardView(context: Context) : LinearLayout(context) {

    /** Снимок одной сессии (парсится из EXTRA_SESSIONS TunnelService). */
    data class Stat(
        val id: String,
        val name: String,
        val state: String,
        val rxRate: Long,
        val txRate: Long,
        val rxTotal: Long,
        val txTotal: Long,
        val proto: String,
        val rttMs: Long,
        val reconnects: Long,
        val errors: Long,
        val switches: Long,
        val uptimeMs: Long,
        val primary: Boolean,
    )

    /** Действие по сессии: cmd = connect|disconnect|reconnect|probe|primary. */
    var onAction: ((id: String, cmd: String) -> Unit)? = null

    private val aggRates = TextView(context).apply {
        textSize = 13f
        setTypeface(typeface, Typeface.BOLD)
        setTextColor(0xFFD8DCE6.toInt())
        setPadding(dp(16), dp(10), dp(16), dp(2))
    }
    private val emptyView = TextView(context).apply {
        text = context.getString(R.string.dash_empty)
        textSize = 13f
        setTextColor(0xFF8FA3D9.toInt())
        setPadding(dp(16), dp(24), dp(16), dp(24))
        gravity = Gravity.CENTER
    }
    private val cardsBox = LinearLayout(context).apply { orientation = VERTICAL }

    private class Card(val root: LinearLayout, val views: SessionViews)

    private class SessionViews(
        val title: TextView,
        val state: TextView,
        val rates: TextView,
        val details: TextView,
        val counters: TextView,
        val graph: TrafficGraphView,
        val connect: TextView,
        val disconnect: TextView,
        val reconnect: TextView,
        val probe: TextView,
        val primary: TextView,
    )

    private val cards = LinkedHashMap<String, Card>()

    init {
        orientation = VERTICAL
        addView(aggRates)
        addView(
            cardsBox,
            LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT),
        )
        addView(emptyView)
    }

    /**
     * Полный рендер по снапшоту. Дифф по id: новые карточки добавляются,
     * исчезнувшие — удаляются; существующие обновляются (тексты + график).
     */
    fun update(sessions: List<Stat>) {
        val seen = HashSet<String>()
        for (s in sessions) {
            seen.add(s.id)
            val card = cards.getOrPut(s.id) { newCard(s.id) }
            bind(card.views, s)
            if (card.root.parent == null) {
                cardsBox.addView(card.root)
            }
        }
        // удалить исчезнувшие
        val dead = cards.keys.filter { it !in seen }
        for (id in dead) {
            val c = cards.remove(id)
            cardsBox.removeView(c?.root)
        }
        // агрегат
        val rx = sessions.sumOf { it.rxRate }
        val tx = sessions.sumOf { it.txRate }
        aggRates.text = context.getString(
            R.string.dash_all_servers,
        ) + "  ·  ↓" + Formats.rate(context, rx) + "  ↑" + Formats.rate(context, tx)
        aggRates.visibility = if (sessions.isEmpty()) View.GONE else View.VISIBLE
        emptyView.visibility = if (sessions.isEmpty()) View.VISIBLE else View.GONE
    }

    /** Сброс (стоп сервиса): карточки disabled/пустые. */
    fun reset() {
        update(emptyList())
    }

    // ------------------------------------------------------------ карточка

    private fun newCard(id: String): Card {
        val title = TextView(context).apply {
            textSize = 14f
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(0xFFFFFFFF.toInt())
        }
        val state = TextView(context).apply {
            textSize = 12f
            setTypeface(typeface, Typeface.BOLD)
        }
        val rates = TextView(context).apply {
            textSize = 12f
            setTypeface(Typeface.MONOSPACE)
            setTextColor(0xFFD8DCE6.toInt())
        }
        val details = TextView(context).apply {
            textSize = 11f
            setTypeface(Typeface.MONOSPACE)
            setTextColor(0xFF8FA3D9.toInt())
        }
        val counters = TextView(context).apply {
            textSize = 11f
            setTypeface(Typeface.MONOSPACE)
            setTextColor(0xFF8FA3D9.toInt())
        }
        val graph = TrafficGraphView(context).apply {
            layoutParams = LinearLayout.LayoutParams(
                LayoutParams.MATCH_PARENT, dp(80),
            )
        }
        val connect = actionBtn(R.string.dash_session_connect) { onAction?.invoke(id, "connect") }
        val disconnect = actionBtn(R.string.dash_session_disconnect) { onAction?.invoke(id, "disconnect") }
        val reconnect = actionBtn(R.string.dash_session_reconnect) { onAction?.invoke(id, "reconnect") }
        val probe = actionBtn(R.string.dash_session_probe) { onAction?.invoke(id, "probe") }
        val primary = actionBtn(R.string.dash_session_primary) { onAction?.invoke(id, "primary") }

        val headRow = LinearLayout(context).apply {
            orientation = HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(title, LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f))
            addView(state)
        }
        val btnRow = HorizontalScrollView(context).apply {
            isHorizontalScrollBarEnabled = false
            addView(
                LinearLayout(context).apply {
                    orientation = HORIZONTAL
                    addView(connect)
                    addView(disconnect)
                    addView(reconnect)
                    addView(probe)
                    addView(primary)
                },
            )
        }
        val root = LinearLayout(context).apply {
            orientation = VERTICAL
            val bg = GradientDrawable().apply {
                cornerRadius = dp(14).toFloat()
                setColor(0xFF141B2E.toInt())
            }
            background = bg
            setPadding(dp(14), dp(12), dp(14), dp(12))
            addView(headRow)
            addView(rates)
            addView(details)
            addView(counters)
            addView(graph)
            addView(btnRow)
        }
        root.layoutParams = LayoutParams(
            LayoutParams.MATCH_PARENT,
            LayoutParams.WRAP_CONTENT,
        ).apply { setMargins(dp(12), dp(6), dp(12), dp(6)) }
        val v = SessionViews(title, state, rates, details, counters, graph, connect, disconnect, reconnect, probe, primary)
        return Card(root, v)
    }

    private fun actionBtn(labelRes: Int, onClick: () -> Unit): TextView =
        TextView(context).apply {
            text = context.getString(labelRes)
            textSize = 11f
            setPadding(dp(10), dp(5), dp(10), dp(5))
            setTextColor(0xFF8BD17C.toInt())
            setBackgroundResource(android.R.drawable.list_selector_background)
            setOnClickListener { onClick() }
            layoutParams = LinearLayout.LayoutParams(
                LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT,
            ).apply { setMargins(0, dp(6), dp(8), 0) }
        }

    private fun bind(v: SessionViews, s: Stat) {
        v.title.text = if (s.primary) "★ ${s.name}" else s.name
        val (label, color) = when (s.state) {
            "CONNECTED", "PROTO", "up" -> context.getString(R.string.dash_state_connected) to 0xFF39D98A.toInt()
            "CONNECTING", "RETRY", "PROTO_ROLLBACK", "connecting" ->
                context.getString(R.string.dash_state_connecting) to 0xFFC79A2A.toInt()
            "ERROR", "LIMIT_REACHED", "PIN_MISMATCH" ->
                context.getString(R.string.dash_state_error) to 0xFFFF6B6B.toInt()
            "STOPPED", "disabled", "off" ->
                context.getString(R.string.dash_state_disabled) to 0xFF8FA3D9.toInt()
            else -> s.state to 0xFFD8DCE6.toInt()
        }
        v.state.text = label
        v.state.setTextColor(color)
        // v1.6.0: счётчики КАЖДЫЙ С НОВОЙ СТРОКИ — детерминированная высота
        // карточки: растущие цифры не переносят строку и не «дёргают» layout.
        v.rates.text = "↓ " + Formats.rate(context, s.rxRate) +
            "\n↑ " + Formats.rate(context, s.txRate) +
            "\nΣ " + Formats.bytes(context, s.rxTotal) + " / " + Formats.bytes(context, s.txTotal)
        v.rates.maxLines = 3
        v.rates.ellipsize = android.text.TextUtils.TruncateAt.END
        val proto = if (s.proto.isBlank()) RrpProtocolsLabel.auto(context) else s.proto
        v.details.text = proto +
            "  ·  RTT " + (if (s.rttMs > 0) "${s.rttMs} ms" else "—") +
            "  ·  " + context.getString(R.string.dash_uptime, Formats.uptime(context, s.uptimeMs))
        v.details.maxLines = 1
        v.details.ellipsize = android.text.TextUtils.TruncateAt.END
        v.counters.text = context.getString(R.string.dash_switches, s.switches.toInt()) +
            "\n" + context.getString(R.string.dash_reconnects, s.reconnects.toInt()) +
            "\n" + context.getString(R.string.dash_errors, s.errors.toInt())
        v.counters.maxLines = 3
        v.counters.ellipsize = android.text.TextUtils.TruncateAt.END
        // график: кормим сэмпл на каждом тике (500 мс) — как на главной
        v.graph.addSample(s.rxRate.toFloat(), s.txRate.toFloat())
        // кнопки по состоянию
        val running = s.state !in setOf("STOPPED", "disabled", "off", "")
        v.connect.visibility = if (running) View.GONE else View.VISIBLE
        v.disconnect.visibility = if (running) View.VISIBLE else View.GONE
        v.reconnect.visibility = if (running) View.VISIBLE else View.GONE
        v.primary.visibility = if (s.primary) View.GONE else View.VISIBLE
    }

    /** AUTO-метка протокола без создания активности (не хардкод кириллицы). */
    private object RrpProtocolsLabel {
        fun auto(context: Context): String =
            context.getString(dev.stelgen.reverseray.R.string.proto_auto_label)
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
}
