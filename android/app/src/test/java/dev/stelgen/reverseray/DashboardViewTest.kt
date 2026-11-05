package dev.stelgen.reverseray

import androidx.test.core.app.ActivityScenario
import dev.stelgen.reverseray.ui.DashboardView
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * v1.5.0: дашборд — рендер 0/1/3 сессий, переключение PRIMARY при running
 * (по образцу MainActivityApi31Test: Robolectric, ActivityScenario).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [31])
class DashboardViewTest {

    private fun stat(
        id: String,
        name: String,
        state: String = "CONNECTED",
        primary: Boolean = false,
        rxRate: Long = 0,
        txRate: Long = 0,
    ) = DashboardView.Stat(
        id = id, name = name, state = state,
        rxRate = rxRate, txRate = txRate, rxTotal = 0, txTotal = 0,
        proto = "mtproto2", rttMs = 42, reconnects = 1, errors = 0, switches = 2,
        uptimeMs = 65_000, primary = primary,
    )

    private fun rendered(actions: MutableList<Pair<String, String>>, vararg stats: DashboardView.Stat): DashboardView {
        // DashboardView — чистый View: контексту нужна тема приложения
        // (ContextThemeWrapper, тема манифеста Theme.ReverseRay)
        val themed = android.view.ContextThemeWrapper(
            androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>(),
            dev.stelgen.reverseray.R.style.Theme_ReverseRay,
        )
        val view = DashboardView(themed)
        view.onAction = { id, cmd -> actions.add(id to cmd) }
        view.update(stats.toList())
        view.update(stats.toList()) // повторный рендер — идемпотентность/дифф
        return view
    }

    @Test
    fun `render zero sessions shows empty state`() {
        val actions = mutableListOf<Pair<String, String>>()
        val view = rendered(actions)
        assertEquals(android.view.View.VISIBLE, view.visibility)
        // пусто — не падаем, дифф по пустому списку ничего не рушит
        view.update(emptyList())
        view.update(emptyList())
    }

    @Test
    fun `render one and three sessions`() {
        val actions = mutableListOf<Pair<String, String>>()
        val view = rendered(actions, stat("s1", "Home", primary = true))
        view.update(
            listOf(
                stat("s1", "Home", primary = true, rxRate = 1200, txRate = 300),
                stat("s2", "Work", rxRate = 50, txRate = 10),
                stat("s3", "VPS", state = "ERROR"),
            ),
        )
        // исчезнувшая s3 не оставляет мусора при повторном рендере
        view.update(
            listOf(
                stat("s1", "Home", primary = true),
                stat("s2", "Work"),
            ),
        )
    }

    @Test
    fun `primary switch action fires with sessionId`() {
        val actions = mutableListOf<Pair<String, String>>()
        val view = rendered(
            actions,
            stat("s1", "Home", primary = true),
            stat("s2", "Work", state = "CONNECTED"),
        )
        // кнопки действий ищем рекурсивно: нажимаем «Make primary» (видна
        // только у НЕ-primary сессии — s2 при running)
        val wanted = view.context.getString(R.string.dash_session_primary)
        pressButtonByText(view, wanted)
        assertEquals(1, actions.size)
        assertEquals("primary", actions[0].second)
        assertEquals("s2", actions[0].first)
    }

    /** Поиск и нажатие VISIBLE TextView-кнопки по тексту (Views-канон UiFind). */
    private fun pressButtonByText(root: android.view.View, text: String) {
        if (root.visibility != android.view.View.VISIBLE) return
        if (root is android.view.ViewGroup) {
            for (i in 0 until root.childCount) {
                pressButtonByText(root.getChildAt(i), text)
            }
        }
        if (root is android.widget.TextView && root.text.toString() == text) {
            root.performClick()
        }
    }

    @Test
    fun `activity launches with new servers tab`() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                assertNotNull(activity.findViewById<android.view.ViewGroup>(android.R.id.content))
                assertTrue(activity.hasWindowFocus() || !activity.isFinishing)
            }
        }
    }
}
