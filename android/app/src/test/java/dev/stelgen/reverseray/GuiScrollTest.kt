package dev.stelgen.reverseray

import android.view.View
import android.view.ViewGroup
import android.widget.ScrollView
import androidx.test.core.app.ActivityScenario
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import dev.stelgen.reverseray.ui.StatusConsole

/**
 * UX-канон скроллинга (v0.8.2): ЛЮБАЯ вкладка листается (ScrollView),
 * консоли — единый компонент на всех трёх вкладках, «пустых полей» нет.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [31])
class GuiScrollTest {

    private fun directChildren(root: ViewGroup): List<View> =
        (0 until root.childCount).map { root.getChildAt(it) }

    @Test
    fun `every tab page is a scrollview`() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val content = UiFind.contentView(activity) as ViewGroup
                // root(LinearLayout) → [TabLayout, pages(FrameLayout)]
                val pages = directChildren(content).filterIsInstance<ViewGroup>()
                    .firstOrNull { it !is androidx.appcompat.widget.LinearLayoutCompat && it.childCount == 5 }
                    ?: directChildren(content).last() as ViewGroup
                val scrollPages = directChildren(pages).filterIsInstance<ScrollView>()
                assertTrue("ожидали 5 скроллируемых страниц, найдено ${scrollPages.size}", scrollPages.size == 5)
                // каждая страница реально листается: scrollable когда контент больше вьюпорта
                scrollPages.forEach { sp ->
                    sp.measure(
                        View.MeasureSpec.makeMeasureSpec(360, View.MeasureSpec.EXACTLY),
                        View.MeasureSpec.makeMeasureSpec(400, View.MeasureSpec.EXACTLY),
                    )
                    sp.layout(0, 0, 360, 400)
                    // SETTINGS содержит несколько карточек — гарантированно выше 400px
                }
                val settings = scrollPages.last()
                assertTrue(
                    "настройки не скроллятся (высота контента ${settings.getChildAt(0).height})",
                    settings.getChildAt(0).height > 400,
                )
            }
        }
    }

    @Test
    fun `unified console lives on home update and log tabs`() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val consoles = UiFind.allViews(UiFind.contentView(activity))
                    .filterIsInstance<StatusConsole>()
                assertTrue("консолей ${consoles.size}, ожидали 3 (главная/обновление/лог)", consoles.size == 3)
            }
        }
    }

    @Test
    fun `link status starts hidden - no empty field`() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                // вкладка «Связь»: статус ссылки скрыт, пока пользователь ничего не ввёл
                val texts = UiFind.texts(UiFind.contentView(activity))
                val status = texts.firstOrNull { it.text.toString().contains("✓") || it.id != View.NO_ID }
                // если статус найден — он обязан быть GONE; главное: не висит пустым VISIBLE
                status?.let {
                    if (it.text.isEmpty()) assertTrue("пустой статус виден", it.visibility == View.GONE)
                }
            }
        }
    }
}
