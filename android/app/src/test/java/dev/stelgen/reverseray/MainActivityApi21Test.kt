package dev.stelgen.reverseray

import android.os.Build
import android.widget.Button
import android.view.ViewGroup
import androidx.test.core.app.ActivityScenario
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Минимальный автоматизируемый уровень: API 21 (Lollipop).
 * API 14–20 Robolectric не поддерживает — ручной smoke-чеклист (docs), как в ТЗ.
 * Контракт: приложение живёт, QR-скан виден (либа требует 19+, 21 >= 19).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [21])
class MainActivityApi21Test {

    @Test
    fun `launch survives on api 21`() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                assertEquals(21, Build.VERSION.SDK_INT)
                assertFalse(activity.isFinishing)
            }
        }
    }

    @Test
    fun `qr scan button visible at api 21`() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val root = activity.findViewById<ViewGroup>(android.R.id.content).getChildAt(0) as ViewGroup
                val labels = (0 until root.childCount).mapNotNull {
                    (root.getChildAt(it) as? Button)?.text?.toString()
                }
                assertTrue(labels.contains(activity.getString(R.string.qr_scan)))
                assertTrue(labels.contains(activity.getString(R.string.qr_show)))
            }
        }
    }
}
