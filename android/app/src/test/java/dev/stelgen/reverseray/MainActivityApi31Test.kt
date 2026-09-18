package dev.stelgen.reverseray

import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import dev.stelgen.reverseray.core.RrpUri
import dev.stelgen.reverseray.service.TunnelService
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Основная матрица на Android 12 (API 31) — первый целевой прогон.
 * Проверяем: launch, UI-элементы, видимость QR-кнопок, roundtrip конфига через prefs.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [31])
class MainActivityApi31Test {

    private val validConfig = "rrp://secret-token@srv.example.com:443,8443/?pin=ABCdef123&name=Home"

    @Test
    fun `launch shows dashboard on android 12`() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                assertNotNull(activity.findViewById<android.view.ViewGroup>(android.R.id.content))
                assertTrue(activity.hasWindowFocus() || !activity.isFinishing)
            }
        }
    }

    @Test
    fun `qr buttons visible on api 31`() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val root = activity.findViewById<android.view.ViewGroup>(android.R.id.content).getChildAt(0)
                    as android.view.ViewGroup
                val labels = (0 until root.childCount).mapNotNull {
                    (root.getChildAt(it) as? Button)?.text?.toString()
                }
                assertTrue(labels.contains(activity.getString(R.string.qr_scan)))
                assertTrue(labels.contains(activity.getString(R.string.qr_show)))
            }
        }
    }

    @Test
    fun `invalid config does not crash on start`() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val root = activity.findViewById<android.view.ViewGroup>(android.R.id.content).getChildAt(0)
                    as android.view.ViewGroup
                val edit = (0 until root.childCount).mapNotNull { root.getChildAt(it) as? EditText }[0]
                edit.setText("not-an-rrp-uri")
                val start = (0 until root.childCount).mapNotNull { root.getChildAt(it) as? Button }
                    .first { it.text == activity.getString(R.string.btn_start) }
                start.performClick() // должен показать тост, не крашиться
                assertFalse(activity.isFinishing)
            }
        }
    }

    @Test
    fun `config persists across restart`() {
        val prefs = ApplicationProvider.getApplicationContext<android.content.Context>()
            .getSharedPreferences(TunnelService.PREFS, android.content.Context.MODE_PRIVATE)
        prefs.edit().putString(TunnelService.KEY_CONFIG, validConfig).commit()
        try {
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                scenario.onActivity { activity ->
                    val root = activity.findViewById<android.view.ViewGroup>(android.R.id.content)
                        .getChildAt(0) as android.view.ViewGroup
                    val edit = (0 until root.childCount).mapNotNull { root.getChildAt(it) as? EditText }[0]
                    assertEquals(validConfig, edit.text.toString())
                    // и парсится тем же кодеком, что и скан QR
                    assertEquals("Home", RrpUri.parse(edit.text.toString()).name)
                }
            }
        } finally {
            prefs.edit().clear().commit()
        }
    }
}
