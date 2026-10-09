package dev.stelgen.reverseray

// ScreenshotBot (v0.9.6) — ФИНАЛЬНОЕ решение скриншот-робота БЕЗ эмулятора:
// CI-эмуляторы падали месяцами (KVM/AVD/boot-гейты), а Robolectric с
// нативной графикой (RNG, 4.10+) рисует НАСТОЯЩИЕ пиксели Views на JVM:
// детерминированно, за секунды, без KVM и без флейков.
//
// Тест рендерит MainActivity в типовых пропорциях телефона и сохраняет PNG
// в build/screenshot.png (абсолютный путь печатается в stdout — воркфлоу
// подхватывает). Ассет в README коммитит отдельный воркфлоу.

import android.graphics.Bitmap
import android.graphics.Canvas
import android.view.View
import androidx.test.core.app.ActivityScenario
import org.robolectric.RobolectricTestRunner
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.File
import java.io.FileOutputStream

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [31], qualifiers = "w360dp-h740dp-xxhdpi")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class ScreenshotBot {

    @Test
    fun renderMainActivityToPng() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val decor = activity.window.decorView
                decor.measure(
                    View.MeasureSpec.makeMeasureSpec(1080, View.MeasureSpec.EXACTLY),
                    View.MeasureSpec.makeMeasureSpec(2220, View.MeasureSpec.EXACTLY),
                )
                decor.layout(0, 0, 1080, 2220)
                val bmp = Bitmap.createBitmap(1080, 2220, Bitmap.Config.ARGB_8888)
                decor.draw(Canvas(bmp))

                // живость кадра: не однотонный (реальный UI, а не пустой декор)
                val probe = IntArray(64 * 64)
                val small = Bitmap.createScaledBitmap(bmp, 64, 64, true)
                small.getPixels(probe, 0, 64, 0, 0, 64, 64)
                val colors = probe.distinct().size
                assertTrue("рендер пустой ($colors цветов) — RNG не отработал", colors > 8)

                val out = File("build").apply { mkdirs() }
                    .resolve("screenshot.png")
                FileOutputStream(out).use { f ->
                    val scaled = Bitmap.createScaledBitmap(bmp, 720, 1440, true)
                    scaled.compress(Bitmap.CompressFormat.PNG, 100, f)
                }
                println("SCREENSHOT_BOT: PNG saved: ${out.absolutePath} (${out.length()} bytes)")
                assertTrue("PNG не записан", out.length() > 20_000)
            }
        }
    }
}
