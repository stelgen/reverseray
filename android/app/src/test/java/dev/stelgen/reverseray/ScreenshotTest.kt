package dev.stelgen.reverseray

import android.graphics.Bitmap
import android.view.ViewGroup
import androidx.test.core.app.ActivityScenario
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import javax.imageio.ImageIO

/**
 * РЕАЛЬНЫЙ скриншот приложения (v0.8): Robolectric рендерит MainActivity
 * в Bitmap и сохраняет PNG в артефакт. CI-робот (screenshot.yml) забирает
 * файл и кладёт в assets/brand/screenshot.png на главной репо — вместо
 * «нарисованных в Paint» картинок.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [31])
class ScreenshotTest {

    @Test
    fun `renders real dashboard screenshot`() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val content = activity.findViewById<ViewGroup>(android.R.id.content)
                val width = 720
                val height = 1280
                val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
                val canvas = android.graphics.Canvas(bitmap)
                content.measure(
                    android.view.View.MeasureSpec.makeMeasureSpec(width, android.view.View.MeasureSpec.EXACTLY),
                    android.view.View.MeasureSpec.makeMeasureSpec(height, android.view.View.MeasureSpec.EXACTLY),
                )
                content.layout(0, 0, width, height)
                content.draw(canvas)

                val out = System.getProperty("rr.screenshot.out", "build/screenshot/app.png")
                val f = File(out).absoluteFile
                f.parentFile?.mkdirs()
                f.outputStream().use { ImageIO.write(bitmap.toBufferedImage(), "png", it) }
                assertTrue(f.length() > 10_000)
            }
        }
    }
}

/** android.graphics.Bitmap → java.awt.BufferedImage (для ImageIO в JVM). */
private fun Bitmap.toBufferedImage(): java.awt.image.BufferedImage {
    val w = width
    val h = height
    val pixels = IntArray(w * h)
    getPixels(pixels, 0, w, 0, 0, w, h)
    val img = java.awt.image.BufferedImage(w, h, java.awt.image.BufferedImage.TYPE_INT_ARGB)
    for (y in 0 until h) {
        for (x in 0 until w) {
            val argb = pixels[y * w + x]
            val a = (argb ushr 24) and 0xFF
            val r = (argb ushr 16) and 0xFF
            val g = (argb ushr 8) and 0xFF
            val b = argb and 0xFF
            img.setRGB(x, y, (a shl 24) or (r shl 16) or (g shl 8) or b)
        }
    }
    return img
}