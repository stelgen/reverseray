package dev.stelgen.reverseray.core

import com.google.zxing.BarcodeFormat
import com.journeyapps.barcodescanner.BarcodeEncoder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** QR-экспорт: serialize → encodeBitmap → строка парсится обратно тем же кодеком. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [31])
class QrEncodeTest {

    @Test
    fun `qr encode roundtrip with unicode and special chars`() {
        val config = RrpUriConfig(
            token = "tok/En+123=",
            host = "srv.example.com",
            ports = listOf(443, 8443),
            pin = "base64pin==",
            name = "Домашний сервер",
        )
        val line = RrpUri.serialize(config)
        val bitmap = BarcodeEncoder().encodeBitmap(line, BarcodeFormat.QR_CODE, 512, 512)
        assertNotNull(bitmap)
        assertEquals(512, bitmap.width)

        val back = RrpUri.parse(line)
        assertEquals(config.token, back.token)
        assertEquals(config.host, back.host)
        assertEquals(config.ports, back.ports)
        assertEquals(config.pin, back.pin)
        assertEquals(config.name, back.name)
    }
}
