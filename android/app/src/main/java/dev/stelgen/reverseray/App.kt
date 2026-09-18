package dev.stelgen.reverseray

import android.app.Application
import android.content.Context
import android.os.Build
import androidx.multidex.MultiDex

/**
 * Application-класс: legacy multidex для API 14–20
 * (AGP требует multiDexEnabled при core desugaring; на 21+ dex2art нативный).
 */
class App : Application() {
    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(base)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            MultiDex.install(this)
        }
    }
}
