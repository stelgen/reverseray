// Корневой build: версии плагинов берутся через alias из gradle/libs.versions.toml,
// применение — в модуле :app.

// R8 override: зависимость Kotlin 2.4.x от R8 >= 9.1.29 (офиц. матрица kotlin-support),
// бандл AGP 8.7.3 = R8/D8 8.7.18 не понимает metadata Kotlin 2.4 -> крэш
// "Unexpected error during rewriting of Kotlin metadata ... Should never be called".
// Переопределение бандленного R8 — документированный путь; AGP 8.5.2+ совместим с R8 9.x,
// значит пин AGP 8.7.3 (minSdk 14, unit-test manifest merge) не нарушаем.
buildscript {
    dependencies {
        classpath("com.android.tools:r8:9.1.43") // минимум 9.1.29; жив на Google Maven (9.1.29 не публиковался)
    }
}

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
}
