// Корневой build: версии плагинов берутся через alias из gradle/libs.versions.toml,
// применение — в модуле :app.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
}
