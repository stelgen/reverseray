import java.util.Properties
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "dev.stelgen.reverseray"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.stelgen.reverseray"
        minSdk = 14
        targetSdk = 36
        // v0.7.2: versionName задаётся релиз-пайплайном (-PversionName=<тег без v>)
        // или дефолтом для локальной разработки; versionCode ВЫВОДИТСЯ из семвера
        // (major*1M + minor*1K + patch) — растёт с КАЖДЫМ релизом автоматически,
        // даже если APK-код не менялся (требование: цифра бежит в каждом релизе).
        val releaseVersion: String = (project.findProperty("versionName") as String?) ?: "0.9.0"
        val (maj, min, pat) = releaseVersion.removePrefix("v").split('.').map { it.toIntOrNull() ?: 0 }
        versionCode = maj * 1_000_000 + min * 1_000 + pat
        versionName = releaseVersion
        // Legacy multidex обязателен для API < 21 при включённом core desugaring
        multiDexEnabled = true

        // Векторные иконки через support-lib (нужно для minSdk 14)
        vectorDrawables {
            useSupportLibrary = true
        }
    }

    // Universal APK: splits/abiFilters намеренно не объявлены — один APK на все ABI.

    // BouncyCastle jars тянут OSGI-манифесты в META-INF/versions (1.80 → /9, 1.86+ → /17,
    // дублируются в bcprov и bctls) — в APK не нужны, wildcard на любую Java-версию
    packaging {
        resources {
            excludes += setOf(
                "META-INF/versions/*/OSGI-INF/MANIFEST.MF",
                "META-INF/OSGI-INF/MANIFEST.MF",
                // BC 1.86+: лицензионные файлы дублируются в каждом jar (bcprov/bctls/bcutil)
                "META-INF/LICENSE.md",
                "META-INF/LICENSE.html",
                "META-INF/NOTICE.md",
                "META-INF/NOTICE.txt",
                "META-INF/DEPENDENCIES",
                // подписи jar в APK не нужны
                "META-INF/*.RSA",
                "META-INF/*.SF",
                "META-INF/*.DSA",
                "META-INF/{AL2.0,LGPL2.1}",
            )
        }
    }

    signingConfigs {
        create("release") {
            // Приоритет: секреты окружения (личный ключ владельца), затем
            // репозиторный ключ (android/app/signing.properties + rr-release.keystore).
            // Репозиторный ключ — открытый (см. SECURITY.md): он гарантирует стабильность
            // подписи между релизами, но не авторство; авторство верифицируется
            // SHA256SUMS в GitHub Release.
            val ks = System.getenv("RR_KEYSTORE")
            if (!ks.isNullOrBlank()) {
                storeFile = file(ks)
                storePassword = System.getenv("RR_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("RR_KEY_ALIAS")
                keyPassword = System.getenv("RR_KEY_PASSWORD")
            } else {
                val props = Properties().apply {
                    val f = rootProject.file("app/signing.properties")
                    if (f.exists()) f.inputStream().use { load(it) }
                }
                storeFile = file(props.getProperty("storeFile", "rr-release.keystore"))
                storePassword = props.getProperty("storePassword", "")
                keyAlias = props.getProperty("keyAlias", "")
                keyPassword = props.getProperty("keyPassword", "")
                enableV1Signing = true // обязателен для установки на API 14-23
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            // подпись всегда: env-ключ при наличии, иначе репозиторный (см. signingConfigs)
            signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        // Java 17 toolchain
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        // java.time/java.util.stream и др. на minSdk 14 — через desugar_jdk_libs
        isCoreLibraryDesugaringEnabled = true
    }

    // Kotlin 2.4: jvmTarget задаётся через kotlin { compilerOptions } (см. ниже)

    lint {
        abortOnError = true
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
        }
    }
}

// Изолируем JVM на тест-класс: Robolectric глобально меняет provider/system-свойства
// и ломает сетевые тесты (EvilServerTest), выполняющиеся после него.
tasks.withType<Test>().configureEach {
    setForkEvery(1)
    maxParallelForks = 2
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.material)
    implementation(libs.bouncycastle.bcprov)
    implementation(libs.bouncycastle.bctls)
    implementation(libs.bouncycastle.bcutil)
    implementation(libs.zxing.android.embedded) // QR-скан (API>=19) и генерация QR; guard в MainActivity
    implementation(libs.androidx.multidex)

    coreLibraryDesugaring(libs.desugar.jdk.libs)

    testImplementation(libs.junit)
    testImplementation(libs.bouncycastle.bcpkix) // генерация self-signed сертификата в evil-server тестах
    testImplementation("org.robolectric:robolectric:4.14.1") // пин: 4.15+ теряет SDK 21 (MainActivityApi21Test) — бампить только координированно
    testImplementation("androidx.test:core-ktx:1.7.0") // 1.7.0 (minSdk 21) ок: test-only + tools:overrideLibrary в манифесте (см. AndroidManifest.xml)
}

// Kotlin 2.4+: jvmTarget через compilerOptions (DSL kotlinOptions удалён);
// мержит dependabot #12 (kotlin 2.1.0 -> 2.4.20)
kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}
