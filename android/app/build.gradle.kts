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
        versionCode = 1
        versionName = "0.1.0"

        // Векторные иконки через support-lib (нужно для minSdk 14)
        vectorDrawables {
            useSupportLibrary = true
        }
    }

    // Universal APK: splits/abiFilters намеренно не объявлены — один APK на все ABI.

    signingConfigs {
        create("release") {
            // Подпись целиком из окружения (CI/локально):
            // RR_KEYSTORE, RR_KEYSTORE_PASSWORD, RR_KEY_ALIAS, RR_KEY_PASSWORD
            val ks = System.getenv("RR_KEYSTORE")
            if (!ks.isNullOrBlank()) {
                storeFile = file(ks)
                storePassword = System.getenv("RR_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("RR_KEY_ALIAS")
                keyPassword = System.getenv("RR_KEY_PASSWORD")
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
            // signingConfig вешаем только если keystore задан в env
            if (!System.getenv("RR_KEYSTORE").isNullOrBlank()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        // Java 17 toolchain
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        // java.time/java.util.stream и др. на minSdk 14 — через desugar_jdk_libs
        isCoreLibraryDesugaringEnabled = true
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    lint {
        abortOnError = true
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.material)
    implementation(libs.bouncycastle.bcprov)
    implementation(libs.bouncycastle.bctls)
    implementation(libs.zxing.android.embedded)

    coreLibraryDesugaring(libs.desugar.jdk.libs)

    testImplementation(libs.junit)
}
