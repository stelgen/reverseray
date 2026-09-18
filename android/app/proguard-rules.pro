# ReverseRay — release R8 rules

# --- BouncyCastle: минимум для TLS-клиента (внутренняя рефлексия/имена классов в BC TLS) ---
-keep class org.bouncycastle.tls.** { *; }
-keep class org.bouncycastle.asn1.** { *; }
-keep class org.bouncycastle.crypto.** { *; }
-dontwarn org.bouncycastle.**

# ВАЖНО (minSdk < 28): платформенный org.bouncycastle.* — скрытые заглушки; BC-jar в APK
# резолвится корректно (bootclasspath-версия скрыта от приложений), но для параноидального
# релиза рекомендуется jarjar-репакейдж bcprov/bctls в свой package.

# zxing-android-embedded тянет свои consumer-rules — дополнительного keep не требуется.
# RRP core (dev.stelgen.reverseray.core.**) — чистый Kotlin без рефлексии, R8 сам разберётся.
