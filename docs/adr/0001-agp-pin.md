# ADR-0001: Пин AGP 8.7.3 (и Kotlin 2.4.21) в Android-сборке

**Статус:** принято · **Дата:** 2026-11-20 · **Релиз:** v1.8.5 (Фаза 2)

## Контекст
`gradle/libs.versions.toml` пинит AGP = 8.7.3 (`agp` version.ref), Kotlin = 2.4.21.
CI и локальные сборки используют Gradle 8.14.6 wrapper.

## Решение
1. **Не бампать AGP** без координации R8: как и Kotlin, AGP тянет версию R8
   (com.android.tools:r8), которая определяет байткод-цели и шrink-поведение.
   Канон проекта: бампы тулчейна = отдельный PR с полным `assembleRelease` и
   smoke-тестом APK (установка + коннект + detekt/gates).
2. Kotlin-бампы координируются с R8 явно (комментарий в `libs.versions.toml`):
   kotlin 2.4 ⇒ R8 ≥ 9.1.29 (`android/build.gradle.kts`, buildscript classpath).
3. Обновления security-патчей AGP (8.7.x patch) допустимы минорным PR без
   смены R8-мажора; мажор AGP (9.x) — только после мажора Gradle.

## Следствия
- Гейт докс-синхрона (`scripts/docs_sync_check.py`) не проверяет AGP — он
  зафиксирован комментарием в toml и этим ADR.
- Любой бамп тулчейна обязан обновить этот ADR (статус → «пересмотрен»).
