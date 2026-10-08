# Workflow

Процесс разработки и релизов (шаблон — nextgen-воркфлоу).

## Ветки

| Ветка | Назначение | Правила |
|---|---|---|
| `main` | прод-код | защищена, только PR; fast-forward |
| `gh-pages` | лендинг | только деплой-джоба/ключ |
| `fix/*`, `feat/*` | работа | PR в main |

## Коммиты

Conventional Commits: `feat:`, `fix:`, `docs:`, `ci:`, `test:`, `chore:`, `style:`.

## CI-гейты (обязательные к merge)

| Джоба | Содержание |
|---|---|
| Go test/vet/fmt | gofmt, vet, `test -race`, coverage |
| Docker smoke | сборка образа, healthcheck-бинарь |
| Android build | assembleDebug + unit-тесты (Robolectric 21/31, JVM-изоляция) |
| Brand assets | перегенерация + сверка с закоммиченным |
| Gitleaks | скан секретов (каждый push/PR) |
| Dependency review | гейт уязвимых зависимостей на PR |

## Релизы

1. Тег `vX.Y.Z` → `release.yml`.
2. Стадии: test → build-binaries (amd64/arm64/armv7) → docker (multi-arch,
   SBOM/provenance) → build-apk (подпись) → publish (SHA256SUMS + Release,
   тело из CHANGELOG).
3. **Версионирование**: SemVer; versionCode в `android/app/build.gradle.kts`
   увеличивается на каждый релиз.
4. **Деплой-эквивалент прод-машины**: путь
   `/portainer/Files/AppData/Config/reverseray/reverseray`.
5. Откат: предыдущий digest из `deploy/digests.yaml`.
6. Автообновление контейнера запрещено; обновления — только вручную или
   автопилотом `deploy/rr.sh` (создаёт `./reverseray/` относительно текущего
   каталога, решает установка/обновление, печатает строку подключения;
   `--reset` — обнулить состояние).
7. Скорость релиза (v0.7): паблиш берёт артефакты `build-binaries` (без
   пересборки), Go-тест+coverage одним прогоном, кэш Gradle в CI.

## Тестовые матрицы

- **Go**: unit + E2E (fake-phone) + hostile-environment (`evilclient_test.go`)
  — запускаются в каждом PR и релизе.
- **Android**: 101 unit (Robolectric API 21/31, evil-сервер, QR, SSRF, тайминги,
  канон HELLO/AUTH, бронепарсер rrp://, согласование протоколов, PROBE-кадры);
  JVM-изоляция (`forkEvery=1`) обязательна.
- **Ассеты**: детерминизм, размеры, синхронность лендинг-копий.

## Диагностика

- Сервер: `RR_DEBUG_LOG=1` — debug-логи в тестах; admin `/metrics` — метрики.
- Клиент: кнопка «Журнал» — копируемая история ошибок.
- Артефакт `android-test-reports` в CI (always) — XML-отчёты.

## Секреты

- `RR_KEYSTORE*` (GitHub Secrets) — личная подпись APK; по умолчанию
  используется репозиторный ключ.
- Deploy key — только gh-pages/теги; ротация 12 мес.
- В репо секретов нет (gitleaks в CI).
