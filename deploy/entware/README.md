# ReversERay сервер — Entware-роутер (Netcraze Ultra NC-1812 и любые aarch64/armv7)

Сервер ReversERay на роутере **без Docker**: статический бинарь из GitHub
Releases + init-скрипт Entware. NC-1812 (Netcraze Ultra, MT7988D,
3×Cortex-A73, aarch64) — целевая платформа; подойдёт любой Entware-роутер.

## Канон модем-сервера (v1.7.1)

- **Веб-морда закрыта**: admin слушает `127.0.0.1` (или unix-сокет) — наружу не торчит;
- **диск не страдает**: лог — в tmpfs `/tmp` или `/dev/null` (настраивается);
- **один конфиг всего**: `/opt/etc/reverseray/reverseray.conf` (порт, бинды,
  лог, имя устройства, версия релиза);
- **валидация в комплекте**: процесс, healthz, листенеры, бинды «наружу»,
  sha256 артефакта, RAM-footprint.

## Установка — один скрипт (на роутере)

```sh
# скачать скрипт на роутер и запустить (нужны curl/wget, sha256sum)
curl -fsSL https://raw.githubusercontent.com/stelgen/reverseray/main/deploy/rr-entware.sh -o /opt/tmp/rr-entware.sh
sh /opt/tmp/rr-entware.sh            # установка/обновление до последнего релиза
```

Скрипт сам: определит архитектуру (aarch64 → `reverseray-linux-arm64`),
скачает бинарь, сверит sha256, проверит что бинарь живёт на этом ядре,
создаст конфиги и init-скрипт, запустит сервис, прогонит валидацию,
зарегистрирует телефон (enroll) и напечатает **ссылку `rrp://` для APK**
и **какие порты пробросить** в файрвол роутера (TCP туннеля + TCP/UDP прокси).

```sh
sh /opt/tmp/rr-entware.sh --validate   # повторная валидация без переустановки
sh /opt/tmp/rr-entware.sh --reset      # обнулить state (токены/CA) и пере-enroll
sh /opt/tmp/rr-entware.sh --tag v1.7.1 # зафиксировать версию
```

## Конфиг: /opt/etc/reverseray/reverseray.conf

| Ключ | Смысл | Дефолт |
|---|---|---|
| `RR_TAG` | версия релиза | `latest` |
| `RR_TUNNEL_BIND` | слушатель туннеля телефона (TLS) | `:4433` |
| `RR_MIXED_BIND` | прокси SOCKS5+HTTP (egress через телефон) | `:1080` |
| `RR_ADMIN_BIND` | админ/веб-морда — канон модема `127.0.0.1:…`, пусто = unix-сокет | `127.0.0.1:9090` |
| `RR_LOG_MODE` | `ram` (tmpfs) / `none` / `file` | `ram` |
| `RR_ENROLL_NAME` | имя устройства в ссылке | `phone-1` |
| `RR_SESSIONS` | мультипоточность 1–8 (порт дублируется в ссылке) | `1` |
| `RR_PUBLIC_HOST` | WAN-IP/DDNS для ссылки (пусто = авто) | авто |

После правки: `sh /opt/etc/init.d/S99reverseray restart`.

## Как это работает

- **Телефон = egress-узел** (канон ReversERay): прокси-порт (`mixed`) и
  туннель обслуживают трафик через подключенный APK-клиент. Без телефона
  egress честно отсутствует — это норма, скрипт валидации это учитывает.
- **Наружу** пробрасываются только порт туннеля (TCP) и порт прокси
  (TCP/UDP, если нужен внешний SOCKS5). Веб-морда не пробрасывается никогда.
- State (токены/CA) пишется только в `RR_STATE_DIR` — небольшие файлы;
  логи — в tmpfs, чтобы не изнашивать флешку модема.

## Вручную (если скрипт не подходит)

```sh
curl -L -o /opt/tmp/reverseray https://github.com/stelgen/reverseray/releases/download/v1.7.1/reverseray-linux-arm64
mkdir -p /opt/bin /opt/etc/reverseray
install -m 0755 /opt/tmp/reverseray /opt/bin/reverseray
/opt/bin/reverseray run -config /opt/etc/reverseray/config.json   # конфиг — см. скрипт
/opt/bin/reverseray enroll -state-dir /opt/var/lib/reverseray -name phone-1 -host <WAN_IP>
```

Артефакты релиза: `reverseray-linux-arm64` (NC-1812), `-armv7`, `-amd64`,
`SHA256SUMS`. Бинарь статический (CGO выключен) — зависимости Entware не нужны.
