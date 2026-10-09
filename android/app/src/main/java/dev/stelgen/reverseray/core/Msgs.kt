package dev.stelgen.reverseray.core

/**
 * v0.8.3: ЕДИНЫЙ типизированный каталог сообщений core-слоя.
 *
 * Правила канона i18n:
 *  - en обязателен и является ФОЛБЭКОМ: если ru == null, всегда английский;
 *  - плейсхолдеры %s/%d — String.format c Locale.US (числа не зависят
 *    от локали устройства);
 *  - НОВЫЙ код обязан добавлять строки сюда (не хардкодить в коде) —
 *    StringsGateTest в CI ловит кириллицу-литералы в src/main;
 *  - формат вызова: Msgs.X.t(a, b) — аргументы по порядку плейсхолдеров.
 */
object Msgs {

    // ── RrpClient: жизненный цикл/HELLO ──────────────────────────────
    val CLIENT_ACTIVE = Msg("client already active: %s", "клиент уже активен: %s")
    val SENT_HELLO = Msg(
        "SENT HELLO agent=%s device=%s ver=%s caps=[chacha20,alpn] proto=%s (%s) max_streams=%s (%sB)",
        "SENT HELLO agent=%s device=%s ver=%s caps=[chacha20,alpn] proto=%s (%s) max_streams=%s (%sБ)",
    )

    // ── RrpClient: рукопожатие ───────────────────────────────────────────
    val HELLO_OK_TIMEOUT = Msg("HELLO_OK timeout (%s)", "таймаут HELLO_OK (%s)")
    val HELLO_OK_EMPTY = Msg("HELLO_OK: no data", "HELLO_OK без данных")
    val HELLO_OK_NO_NONCE = Msg(
        "HELLO_OK without nonce (server did not send a one-time nonce)",
        "HELLO_OK без nonce (сервер не прислал одноразовый nonce)",
    )
    val HELLO_OK_BAD_NONCE = Msg("HELLO_OK: nonce is not base64 (%s)", "HELLO_OK: nonce не base64 (%s)")
    val READY_TIMEOUT = Msg("READY timeout (%s)", "таймаут READY (%s)")
    val READY_EMPTY = Msg("READY: no data", "READY без данных")
    val APIMASK_ENABLED = Msg(
        "API Mask: server confirmed apimask — background chatter is on",
        "API Mask: сервер подтвердил apimask — фоновый шум включён",
    )
    val PROBE_SENT = Msg("PROBE → %s (protocol validation %s)", "PROBE → %s (валидация протокола %s)")
    val PROBE_NOT_ANSWERED = Msg(
        "PROBE not answered by the server (validation failed)",
        "PROBE не отвечен сервером (валидация не пройдена)",
    )
    val PROBE_VALIDATION_FAILED = Msg("validation failed: %s", "валидация не пройдена: %s")
    val PROBE_NO_EGRESS = Msg("no egress", "нет egress")
    val PROBE_OK = Msg("PROBE OK — egress up to %s confirmed", "PROBE OK — egress до %s подтверждён")
    val HANDSHAKE_INTERRUPTED = Msg("handshake interrupted", "рукопожатие прервано")
    val TRANSPORT_NOT_READY = Msg("transport not initialized", "транспорт не инициализирован")
    val HANDSHAKE_FAILED = Msg("handshake not completed: %s", "рукопожатие не завершено: %s")
    val READER_STOPPED = Msg("reader stopped: %s", "reader остановлен: %s")

    // ── RrpClient: кадры ─────────────────────────────────────────────────
    val AUTH_UNEXPECTED = Msg("AUTH from the server is not expected", "AUTH от сервера не ожидается")
    val HELLO_UNEXPECTED = Msg("HELLO from the server is not expected", "HELLO от сервера не ожидается")
    val PROBE_UNEXPECTED = Msg("PROBE from the server is not expected", "PROBE от сервера не ожидается")
    val KEY_RESP_UNEXPECTED = Msg("KEY_RESP from the server is not expected", "KEY_RESP от сервера не ожидается")
    val SERVER_ERROR_RAW = Msg(
        "server ERROR %s: %s (raw payload %s)",
        "сервер ERROR %s: %s (raw payload %s)",
    )
    val SERVER_ERROR = Msg("server returned ERROR %s: %s", "сервер вернул ERROR %s: %s")
    val KEY_REQ_IGNORED = Msg(
        "KEY_REQ again — ignoring (crypto already enabled)",
        "KEY_REQ повторно — игнорирую (крипто уже включена)",
    )

    // ── RrpClient: mtproto2 ──────────────────────────────────────────────
    val DH_PRIME_MISMATCH = Msg(
        "p does not match the canonical dh_prime (anti-logjam)",
        "p не равен каноническому dh_prime (anti-logjam)",
    )
    val DH_G_UNEXPECTED = Msg("g = %s, expected 3", "g = %s, ожидали 3")
    val NO_SESSION_ID = Msg("no session_id", "нет session_id")
    val MTPROTO_KEYS_OK = Msg(
        "MTProto/2: keys agreed (DH 2048, Telegram canon; DATA/UDP_DATA payload is AES-256-IGE encrypted)",
        "MTProto/2: ключи согласованы (DH 2048, канон Telegram; payload DATA/UDP_DATA шифруется AES-256-IGE)",
    )
    val MTPROTO_EXCHANGE_FAILED = Msg(
        "MTProto/2: key exchange failed: %s",
        "MTProto/2: обмен ключами не удался: %s",
    )
    val MTPROTO_DATA_ENVELOPE_BAD = Msg(
        "MTProto/2: bad DATA envelope (stream %s): %s — stream closed",
        "MTProto/2: битый конверт DATA (stream %s): %s — поток закрыт",
    )
    val MTPROTO_UDP_ENVELOPE_BAD = Msg(
        "MTProto/2: bad UDP_DATA envelope: %s",
        "MTProto/2: битый конверт UDP_DATA: %s",
    )

    // ── RrpClient: wireguard (v0.9.5) ─────────────────────────────────────
    val WG_BAD_SPUB = Msg(
        "WireGuard: bad server static pub (len %s)",
        "WireGuard: битый static public сервера (длина %s)",
    )
    val WG_INIT_SENT = Msg(
        "SENT WG_INIT (%sB) — Noise_IKpsk2 msg1 (PSK = SHA256(token))",
        "SENT WG_INIT (%sБ) — msg1 Noise_IKpsk2 (PSK = SHA256(токена))",
    )
    val WG_RESP_TIMEOUT = Msg(
        "WireGuard: WG_RESP (msg2) not received in time",
        "WireGuard: WG_RESP (msg2) не получен вовремя",
    )
    val WG_RESP_RECV = Msg(
        "RECV WG_RESP (%sB) — WireGuard msg2 accepted",
        "RECV WG_RESP (%sБ) — msg2 WireGuard принят",
    )
    val WG_MSG2_LEN = Msg(
        "wg msg2 len %s not equal %s",
        "wg msg2 длина %s ≠ %s",
    )
    val WG_MSG2_TYPE = Msg(
        "wg msg2 type not equal 2",
        "wg msg2 тип ≠ 2",
    )
    val WG_MSG2_RECEIVER = Msg(
        "wg msg2 receiver not equal our sender_index",
        "wg msg2 receiver ≠ наш sender_index",
    )
    val WG_MSG2_MAC1 = Msg(
        "wg msg2 mac1 mismatch",
        "wg msg2 mac1 не совпал",
    )
    val WG_PACKET_SHORT = Msg(
        "wg transport packet too short",
        "wg transport-пакет слишком короткий",
    )
    val WG_PACKET_TYPE = Msg(
        "wg transport type not equal 4",
        "wg transport тип ≠ 4",
    )
    val WG_REPLAY = Msg(
        "wg transport replay detected",
        "wg transport: повтор пакета (анти-реплей)",
    )
    val WG_COUNTER = Msg(
        "wg transport counter exhausted (rekey required)",
        "wg transport: счётчик исчерпан (нужен ре-кей)",
    )
    val WG_INIT_UNEXPECTED = Msg(
        "WG_INIT from the server is not expected",
        "WG_INIT от сервера не ожидается",
    )
    val WG_KEYS_AGREED = Msg(
        "WireGuard/1: handshake OK (Noise_IKpsk2 + PSK; DATA/UDP_DATA payload is ChaCha20-Poly1305, window 2048)",
        "WireGuard/1: хендшейк OK (Noise_IKpsk2 + PSK; payload DATA/UDP_DATA шифруется ChaCha20-Poly1305, окно 2048)",
    )
    val WG_FAILED = Msg(
        "WireGuard: handshake failed: %s",
        "WireGuard: хендшейк не удался: %s",
    )
    val CAM_CTL_SENT = Msg(
        "SENT CAM_CTL %s (0x2A) — device choice persisted on server",
        "SENT CAM_CTL %s (0x2A) — выбор устройства сохранён на сервере",
    )
    val CAM_CTL_FAILED = Msg(
        "CAM_CTL not sent: %s",
        "CAM_CTL не отправлен: %s",
    )
    val CAM_CTL_UNEXPECTED = Msg(
        "CAM_CTL from the server is not expected",
        "CAM_CTL от сервера не ожидается",
    )

    // ── RrpClient: SSRF/UDP/WS/каналы ────────────────────────────────────
    val SEND_OPEN_SSRF = Msg("sendOpen: %s blocked by SSRF-guard", "sendOpen: %s заблокирован SSRF-guard")
    val OPEN_SSRF = Msg("OPEN %s blocked by SSRF-guard", "OPEN %s заблокирован SSRF-guard")
    val OPEN_RESOLVES_SSRF = Msg(
        "OPEN %s: all resolved addresses blocked by SSRF-guard",
        "OPEN %s: все резолвы заблокированы SSRF-guard",
    )
    val WINDOW_NOT_GROWN = Msg(
        "stream %s: window not grown within %s ms — closing",
        "stream %s: окно не наращено за %sмс — закрываю",
    )
    val UDP_ASSOC_FAILED = Msg("UDP assoc: failed to open socket: %s", "UDP assoc: не удалось поднять сокет: %s")
    val UDP_SSRF = Msg("UDP %s blocked by SSRF-guard", "UDP %s заблокирован SSRF-guard")
    val UDP_RESOLVE_SSRF = Msg("UDP %s: resolved address blocked by SSRF-guard", "UDP %s: резолв заблокирован SSRF-guard")
    val UDP_ADDR_SSRF = Msg("UDP %s: address blocked by SSRF-guard", "UDP %s: адрес заблокирован SSRF-guard")
    val WS_WRITE_UNSUPPORTED = Msg("WS: bytewise write is not supported", "WS: побайтовая запись не поддерживается")
    val PROBE_SEND_FAILED = Msg("PROBE not sent: %s", "PROBE не отправлен: %s")
    val PING_SEND_FAILED = Msg("ping not sent: %s", "ping не отправлен: %s")
    val NO_CONNECTION = Msg("no connection", "нет соединения")
    val DATA_LIMIT = Msg("DATA %s > protocol envelope limit", "DATA %s > лимита конверта протокола")
    val UDP_DATA_LIMIT = Msg("UDP_DATA %s > envelope limit — dropped", "UDP_DATA %s > лимита конверта — дроп")
    val NOISE_GEN_FAILED = Msg("noise: generation failed: %s", "noise: генерация не удалась: %s")
    val NOISE_SEND_FAILED = Msg("noise not sent: %s", "noise не отправлен: %s")
    val SEND_FAILED = Msg("send failed: %s", "send не удался: %s")

    // ── TunnelService (companion — без Context) ──────────────────────
    val LOG_SETTING_CHANGE = Msg("setting: %s: %s → %s", "настройка: %s: %s → %s")

    // ── RrpClient: TLS/пин ───────────────────────────────────────────────
    val TLS_PIN_MISMATCH = Msg(
        "TLS: CA pin MISMATCH — connection rejected (anti-MITM). Server's real pin: %s. If the server CA changed — refresh the link (re-enroll).",
        "TLS: CA-pin НЕ совпал — соединение отклонено (анти-MITM). Реальный pin сервера: %s. Если сервер менял CA — обнови ссылку (re-enroll).",
    )
    val TLS_TOFU_FIRST = Msg(
        "TLS: no pin — TOFU: server pinned, pin=%s (keep the config line)",
        "TLS: пина нет — TOFU: сервер зафиксирован, pin=%s (сохрани строку конфига)",
    )
    val TLS_TOFU_OVERRIDE = Msg(
        "TLS: pin mismatch but explicit TOFU-override enabled — self-signed server accepted, pin=%s",
        "TLS: пин не совпал, но включён явный TOFU-override — принят самоподписанный сервер, pin=%s",
    )
    val TLS_CERT_VALID = Msg(
        "TLS: server certificate valid until %s, issuer: %s (pin = SPKI CA, leaf rotation does not break clients)",
        "TLS: серверный серт действителен до %s, издатель: %s (pin — SPKI CA, ротация листа клиентов не ломает)",
    )
    val PIN_FORMAT = Msg("pin: expected sha256 (32 bytes, hex/base64)", "pin: ожидался sha256 (32 байта, hex/base64)")
    val PIN_ACCEPTED = Msg(
        "CA pin updated (owner confirmed): %s — reconnecting with the new pin",
        "пин CA обновлён (подтверждено владельцем): %s — реконнект с новым пином",
    )

    // ── RrpFrame: границы/размеры ────────────────────────────────────────
    val FRAME_PAYLOAD_LIMIT = Msg(
        "payload %s > limit %s for type 0x%s",
        "payload %s > лимита %s для типа 0x%s",
    )
    val STREAM_ID_RANGE = Msg("stream_id out of u32: %s", "stream_id вне u32: %s")
    val FLAGS_RANGE = Msg("flags out of u16: %s", "flags вне u16: %s")
    val FRAME_VERSION = Msg("unsupported frame version: %s", "неподдерживаемая версия кадра: %s")
    val UNKNOWN_FRAME = Msg("unknown frame type 0x%s", "неизвестный тип кадра 0x%s")
    val STREAM_TRUNCATED = Msg(
        "RRP: stream cut short (%s more bytes expected)",
        "RRP: обрыв потока (ожидалось ещё %s байт)",
    )

    // ── RrpFrame: парсеры кадров ─────────────────────────────────────────
    val HELLO_BAD_JSON = Msg("HELLO: invalid JSON", "HELLO: некорректный JSON")
    val HELLO_OK_BAD_JSON = Msg("HELLO_OK: invalid JSON", "HELLO_OK: некорректный JSON")
    val AUTH_BAD_JSON = Msg("AUTH: invalid JSON", "AUTH: некорректный JSON")
    val READY_BAD_JSON = Msg("READY: invalid JSON", "READY: некорректный JSON")
    val OPEN_EMPTY = Msg("OPEN: empty payload", "OPEN: пустой payload")
    val OPEN_NO_HOSTLEN = Msg("OPEN: no domain length", "OPEN: нет длины домена")
    val OPEN_BAD_ATYP = Msg("OPEN: unknown ATYP %s", "OPEN: неизвестный ATYP %s")
    val OPEN_SHORT = Msg("OPEN: short payload", "OPEN: короткий payload")
    val OPEN_OK_SIZE = Msg("OPEN_OK: expected 1 byte, got %s", "OPEN_OK: ожидался 1 байт, получено %s")
    val CLOSE_SIZE = Msg("CLOSE: expected 1 byte, got %s", "CLOSE: ожидался 1 байт, получено %s")
    val WINDOW_SIZE = Msg("WINDOW: expected 4 bytes, got %s", "WINDOW: ожидалось 4 байта, получено %s")
    val PING_SIZE = Msg("PING: expected an 8-byte nonce, got %s", "PING: ожидался 8-байтовый nonce, получено %s")
    val PONG_SIZE = Msg("PONG: expected an 8-byte nonce, got %s", "PONG: ожидался 8-байтовый nonce, получено %s")
    val UDP_EMPTY = Msg("UDP_DATA: empty payload", "UDP_DATA: пустой payload")
    val UDP_NO_HOSTLEN = Msg("UDP_DATA: no domain length", "UDP_DATA: нет длины домена")
    val UDP_BAD_ATYP = Msg("UDP_DATA: unknown ATYP %s", "UDP_DATA: неизвестный ATYP %s")
    val UDP_SHORT = Msg("UDP_DATA: short payload", "UDP_DATA: короткий payload")
    val PROBE_BAD_JSON = Msg("PROBE: invalid JSON", "PROBE: некорректный JSON")
    val NOISE_NOT_JSON = Msg("NOISE: expected a JSON object", "NOISE: ожидался JSON-объект")
    val NOISE_BAD_JSON = Msg("NOISE: invalid JSON", "NOISE: некорректный JSON")
    val KEY_REQ_BAD_JSON = Msg("KEY_REQ: invalid JSON", "KEY_REQ: некорректный JSON")
    val KEY_RESP_BAD_JSON = Msg("KEY_RESP: invalid JSON", "KEY_RESP: некорректный JSON")
    val ERROR_TOO_LONG = Msg(
        "ERROR: message longer than the control-frame limit",
        "ERROR: сообщение длиннее лимита контрольного кадра",
    )
    val ERROR_SHORT = Msg("ERROR: short payload", "ERROR: короткий payload")

    // ── RrpUri ───────────────────────────────────────────────────────────
    val URI_SCHEME = Msg("expected rrp:// scheme", "ожидалась схема rrp://")
    val URI_NO_TOKEN = Msg("no token: rrp://token@host:ports", "нет токена: rrp://token@host:ports")
    val URI_EMPTY_TOKEN = Msg("empty token", "пустой токен")
    val URI_IPV6_NOCLOSE = Msg("IPv6 literal without closing ]", "IPv6-литерал без закрывающей ]")
    val URI_IPV6_NO_PORTS = Msg("no ports after ]", "нет портов после ]")
    val URI_NO_PORTS = Msg("no ports: host:443,8443", "нет портов: host:443,8443")
    val URI_EMPTY_HOST = Msg("empty host", "пустой хост")
    val URI_BAD_PORT = Msg("invalid port: %s", "некорректный порт: %s")
    val URI_PORT_RANGE = Msg("port out of 1..65535: %s", "порт вне 1..65535: %s")
    val URI_EMPTY_PORTS = Msg("empty port list", "список портов пуст")
    val URI_PCT_TRUNCATED = Msg("truncated percent-encoding", "обрезанный percent-encoding")
    val URI_PCT_BAD = Msg("invalid percent-encoding: %s", "некорректный percent-encoding: %s")

    // ── RrpAddress ───────────────────────────────────────────────────────
    val ADDR_PORT_RANGE = Msg("port out of 1..65535: %s", "порт вне 1..65535: %s")
    val ADDR_EMPTY = Msg("empty address", "пустой адрес")
    val ADDR_IPV6_BAD = Msg("invalid IPv6 literal: %s", "некорректный IPv6-литерал: %s")
    val ADDR_EMPTY_DOMAIN = Msg("empty domain", "пустой домен")
    val ADDR_DOMAIN_TOO_LONG = Msg("domain longer than 255 bytes", "домен длиннее 255 байт")
    val OPEN_IPV4_SHORT = Msg("OPEN: short IPv4", "OPEN: короткий IPv4")
    val OPEN_DOMAIN_TRUNCATED = Msg("OPEN: domain truncated", "OPEN: домен обрезан")
    val OPEN_IPV6_SHORT = Msg("OPEN: short IPv6", "OPEN: короткий IPv6")
    val OPEN_NO_PORT = Msg("OPEN: no port", "OPEN: нет порта")
    val OPEN_BAD_PORT = Msg("OPEN: invalid port %s", "OPEN: некорректный порт %s")
    val IPV4_SIZE = Msg("IPv4: expected 4 bytes", "IPv4: ожидалось 4 байта")
    val IPV6_SIZE = Msg("IPv6: expected 16 bytes", "IPv6: ожидалось 16 байт")
    val ATYP_UNKNOWN = Msg("unknown ATYP %s", "неизвестный ATYP %s")

    // ── MtProto ──────────────────────────────────────────────────────────
    val G_PEER_SIZE = Msg("g_peer > 256 bytes", "g_peer > 256 байт")
    val PUBLIC_SHARE_SIZE = Msg("public share must be 256 bytes", "публичная доля должна быть 256 байт")
    val KEYPAIR_GEN_FAILED = Msg(
        "failed to generate a valid key pair",
        "не удалось сгенерировать валидную пару",
    )
    val G_AB_RANGE = Msg("g_ab out of corridor", "g_ab вне коридора")
    val NOT_BASE64 = Msg("not base64: %s", "не base64: %s")
    val IGE_BLOCK_ALIGN = Msg("IGE: length is not a multiple of the block size", "IGE: длина не кратна блоку")
    val AUTH_KEY_SIZE = Msg("auth_key must be 256 bytes", "auth_key должен быть 256 байт")
    val SALT_SESSION_SIZE = Msg("salt/session_id must be 8 bytes", "salt/session_id должны быть 8 байт")
    val MTPROTO_PAYLOAD_LIMIT = Msg("payload exceeds the DATA limit", "payload превышает лимит DATA")
    val MTPROTO_ENVELOPE_BAD = Msg("bad envelope", "битый конверт")
    val FOREIGN_AUTH_KEY = Msg("foreign auth_key_id", "чужой auth_key_id")
    val MTPROTO_BODY_SHORT = Msg("body shorter than the header", "тело короче заголовка")
    val SALT_MISMATCH = Msg("salt mismatch", "salt не совпал")
    val SESSION_MISMATCH = Msg("session_id mismatch", "session_id не совпал")
    val MSGLEN_OVERFLOW = Msg("msg_len > body", "msg_len > тела")
    val PADDING_RANGE = Msg("padding %s out of 12..1024", "паддинг %s вне 12..1024")
    val MSG_KEY_MISMATCH = Msg("msg_key mismatch", "msg_key не сошёлся")

    // ── Modules (манифест) ───────────────────────────────────────────────
    val MANIFEST_NOT_JSON = Msg("manifest is not JSON: %s", "манифест не JSON: %s")
    val MANIFEST_SCHEMA = Msg("schema is not 1", "schema не 1")
    val MANIFEST_VERSION = Msg("version is not semver: %s", "версия не семвер: %s")
    val MANIFEST_NO_REGISTRY = Msg("no protocol registry", "нет реестра протоколов")
    val MANIFEST_BAD_PROTOCOL_ID = Msg("garbage protocol id", "мусорный id протокола")
    val MANIFEST_DUPLICATE_PROTOCOL = Msg("duplicate protocol %s", "дубликат протокола %s")
    val MANIFEST_NO_RRP1 = Msg("registry without rrp1 is forbidden", "реестр без rrp1 запрещён")
    val MANIFEST_BAD_PROBE_TARGET = Msg("broken probe_default_target: %s", "битый probe_default_target: %s")
    val MANIFEST_BAD_CAMO_ID = Msg("garbage camouflage module id", "мусорный id модуля camouflage")

    // ── WsStream ─────────────────────────────────────────────────────────
    val WS_EMPTY_RESPONSE = Msg("<empty>", "<пусто>")
    val WS_UPGRADE_REJECTED = Msg("WebSocket upgrade rejected: %s", "WebSocket-апгрейд отклонён: %s")
    val WS_NO_ACCEPT = Msg("WebSocket: no Sec-WebSocket-Accept", "WebSocket: нет Sec-WebSocket-Accept")
    val WS_BAD_ACCEPT = Msg("WebSocket: invalid Sec-WebSocket-Accept", "WebSocket: некорректный Sec-WebSocket-Accept")
    val WS_READ_INTERRUPTED = Msg("WS: interrupted while reading the upgrade response", "WS: обрыв при чтении ответа апгрейда")
    val WS_UPGRADE_TOO_LONG = Msg("WS: upgrade response too long (%s bytes)", "WS: слишком длинный ответ апгрейда (%s байт)")
    val WS_MSG_TOO_BIG = Msg("WS: message %s > %s", "WS: сообщение %s > %s")
    val WS_BAD_OPCODE = Msg("WS: unsupported opcode 0x%s", "WS: неподдерживаемый opcode 0x%s")
    val WS_SKIP_INTERRUPTED = Msg("WS: interrupted while skipping a frame", "WS: обрыв при пропуске кадра")
    val WS_TRUNCATED = Msg("WS: stream cut short (%s more bytes expected)", "WS: обрыв потока (ожидалось ещё %s байт)")

    // ── ProtoFallback ────────────────────────────────────────────────────
    val FALLBACK_NOTICE = Msg(
        "protocol module %s fails to connect (%s failures in a row) — the client falls back to %s; the server NEVER rolls back (anti-loop): it will raise the new protocol once it updates itself",
        "модуль протокола %s не даёт подключиться (%s неудачи подряд) — клиент фоллбечится на %s; сервер не откатываем (анти-цикл): он поднимет новый протокол, когда обновится сам",
    )

    // ── RrpProtocols: суффиксы меток ─────────────────────────────────────
    val LABEL_STABLE = Msg(" · stable", " · стабильный")
    val LABEL_PAYLOAD_ENC = Msg(" · payload encryption", " · шифрование payload")

    // ── SecurityFacts (вкладка «О приложении») ───────────────────────────
    val SF_TLS_MIN = Msg(
        "TLS 1.3 (minimum; TLS 1.2 allowed only in the compat profile)",
        "TLS 1.3 (минимум; TLS 1.2 разрешён только в compat-профиле)",
    )
    val SF_TLS_LIB = Msg(
        "BouncyCastle BcTlsCrypto (lightweight, no platform JCA)",
        "BouncyCastle BcTlsCrypto (lightweight, без платформенного JCA)",
    )
    val SF_PKI = Msg(
        "self-signed CA (10 years) → leaf 3 years; pin = SHA256(SPKI CA)",
        "self-signed CA (10 лет) → лист 3 года; пин = SHA256(SPKI CA)",
    )
    val SF_PIN = Msg(
        "strict: pin set and mismatched → connection rejected (anti-MITM); TOFU only for the first friendship (no pin yet)",
        "строгий: пин задан и не совпал → соединение отклоняется (анти-MITM); TOFU только для первой дружбы (пина нет)",
    )
    val SF_NO_0RTT = Msg(
        "0-RTT/early data is not used; resumption never skips AUTH",
        "0-RTT/early data не используется; resumption не пропускает AUTH",
    )
    val SF_TOKEN_HASH = Msg(
        "the server stores only SHA256(token); the token never leaves the device",
        "сервер хранит только SHA256(token); токен никогда не покидает устройство",
    )
    val SF_HMAC = Msg(
        "HMAC-SHA256(key=SHA256(token), msg=nonce‖session_id), constant-time comparison",
        "HMAC-SHA256(key=SHA256(token), msg=nonce‖session_id), сравнение constant-time",
    )
    val SF_NONCE = Msg(
        "one-time 128-bit nonce (crypto/rand), TTL 60 s, replay → rejection",
        "одноразовый 128-бит nonce (crypto/rand), TTL 60 с, replay → отказ",
    )
    val SF_LOCKOUT = Msg(
        "≤120 handshakes/min/IP; lockout only for invalid HMAC: 5 failures → 30s·2^n (up to 10 min)",
        "≤120 рукопожатий/мин/IP; lockout только за невалидный HMAC: 5 неудач → 30с·2^n (до 10 мин)",
    )
    val SF_MTPROTO = Msg(
        "MTProto 2.0: DH-2048 on the official Telegram dh_prime (safe prime, anti-logjam), AES-256-IGE, msg_key SHA-256",
        "MTProto 2.0: DH-2048 на официальном dh_prime Telegram (safe prime, anti-logjam), AES-256-IGE, msg_key SHA-256",
    )
    val SF_LIMITS = Msg(
        "DATA ≤ 65535 B; other frames ≤ 4096 B; stream window 512 KB→4 MB; session budget 16 MB",
        "DATA ≤ 65535 Б; прочие кадры ≤ 4096 Б; окно стрима 512 КБ→4 МБ; бюджет сессии 16 МБ",
    )
    val SF_HARDENING = Msg(
        "first byte ≠ TLS → tarpit + silence (0 response bytes); global + per-IP concurrency limits",
        "первый байт ≠ TLS → tarpit + тишина (0 байт ответа); глобальный + per-IP лимиты параллельности",
    )
    val SF_SSRF = Msg(
        "private-range blacklist on the client (DNS-rebinding protected by post-resolve address checks)",
        "блэклист приватных диапазонов на клиенте (DNS-rebinding защищён пострезолвной проверкой адресов)",
    )
    val SF_MANIFEST = Msg(
        "modules.json manifest: schema check, semver, sha256, downgrade forbidden, garbage never applied",
        "манифест modules.json: schema-чек, семвер, sha256, даунгрейд запрещён, мусор не применяется",
    )
    val SF_UPDATES = Msg(
        "release signed v1+v2+v3; release SHA256SUMS verified before APK installation",
        "релиз подписан v1+v2+v3; SHA256SUMS релиза сверяется перед установкой APK",
    )

    // ── DnsProbe (вкладка «О сети») ──────────────────────────────────────
    val DP_NO_CONTEXT = Msg("no application context", "нет контекста приложения")
    val DP_SNI_OS = Msg(
        "not supported at the OS level (SNI goes out in the clear inside apps' TLS connections)",
        "не поддерживается уровнем ОС (SNI уходит открытым внутри TLS-соединений приложений)",
    )
    val DP_SYSTEM_DNS = Msg("System DNS servers", "DNS-серверы системы")
    val DP_NOT_DETERMINED = Msg("not determined", "не определены")
    val DP_REAL_RESOLVER = Msg("Who actually resolves", "Кто реально резолвит")
    val DP_ROUTER_SUFFIX = Msg(" (this is your system DNS — the router)", " (это ваш системный DNS — роутер)")
    val DP_UPPER_SUFFIX = Msg(" (upstream resolver, not the router)", " (верхний резолв, не роутер)")
    val DP_UNDEFINED = Msg("could not determine", "не удалось определить")
    val DP_DNSSEC = Msg("DNSSEC (AD on a signed zone)", "DNSSEC (AD на подписанной зоне)")
    val DP_DNSSEC_YES = Msg("yes — the resolver validates", "да — резолвер валидирует")
    val DP_DNSSEC_NO = Msg("no — AD is not set", "нет — AD не ставится")
    val DP_DNSSEC_FAIL = Msg("could not check", "не удалось проверить")
    val DP_DOT_AVAILABLE = Msg("available", "доступен")
    val DP_DOT_UNAVAILABLE = Msg("unavailable", "недоступен")
    val DP_NOT_CHECKED = Msg("not checked", "не проверен")
    val DP_ECS_AVAILABLE = Msg("available on this network", "доступен в этой сети")
    val DP_ECS_UNAVAILABLE = Msg("unavailable (blocked / no egress)", "недоступен (заблокирован/нет выхода)")
    val DP_ECC_SENT = Msg("sent", "шлётся")
    val DP_ECC_NOT_SENT = Msg("not sent by the app (we do not send it)", "не шлётся приложением (мы не отправляем)")
    val DP_ECH = Msg("SNI encryption (ECH)", "Шифрование SNI (ECH)")

    // ── SpeedTest ────────────────────────────────────────────────────────
    val ST_HTTP_CHECK = Msg("Internet HTTP check ← %s (HTTPS)", "HTTP-проверка интернета ← %s (HTTPS)")
    val ST_TCP_PING = Msg("TCP ping → %s", "TCP-пинг → %s")
    val ST_DOWNLOAD = Msg("25 MB download ← %s (HTTPS)", "скачивание 25 МБ ← %s (HTTPS)")
    val ST_HTTP_OK = Msg("HTTP %s → 200 in %s ms", "HTTP %s → 200 за %s мс")
    val ST_HTTP_DOWN = Msg("HTTP %s → unreachable", "HTTP %s → недоступен")
    val ST_NO_INET = Msg("no internet (HTTP check failed)", "интернета нет (HTTP-проверка не прошла)")
    val ST_PING_RESULT = Msg("TCP ping %s → %s", "TCP-пинг %s → %s")
    val ST_PING_MS = Msg("%s ms", "%s мс")
    val ST_PING_NONE = Msg("no reply", "нет ответа")
    val ST_DOWNLOAD_DONE = Msg("download %s → %s B", "скачивание %s → %s Б")

    // ── UpdateChecker ────────────────────────────────────────────────────
    val UC_APK_NAME = Msg("reverseray-<version>.apk", "reverseray-<версия>.apk")
    val UC_SHA_MISMATCH = Msg(
        "APK SHA256 did not match the release SHA256SUMS (%s ≠ %s) — installation cancelled (possible tampering)",
        "SHA256 APK не совпал с SHA256SUMS релиза (%s ≠ %s) — установка отменена (возможна подмена)",
    )
}