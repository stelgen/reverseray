// Package apimasq — модуль камуфляжа «API Mask» (v0.8.2, module id: apimask).
//
// Назначение: туннельный трафик APK↔сервер дополняется низкообъёмным
// «фоновым обменом», неотличимым по форме и ритму от API обычного бизнес-
// приложения: периодические JSON-запросы/ответы (телеметрия/синхронизация/
// конфиг) со случайными размерами и джиттером интервала. Для DPI (ТСПУ)
// сессия выглядит как работа корпоративного приложения, а не как «труба».
//
// Принципы канона ReverseRay:
//   - НОЛЬ внешних запросов: шум ходит ТОЛЬКО внутри приватного туннеля
//     (клиент ↔ сервер), никакого реального egress и внешних хостов;
//   - НИЧЕГО НЕ ПРЯЧЕМ: клиент честно пишет в консоль каждый факт шума
//     (сколько байт, какой бюджет, когда перестал) — «API Mask» не тайная
//     функция, а открытая опция манифеста;
//   - БЮДЖЕТ: max_bytes_per_day из манифеста, шум считается в счётчике
//     трафика телефона наравне с пользовательскими данными (лимит — король);
//   - БЕЗ ЗАВИСИМОСТЕЙ: pure stdlib, без чужих «генераторов трафика»
//     (решение зафиксировано в modules/README.md: готовых MIT-библиотек
//     маскировки под API-профиль нет, тянуть мок-серверы ради этого —
//     зависимостный кошмар, которого канон не допускает).
//
// Совместимость (анти-фреймворк, ноль поломок старых версий):
//   - кадр NOISE (0x26) — новый тип; сервер отвечает ТОЛЬКО на полученный
//     NOISE, старые клиенты его никогда не увидят;
//   - клиент шлёт NOISE только если сервер в READY заявил
//     features:["apimask"] — старые серверы поля не присылают, клиент молчит.
package apimasq

import (
	"encoding/json"
	"math/rand"
	"time"
)

// Feature — маркер возможности в READY.features (S→C).
const Feature = "apimask"

// Лимиты payload'ов: NOISE — контрольный кадр (≤4096), рабочие размеры
// держим заметно меньше, чтобы записи TLS выглядели как обычные API-вызовы.
const (
	MinRequestSize  = 120
	MaxRequestSize  = 700
	MinResponseSize = 160
	MaxResponseSize = 1400
	MaxPayloadSize  = 4096
)

// Config — параметры модуля (источник: modules.json → camouflage).
type Config struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Ver            string `json:"ver,omitempty"`
	Enabled        bool   `json:"enabled"`
	MinIntervalSec int    `json:"min_interval_sec,omitempty"`
	MaxIntervalSec int    `json:"max_interval_sec,omitempty"`
	MaxBytesPerDay int    `json:"max_bytes_per_day,omitempty"`
}

// DefaultConfig — встроенные значения (если манифест не задаёт секцию).
func DefaultConfig() Config {
	return Config{
		ID:             "apimask",
		Name:           "API Mask",
		Ver:            "1",
		Enabled:        false,
		MinIntervalSec: 300,
		MaxIntervalSec: 900,
		MaxBytesPerDay: 256 * 1024,
	}
}

// Clamp нормализует мусорные значения манифеста к дефолтам (канон:
// мусор никогда не ломает стек; нули → дефолты; интервалы в разумных
// пределах; бюджет — от 16 КБ до 1 МБ в сутки).
func (c Config) Clamp() Config {
	d := DefaultConfig()
	if c.MinIntervalSec <= 0 || c.MinIntervalSec > 3600 {
		c.MinIntervalSec = d.MinIntervalSec
	}
	if c.MaxIntervalSec < c.MinIntervalSec || c.MaxIntervalSec > 6*3600 {
		c.MaxIntervalSec = d.MaxIntervalSec
	}
	if c.MinIntervalSec > c.MaxIntervalSec {
		c.MinIntervalSec = c.MaxIntervalSec
	}
	if c.MaxBytesPerDay <= 0 || c.MaxBytesPerDay > 1024*1024 {
		c.MaxBytesPerDay = d.MaxBytesPerDay
	}
	return c
}

// Interval возвращает следующий интервал до шума: [min;max] с равномерным
// джиттером (секунды → длительность).
func (c Config) Interval(rnd *rand.Rand) time.Duration {
	lo, hi := c.MinIntervalSec, c.MaxIntervalSec
	if hi < lo {
		lo, hi = hi, lo
	}
	span := hi - lo + 1
	return time.Duration(lo+rnd.Intn(span)) * time.Second
}

// Valid проверяет входящий NOISE-payload: это JSON-объект в разумных
// пределах. Мусор игнорируется (сессию не рвём — шум декоративный).
func Valid(payload []byte) bool {
	if len(payload) < 2 || len(payload) > MaxPayloadSize {
		return false
	}
	if !json.Valid(payload) {
		return false
	}
	var obj map[string]json.RawMessage
	return json.Unmarshal(payload, &obj) == nil && obj != nil
}

// ---- генераторы тел ----

// версии/имена «бизнес-приложения», под которое маскируется обмен
var (
	appNames    = []string{"com.acme.workspace", "com.acme.suite", "com.acme.fieldops"}
	appVersions = []string{"3.4.1", "3.4.2", "3.5.0"}
)

// Request строит тело API-запроса (C→S): ротация форм
// (телеметрия / синхронизация конфига / отложенные события) + случайные
// идентификаторы и счётчики; размер держится в [MinRequestSize;MaxRequestSize].
func Request(rnd *rand.Rand, now time.Time) []byte {
	kind := rnd.Intn(3)
	body := map[string]any{
		"app": appNames[rnd.Intn(len(appNames))],
		"v":   appVersions[rnd.Intn(len(appVersions))],
		"did": hexID(rnd, 8+rnd.Intn(8)),
		"ts":  now.UnixMilli(),
	}
	target := MinRequestSize + rnd.Intn(MaxRequestSize-MinRequestSize+1)
	body["kind"] = []string{"telemetry.batch", "config.sync", "queue.flush"}[kind]
	switch kind {
	case 0: // телеметрия: батч событий
		fillEvents(rnd, body, "events", target)
	case 1: // синхронизация конфига
		body["cursor"] = hexID(rnd, 6+rnd.Intn(6))
		fillFlags(rnd, body, "flags", target)
	default: // отложенная очередь
		fillEvents(rnd, body, "items", target)
		body["ack"] = rnd.Intn(100000)
	}
	return marshal(body)
}

// Response строит тело API-ответа (S→C): {"code":200,...} со случайным
// payload'ом в [MinResponseSize;MaxResponseSize].
func Response(rnd *rand.Rand, now time.Time) []byte {
	body := map[string]any{
		"code": 200,
		"ts":   now.UnixMilli(),
		"sv":   appVersions[rnd.Intn(len(appVersions))],
	}
	target := MinResponseSize + rnd.Intn(MaxResponseSize-MinResponseSize+1)
	if rnd.Intn(2) == 0 {
		body["cursor"] = hexID(rnd, 8+rnd.Intn(8))
		fillEvents(rnd, body, "items", target)
	} else {
		body["status"] = "ok"
		fillFlags(rnd, body, "settings", target)
	}
	return marshal(body)
}

// fillEvents добавляет массив «событий» до достижения целевого размера.
// Массив кладётся в body КАЖДУЮ итерацию — иначе marshalLen его не видит.
func fillEvents(rnd *rand.Rand, body map[string]any, key string, target int) []map[string]any {
	events := make([]map[string]any, 0, 8)
	for {
		events = append(events, map[string]any{
			"t":   []string{"sync", "beat", "metrics", "cache"}[rnd.Intn(4)],
			"n":   rnd.Intn(10000),
			"ms":  20 + rnd.Intn(900),
			"id":  hexID(rnd, 6+rnd.Intn(6)),
			"seq": len(events) + 1,
		})
		body[key] = events
		if marshalLen(body) >= target || len(events) >= 64 {
			break
		}
	}
	return events
}

// fillFlags добавляет карту «фичей/настроек» до целевого размера.
func fillFlags(rnd *rand.Rand, body map[string]any, key string, target int) map[string]any {
	flags := map[string]any{}
	for {
		key2 := "opt" + itoa(rnd.Intn(1000))
		flags[key2] = []any{rnd.Intn(2) == 1, rnd.Intn(5000), hexID(rnd, 5+rnd.Intn(5))}[rnd.Intn(3)]
		body[key] = flags
		if marshalLen(body) >= target || len(flags) >= 64 {
			break
		}
	}
	return flags
}

func marshalLen(body map[string]any) int { return len(marshal(body)) }

func marshal(body map[string]any) []byte {
	b, err := json.Marshal(body)
	if err != nil {
		return []byte(`{"code":200}`)
	}
	return b
}

func hexID(rnd *rand.Rand, n int) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, n*2)
	for i := range out {
		out[i] = hexChars[rnd.Intn(len(hexChars))]
	}
	return string(out)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
