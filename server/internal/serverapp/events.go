package serverapp

import (
	"strings"
	"sync"
	"time"
)

// EventLog — v1.3.0: кольцевой журнал ключевых событий для веб-морды
// (Grafana-стиль). Питается от: туннели (attach/detach), смена протокола,
// обмен ключами, авторизация (классифицированная: устройство против сканера),
// диал-ошибки, буфер трафика (паркинг/резюме), hardening, модули.
// Redaction-канон: хосты назначения и токены никогда не попадают в события.
type Event struct {
	At     time.Time `json:"at"`
	Level  string    `json:"level"` // канон LogKind APK: TRACE|DEBUG|INFO|NOTICE|OK|WARN|ERROR|PANIC
	Kind   string    `json:"kind"`  // tunnel|proto|keys|auth|park|dial|hardening|modules|inbound
	Device string    `json:"device,omitempty"`
	Msg    string    `json:"msg"`
}

// Уровни журнала — 1:1 канон APK (android/.../core/LogStore.kt, v1.8.4).
// severity монотонно растёт; любые новые события обязаны использовать эти
// константы (легаси "info"/"warn" нормализуются на входе Add/AddDev).
const (
	LevelTrace  = "TRACE"
	LevelDebug  = "DEBUG"
	LevelInfo   = "INFO"
	LevelNotice = "NOTICE"
	LevelOK     = "OK"
	LevelWarn   = "WARN"
	LevelError  = "ERROR"
	LevelPanic  = "PANIC"
)

// canonLevel приводит уровень к канону LogKind APK. Легаси-алиасы
// ("info", "warn", "error", "ok", "notice", "debug", "trace", "panic")
// маппятся 1:1; неизвестное → INFO (не теряем событие).
func canonLevel(level string) string {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case LevelTrace, LevelDebug, LevelInfo, LevelNotice, LevelOK, LevelWarn, LevelError, LevelPanic:
		return strings.ToUpper(strings.TrimSpace(level))
	default:
		return LevelInfo
	}
}

type EventLog struct {
	mu   sync.Mutex
	ring []Event
	next int
	size int
	dedp map[string]time.Time // дедуп спам-событий (kind|msg) — окно 3 c
}

func NewEventLog(capacity int) *EventLog {
	if capacity < 64 {
		capacity = 256
	}
	return &EventLog{ring: make([]Event, capacity), dedp: make(map[string]time.Time)}
}

// Add добавляет событие. Повтор той же пары kind+msg в течение 3 с глушится —
// сканерный шум и dial-ошибки не должны затоплять журнал.
func (l *EventLog) Add(level, kind, msg string) {
	l.AddDev(level, kind, msg, "")
}

func (l *EventLog) AddDev(level, kind, msg, device string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	level = canonLevel(level)
	now := time.Now()
	key := kind + "|" + msg
	if last, ok := l.dedp[key]; ok && now.Sub(last) < 3*time.Second {
		return
	}
	if len(l.dedp) > 512 {
		l.dedp = make(map[string]time.Time) // защита от роста карты
	}
	l.dedp[key] = now
	l.ring[l.next] = Event{At: now, Level: level, Kind: kind, Device: device, Msg: msg}
	l.next = (l.next + 1) % len(l.ring)
	if l.size < len(l.ring) {
		l.size++
	}
}

// Snapshot возвращает последние n событий (новые вперёд).
func (l *EventLog) Snapshot(n int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > l.size {
		n = l.size
	}
	out := make([]Event, 0, n)
	for i := 0; i < n; i++ {
		idx := (l.next - 1 - i + len(l.ring)) % len(l.ring)
		out = append(out, l.ring[idx])
	}
	return out
}

// Counts — сводка по уровням (для KPI морды).
func (l *EventLog) Counts() (info, warn, errs int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := 0; i < l.size; i++ {
		switch canonLevel(l.ring[i].Level) {
		case LevelWarn:
			warn++
		case LevelError, LevelPanic:
			errs++
		default:
			info++
		}
	}
	return
}
