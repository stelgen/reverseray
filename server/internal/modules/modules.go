// Package modules — ЕДИНЫЙ манифест модулей для APK и сервера (v0.8).
//
// Идея канона: APK — это «тонкий движок» (как ПО POS-терминала), а вся
// бизнес-логика/реестры/политики живут в обновляемых модулях. Сервер и
// приложение парсят ОДИН И ТОТ ЖЕ манифест (modules/modules.json) и
// оркестрируют его одинаково — поэтому клиент и сервер никогда не
// расходятся во «мнении» о поддерживаемых протоколах/правилах.
//
// Дисциплина обновления (никаких лишних скачиваний):
//   - чек раз в RR_MODULES_CHECK_HOURS (по умолчанию 24 ч);
//   - скачивание только при изменении версии ИЛИ sha256 тела;
//   - битый/мусорный манифест НЕ применяется (работаем на предыдущем
//     или встроенном реестре) — фоллбек всегда в стабильный rrp1.
package modules

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

// DefaultURL — источник манифеста по умолчанию (ветка main репозитория).
const DefaultURL = "https://raw.githubusercontent.com/stelgen/reverseray/main/modules/modules.json"

// Manifest — общий формат манифеста. Одинаковые поля парсит и Kotlin
// (dev.stelgen.reverseray.core.Modules) — менять синхронно.
type Manifest struct {
	Schema    int             `json:"schema"`
	Version   string          `json:"version"`
	Updated   string          `json:"updated"`
	Protocols []ProtocolEntry `json:"protocols"`
	Policy    Policy          `json:"policy"`
	// Camouflage — секция модуля камуфляжа «API Mask» (v0.8.2, id apimask).
	// Отсутствие секции = модуль выключен (nil). Один и тот же JSON парсит
	// и Kotlin (dev.stelgen.reverseray.core.Modules) — менять синхронно.
	Camouflage *CamouflageEntry `json:"camouflage,omitempty"`
}

// CamouflageEntry — запись модуля камуфляжа в манифесте (v0.8.2).
type CamouflageEntry struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Ver            string `json:"ver,omitempty"`
	Enabled        *bool  `json:"enabled,omitempty"`
	MinIntervalSec int    `json:"min_interval_sec,omitempty"`
	MaxIntervalSec int    `json:"max_interval_sec,omitempty"`
	MaxBytesPerDay int    `json:"max_bytes_per_day,omitempty"`
}

// CamouflageConfig — нормализованный конфиг камуфляжа для rrp.SetCamouflage.
// Мусорные значения сводятся к дефолтам (канон: мусор не ломает стек).
func (m *Manifest) CamouflageConfig() rrp.Camouflage {
	e := m.Camouflage
	if e == nil {
		c := rrp.DefaultCamouflage()
		c.Enabled = false
		return c
	}
	enabled := true
	if e.Enabled != nil {
		enabled = *e.Enabled
	}
	id := rrp.NormalizeID(e.ID)
	name := strings.TrimSpace(e.Name)
	return rrp.Camouflage{
		ID:             id,
		Name:           name,
		Ver:            rrp.SanitizeVer(e.Ver),
		Enabled:        enabled,
		MinIntervalSec: e.MinIntervalSec,
		MaxIntervalSec: e.MaxIntervalSec,
		MaxBytesPerDay: e.MaxBytesPerDay,
	}
}

// ProtocolEntry — запись реестра протоколов. Enabled=null → включён.
type ProtocolEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Ver — публичная версия протокола (v0.8.1: "1", "2.0"). Если публичной
	// версии нет в природе — пусто: ни GUI, ни логи ничего не показывают.
	// Мусорная версия чистится SanitizeVer → "" (не ошибка).
	Ver     string `json:"ver,omitempty"`
	Default bool   `json:"default,omitempty"`
	// Enabled: false — протокол выключен манифестом (клиент его не предложит,
	// сервер не согласует). Отсутствие поля = включён.
	Enabled *bool `json:"enabled,omitempty"`
}

// Policy — общие правила (APK и сервер применяют одинаковые дефолты).
type Policy struct {
	// ProbeTarget — цель валидации PROBE (APK; сервер клампит таймаут).
	ProbeTarget string `json:"probe_default_target,omitempty"`
	// DnsProbes — имена для «кто реально резолвит» (APK, DnsProbe).
	DnsProbes []string `json:"dns_probe_names,omitempty"`
}

// EnabledProtocolIDs — id включённых протоколов.
func (m *Manifest) EnabledProtocolIDs() []string {
	out := make([]string, 0, len(m.Protocols))
	for _, p := range m.Protocols {
		if p.Enabled != nil && !*p.Enabled {
			continue
		}
		if p.ID != "" {
			out = append(out, rrp.NormalizeID(p.ID))
		}
	}
	return out
}

// ProtocolRegistry — включённые протоколы для rrp.SetRegistry.
func (m *Manifest) ProtocolRegistry() []rrp.Protocol {
	out := make([]rrp.Protocol, 0, len(m.Protocols))
	for _, p := range m.Protocols {
		if p.Enabled != nil && !*p.Enabled {
			continue
		}
		id := rrp.NormalizeID(p.ID)
		if id == "" {
			continue
		}
		out = append(out, rrp.Protocol{ID: id, Name: p.Name, Ver: rrp.SanitizeVer(p.Ver), Default: p.Default})
	}
	return out
}

// Validate — мусорный манифест НЕ применяется никогда (канон: фоллбек).
func (m *Manifest) Validate() error {
	if m.Schema != 1 {
		return fmt.Errorf("modules: schema %d не поддерживается (ожидается 1)", m.Schema)
	}
	if !validSemVer(m.Version) {
		return fmt.Errorf("modules: версия %q не семвер", m.Version)
	}
	if len(m.Protocols) == 0 {
		return errors.New("modules: пустой реестр протоколов")
	}
	seen := map[string]bool{}
	hasRRP := false
	for _, p := range m.Protocols {
		id := rrp.NormalizeID(p.ID)
		if id == "" {
			return fmt.Errorf("modules: протокол %q — мусорный id", p.ID)
		}
		if seen[id] {
			return fmt.Errorf("modules: дубликат протокола %q", id)
		}
		seen[id] = true
		if id == rrp.DefaultProtocolID {
			hasRRP = true
		}
	}
	if !hasRRP {
		return errors.New("modules: реестр без rrp1 — запрещено (rrp1 = фундамент)")
	}
	if m.Policy.ProbeTarget != "" {
		if _, _, err := splitHostPort(m.Policy.ProbeTarget); err != nil {
			return fmt.Errorf("modules: policy.probe_default_target %q: %w", m.Policy.ProbeTarget, err)
		}
	}
	// camouflage (v0.8.2): секция опциональна; если есть — id обязан быть
	// валидным токеном модуля, битый id = битый манифест (не применяется).
	if m.Camouflage != nil {
		id := rrp.NormalizeID(m.Camouflage.ID)
		if id == "" {
			return fmt.Errorf("modules: camouflage %q — мусорный id", m.Camouflage.ID)
		}
	}
	return nil
}

func splitHostPort(s string) (string, string, error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", errors.New("нет порта")
	}
	host, port := s[:i], s[i+1:]
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || host == "" {
		return "", "", errors.New("плохой host:port")
	}
	return host, port, nil
}

// validSemVer — «X.Y.Z» (без прелюдий; prerelease не нужен в манифесте).
func validSemVer(v string) bool {
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	if len(parts) < 2 || len(parts) > 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false
			}
		}
	}
	return true
}

// VersionNewer: a новее b? Числовые сегменты слева направо (как в APK SemVer).
func VersionNewer(a, b string) bool {
	pa := segments(a)
	pb := segments(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, y := 0, 0
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

func segments(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			n = 0
		}
		out = append(out, n)
	}
	return out
}

// Status — для /modules (admin, только чтение, без приватных деталей).
