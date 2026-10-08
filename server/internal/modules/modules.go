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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

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
	Policy    Policy          `json:"policy,omitempty"`
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
type Status struct {
	Enabled     bool     `json:"enabled"`
	Auto        bool     `json:"auto"`
	URL         string   `json:"url,omitempty"` // публичный raw-URL, секретов нет
	Version     string   `json:"version,omitempty"`
	Source      string   `json:"source,omitempty"` // builtin|cache|remote
	Protocols   []string `json:"protocols,omitempty"`
	LastCheck   string   `json:"last_check,omitempty"`
	LastCheckOK bool     `json:"last_check_ok"`
	LastError   string   `json:"last_error,omitempty"`
}

// Syncer тянет/валидирует/применяет манифест.
type Syncer struct {
	cfg      ModulesConfig
	log      *slog.Logger
	stateDir string
	client   *http.Client

	mu          sync.Mutex
	active      *Manifest
	source      string
	bodyHash    string
	lastCheck   time.Time
	lastCheckOK bool
	lastErr     string
}

// ModulesConfig — срез конфига (без тащить весь *config.Config в тесты).
type ModulesConfig struct {
	URL        string
	Auto       bool
	CheckHours int
}

func NewSyncer(cfg ModulesConfig, log *slog.Logger, stateDir string) *Syncer {
	if cfg.URL == "" {
		cfg.URL = DefaultURL
	}
	if cfg.CheckHours <= 0 {
		cfg.CheckHours = 24
	}
	return &Syncer{
		cfg:      cfg,
		log:      log,
		stateDir: stateDir,
		client:   &http.Client{Timeout: 10 * time.Second},
		source:   "builtin",
	}
}

// Run — фоновый цикл: первый чек сразу (стартап-обязанность), дальше по расписанию.
func (s *Syncer) Run(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("modules syncer panic recovered", "panic", r)
		}
	}()
	s.Check(ctx)
	// джиттер ±10% — не синхронизировать флоты серверов в одну секунду
	interval := time.Duration(s.cfg.CheckHours) * time.Hour
	jitter := interval / 10
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Check(ctx)
			if jitter > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(randIntn(int(jitter)))):
				}
			}
		}
	}
}

// Check — один цикл «скачать → сравнить по версии И хешу → применить».
func (s *Syncer) Check(ctx context.Context) {
	defer s.recoverCheck()
	body, err := s.fetch(ctx)
	s.mu.Lock()
	s.lastCheck = time.Now()
	s.mu.Unlock()
	if err != nil {
		s.mu.Lock()
		s.lastCheckOK = false
		s.lastErr = err.Error()
		s.mu.Unlock()
		s.log.Warn("modules: check failed", "err", err)
		return
	}
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		s.fail(fmt.Sprintf("манифест не разобран: %v", err))
		return
	}
	if err := m.Validate(); err != nil {
		s.fail(err.Error())
		return
	}
	s.mu.Lock()
	sameVersion := s.active != nil && s.active.Version == m.Version
	sameHash := s.bodyHash == hash
	s.mu.Unlock()
	if s.active != nil && sameVersion && sameHash {
		// ничего не изменилось — перекачивать и применять не надо (канон)
		s.mu.Lock()
		s.lastCheckOK = true
		s.lastErr = ""
		s.mu.Unlock()
		s.log.Info("modules: manifest unchanged", "version", m.Version)
		return
	}
	s.mu.Lock()
	oldVersion := ""
	if s.active != nil {
		oldVersion = s.active.Version
	}
	s.mu.Unlock()
	if oldVersion != "" && !VersionNewer(m.Version, oldVersion) && !sameHash {
		// вниз не откатываемся из-за гонки CDN; только вверх или новый хеш той же версии
		s.log.Info("modules: remote not newer — keep current", "remote", m.Version, "current", oldVersion)
		s.mu.Lock()
		s.lastCheckOK = true
		s.mu.Unlock()
		return
	}
	// применяем: реестр протоколов + модуль камуфляжа на горячую
	rrp.SetRegistry(m.ProtocolRegistry(), m.Version)
	rrp.SetCamouflage(m.CamouflageConfig())
	s.mu.Lock()
	s.active = &m
	s.source = "remote"
	s.bodyHash = hash
	s.lastCheckOK = true
	s.lastErr = ""
	s.mu.Unlock()
	if err := s.persist(body); err != nil {
		s.log.Warn("modules: persist failed", "err", err)
	}
	s.log.Info("modules: manifest applied", "version", m.Version, "protocols", m.EnabledProtocolIDs())
}

func (s *Syncer) recoverCheck() {
	if r := recover(); r != nil {
		s.fail(fmt.Sprintf("panic: %v", r))
	}
}

func (s *Syncer) fail(msg string) {
	s.mu.Lock()
	s.lastCheckOK = false
	s.lastErr = msg
	s.mu.Unlock()
	s.log.Warn("modules: manifest rejected", "err", msg)
}

func (s *Syncer) fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// манифест маленький: жёсткий потолок против memory-bomb
	return io.ReadAll(io.LimitReader(resp.Body, 512*1024))
}

func (s *Syncer) persist(body []byte) error {
	if s.stateDir == "" {
		return nil
	}
	path := filepath.Join(s.stateDir, "modules.json")
	if err := os.WriteFile(path+".tmp", body, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// Cached — при старте: прочитать сохранённый манифест (если валиден).
func (s *Syncer) Cached() *Manifest {
	if s.stateDir == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(s.stateDir, "modules.json"))
	if err != nil {
		return nil
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil || m.Validate() != nil {
		// битый кеш не применяем
		return nil
	}
	sum := sha256.Sum256(b)
	s.mu.Lock()
	s.active = &m
	s.source = "cache"
	s.bodyHash = hex.EncodeToString(sum[:])
	s.mu.Unlock()
	return &m
}

// Status — снимок для /modules.
func (s *Syncer) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{
		Enabled:     true,
		Auto:        s.cfg.Auto,
		URL:         s.cfg.URL,
		Source:      s.source,
		LastCheckOK: s.lastCheckOK,
		LastError:   s.lastErr,
	}
	if s.active != nil {
		st.Version = s.active.Version
		st.Protocols = s.active.EnabledProtocolIDs()
	}
	if !s.lastCheck.IsZero() {
		st.LastCheck = s.lastCheck.UTC().Format(time.RFC3339)
	}
	return st
}

// ActiveVersion — версия активного манифеста ("" — встроенный).
func (s *Syncer) ActiveVersion() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return ""
	}
	return s.active.Version
}

// LastCheckOK — последний чек прошёл?
func (s *Syncer) LastCheckOK() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastCheckOK
}

func randIntn(n int) int {
	// лёгкий джиттер без crypto/rand (не секретно)
	return int(time.Now().UnixNano() % int64(n))
}
