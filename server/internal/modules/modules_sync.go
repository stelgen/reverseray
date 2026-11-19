// modules_sync.go — зона «Syncer: загрузка/валидация/кэш манифеста» — pure move из modules.go (v1.8.3, дробление по зонам; поведение не меняется).
package modules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

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
