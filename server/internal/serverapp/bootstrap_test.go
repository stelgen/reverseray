package serverapp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stelgen/reverseray/server/internal/config"
	"io"
	"log/slog"
)

func newDiscardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// minimalCfg — конфигурация для тестов bootstrap: реальные пути в tempdir,
// листенеры не запускаются (New() не стартует сервер).
func minimalCfg(t *testing.T, dir, tokensPath string) *config.Config {
	t.Helper()
	c := config.Default()
	c.StateDir = dir
	c.TokensFile = tokensPath
	return c
}

// Первый запуск без tokens.json: сервер сам создаёт устройство phone-1.
func TestBootstrapCreatesDefaultDevice(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "tokens.json") // намеренно не создаём

	app, err := New(minimalCfg(t, dir, cfgPath), newDiscardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = app

	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("bootstrap did not create tokens.json: %v", err)
	}
	var doc struct {
		Devices map[string]string `json:"devices"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("invalid tokens.json: %v", err)
	}
	if doc.Devices["phone-1"] == "" {
		t.Fatalf("default device phone-1 missing: %v", doc.Devices)
	}
	if len(doc.Devices["phone-1"]) < 40 {
		t.Fatalf("token hash too short: %q", doc.Devices["phone-1"])
	}
}

// Существующий tokens.json bootstrap не трогает.
func TestBootstrapKeepsExistingTokens(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "tokens.json")
	h := sha256.Sum256([]byte("test"))
	if err := os.WriteFile(cfgPath, []byte(`{"devices":{"my-custom":"`+hex.EncodeToString(h[:])+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := New(minimalCfg(t, dir, cfgPath), newDiscardLogger()); err != nil {
		t.Fatalf("New: %v", err)
	}
	b, _ := os.ReadFile(cfgPath)
	var doc struct {
		Devices map[string]string `json:"devices"`
	}
	_ = json.Unmarshal(b, &doc)
	if doc.Devices["my-custom"] != hex.EncodeToString(h[:]) {
		t.Fatalf("existing tokens must be preserved: %v", doc.Devices)
	}
	if _, ok := doc.Devices["phone-1"]; ok {
		t.Fatal("bootstrap must not add phone-1 when tokens.json exists")
	}
}
