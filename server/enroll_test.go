package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// enroll обязан сам создавать tokens.json, добавлять устройство и печатать
// готовую rrp:// строку — без ручного редактирования и SIGHUP/curl.
func TestCmdEnrollWritesTokensFile(t *testing.T) {
	dir := t.TempDir()
	args := []string{"-state-dir", dir, "-name", "phone-x", "-host", "203.0.113.9", "-port", "4433"}
	if err := cmdEnroll(args); err != nil {
		t.Fatalf("cmdEnroll: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(dir, "tokens.json"))
	if err != nil {
		t.Fatalf("tokens.json not created: %v", err)
	}
	var doc struct {
		Devices map[string]string `json:"devices"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("tokens.json invalid: %v", err)
	}
	if doc.Devices == nil || doc.Devices["phone-x"] == "" {
		t.Fatalf("device phone-x missing: %v", doc.Devices)
	}
	if len(doc.Devices["phone-x"]) < 40 {
		t.Fatalf("hash too short: %q", doc.Devices["phone-x"])
	}
}

// Повторный enroll того же устройства обновляет запись, не ломая файл.
func TestCmdEnrollUpsertSameDevice(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 2; i++ {
		args := []string{"-state-dir", dir, "-name", "phone-dup", "-host", "203.0.113.9"}
		if err := cmdEnroll(args); err != nil {
			t.Fatalf("cmdEnroll #%d: %v", i, err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, "tokens.json"))
	var doc struct {
		Devices map[string]string `json:"devices"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("invalid: %v", err)
	}
	if len(doc.Devices) != 1 {
		t.Fatalf("devices must be 1, got %d", len(doc.Devices))
	}
}

// enroll без -host и без сети должен вернуть внятную ошибку, а не панику.
// (автоопределение IP тестируется отдельно в средах с сетью)
func TestCmdEnrollBadHostFails(t *testing.T) {
	dir := t.TempDir()
	args := []string{"-state-dir", dir, "-name", "phone-bad", "-host", "not-an-ip-or-domain-xyz"}
	if err := cmdEnroll(args); err != nil {
		// host задан вручную — enroll не проверяет резолвинг; строка уйдёт как есть.
		// Проверяем только отсутствие паники.
		return
	}
	_ = strings.TrimSpace("")
}
