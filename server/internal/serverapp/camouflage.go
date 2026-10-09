// camouflage.go — перманентный выбор камуфляжа КЛИЕНТОМ (v0.9.5).
//
// Кадр 0x2A (TypeCamCtl): клиент в любой момент (даже вне туннеля —
// при следующем коннекте) сообщает {"enabled":true|false}; сервер хранит
// выбор устройства в state/camouflage.json и отражает его в READY.features
// КАЖДОЙ будущей сессии: выключенный клиентом apimask сам не включается.
package serverapp

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

const camouflageFile = "camouflage.json"

// setCamouflageOverride — клиент подтвердил/выключил apimask для устройства.
func (a *App) setCamouflageOverride(device string, enabled bool) {
	a.camoMu.Lock()
	if enabled {
		delete(a.camoOff, device)
	} else {
		if a.camoOff == nil {
			a.camoOff = make(map[string]bool)
		}
		a.camoOff[device] = true
	}
	over := make(map[string]bool, len(a.camoOff))
	for k, v := range a.camoOff {
		over[k] = v
	}
	a.camoMu.Unlock()
	a.persistCamouflage(over)
	a.log.Info("camouflage choice by client (persisted)", "device", device, "enabled", enabled)
}

// featuresFor — features конкретного устройства для READY: apimask заявляется
// только если включён манифестом И не выключен клиентом перманентно.
func (a *App) featuresFor(device string) []string {
	f := rrp.CamouflageFeature()
	if len(f) == 0 {
		return nil
	}
	a.camoMu.Lock()
	defer a.camoMu.Unlock()
	if a.camoOff[device] {
		return nil
	}
	return f
}

// CamouflageOverrides — снимок выборов клиентов для /status.
func (a *App) CamouflageOverrides() map[string]bool {
	a.camoMu.Lock()
	defer a.camoMu.Unlock()
	if len(a.camoOff) == 0 {
		return nil
	}
	out := make(map[string]bool, len(a.camoOff))
	for k, v := range a.camoOff {
		out[k] = v
	}
	return out
}

func (a *App) camouflagePath() string { return filepath.Join(a.cfg.StateDir, camouflageFile) }

// loadCamouflage читает перманентные выборы при старте сервера.
func (a *App) loadCamouflage() {
	b, err := os.ReadFile(a.camouflagePath())
	if err != nil {
		return // нет файла — выборов нет (это норма)
	}
	var doc struct {
		Devices map[string]bool `json:"devices"` // устройство → выключен ли apimask
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		a.log.Warn("camouflage.json повреждён — применяются выборы по умолчанию", "err", err)
		return
	}
	a.camoMu.Lock()
	a.camoOff = make(map[string]bool, len(doc.Devices))
	for k, v := range doc.Devices {
		if v {
			a.camoOff[k] = true
		}
	}
	a.camoMu.Unlock()
}

// persistCamouflage атомарно пишет выборы (rename-паттерн, 0600).
func (a *App) persistCamouflage(over map[string]bool) {
	doc := struct {
		Schema  int             `json:"schema"`
		Devices map[string]bool `json:"devices"`
	}{Schema: 1, Devices: over}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return
	}
	tmp := a.camouflagePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		a.log.Warn("camouflage.json недоступен для записи (выбор живёт в памяти)", "err", err)
		return
	}
	if err := os.Rename(tmp, a.camouflagePath()); err != nil {
		a.log.Warn("camouflage.json rename failed", "err", err)
		_ = os.Remove(tmp)
	}
}
