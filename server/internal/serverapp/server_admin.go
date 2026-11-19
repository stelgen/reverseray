// Package serverapp — зона «Admin API» (mountAdmin: /healthz, /metrics, /sessions, /tokens/reload, /devices/kick|delete). Pure move из server.go (v1.8.3).
package serverapp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// ---- admin ----

func (a *App) mountAdmin(mux *http.ServeMux) {
	a.mountUI(mux)
	mux.HandleFunc("/healthz", a.safeHandler("healthz", secureHeaders(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})))
	mux.HandleFunc("/readyz", a.safeHandler("readyz", secureHeaders(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if len(a.store.Devices()) == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"ready":false,"reason":"no tokens loaded"}`)
			return
		}
		fmt.Fprint(w, `{"ready":true}`)
	})))
	mux.HandleFunc("/metrics", a.safeHandler("metrics", secureHeaders(a.metricsHandler())))
	mux.HandleFunc("/sessions", a.safeHandler("sessions", secureHeaders(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(a.hub.Snapshot())
	})))
	mux.HandleFunc("/tokens/reload", a.safeHandler("tokens_reload", secureHeaders(func(w http.ResponseWriter, _ *http.Request) {
		if err := a.Reload(); err != nil {
			// текст ошибки ТОЛЬКО в лог — наружу без деталей (canon: ноль утечек)
			a.log.Warn("tokens reload failed", "err", err)
			http.Error(w, "reload failed", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, "reloaded")
	})))
	// v0.8: статус модулей (версия, протоколы, последний чек) — только чтение
	mux.HandleFunc("/modules", a.safeHandler("modules", secureHeaders(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if a.modSync == nil {
			fmt.Fprint(w, `{"enabled":false}`)
			return
		}
		_ = json.NewEncoder(w).Encode(a.modSync.Status())
	})))
	mux.HandleFunc("/devices/kick", a.safeHandler("devices_kick", secureHeaders(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		name := r.URL.Query().Get("device")
		if name == "" || containsAny(name, "..", "/", "\\") {
			http.Error(w, "bad device", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "kicked %d sessions", a.hub.Kick(name)) // #nosec G705: name не выводится в ответ, только валидируется
	})))
	// v1.6.1: список устройств для веб-управления (только публичные факты:
	// имя, онлайн-сессии, суммарный релей, камуфляж; НИКАКИХ хэшей/токенов).
	mux.HandleFunc("/devices", a.safeHandler("devices", secureHeaders(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		online := map[string]int{}
		totals := map[string][2]uint64{}
		protos := map[string]map[string]bool{}
		for _, sm := range a.hub.Snapshot() {
			d, _ := sm["device"].(string)
			if d == "" {
				continue
			}
			online[d]++
			t := totals[d]
			if v, ok := sm["relay_in"].(uint64); ok {
				t[0] += v
			}
			if v, ok := sm["relay_out"].(uint64); ok {
				t[1] += v
			}
			totals[d] = t
			if p, ok := sm["proto"].(string); ok && p != "" {
				if protos[d] == nil {
					protos[d] = map[string]bool{}
				}
				protos[d][p] = true
			}
		}
		type devInfo struct {
			Device    string   `json:"device"`
			Online    int      `json:"online"`
			Protocols []string `json:"protocols,omitempty"`
			RelayIn   uint64   `json:"relay_in"`
			RelayOut  uint64   `json:"relay_out"`
			CamoOff   bool     `json:"camouflage_off"`
		}
		over := a.CamouflageOverrides()
		out := make([]devInfo, 0, 8)
		for _, d := range a.store.Devices() {
			di := devInfo{Device: d, Online: online[d], CamoOff: over[d]}
			t := totals[d]
			di.RelayIn, di.RelayOut = t[0], t[1]
			for p := range protos[d] {
				di.Protocols = append(di.Protocols, p)
			}
			out = append(out, di)
		}
		_ = json.NewEncoder(w).Encode(out)
	})))
	// v1.6.1: УДАЛЕНИЕ телефона (отзыв авторизации): удаляем из tokens.json
	// (hash-only) + из памяти + глушим живые сессии. ГАРДРЕЙЛ: последнее
	// устройство удалить нельзя (сервер останется без авторизации вовсе).
	mux.HandleFunc("/devices/delete", a.safeHandler("devices_delete", secureHeaders(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		name := r.URL.Query().Get("device")
		if name == "" || containsAny(name, "..", "/", "\\") {
			http.Error(w, "bad device", http.StatusBadRequest)
			return
		}
		rest := a.store.Devices()
		found := false
		for _, d := range rest {
			if d == name {
				found = true
			}
		}
		if !found {
			http.Error(w, "no such device", http.StatusNotFound)
			return
		}
		if len(rest) <= 1 {
			http.Error(w, "refusing to delete the last device", http.StatusConflict)
			return
		}
		// перезаписываем tokens.json без устройства (0600, канон прав state-dir)
		path := a.tokensPath()
		raw, err := os.ReadFile(path)
		if err != nil {
			a.log.Warn("device delete: tokens.json unreadable", "err", err)
			http.Error(w, "tokens file unreadable", http.StatusInternalServerError)
			return
		}
		var doc struct {
			Devices map[string]string `json:"devices"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Devices) == 0 {
			a.log.Warn("device delete: tokens.json parse failed")
			http.Error(w, "tokens file parse failed", http.StatusInternalServerError)
			return
		}
		if _, ok := doc.Devices[name]; !ok {
			http.Error(w, "no such device in tokens file", http.StatusNotFound)
			return
		}
		delete(doc.Devices, name)
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			http.Error(w, "serialize failed", http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(path, append(out, '\n'), 0o600); err != nil {
			a.log.Warn("device delete: tokens.json write failed", "err", err)
			http.Error(w, "tokens file write failed", http.StatusInternalServerError)
			return
		}
		_ = a.store.RemoveDevice(name)
		a.hub.Kick(name)
		// перманентный выбор камуфляжа устройства тоже чистим
		a.setCamouflageOverride(name, true)
		a.log.Info("device deleted via web UI (auth revoked)", "devices_left", len(a.store.Devices()))
		a.ev.AddDev("warn", "devices", "телефон удалён из авторизации через веб-панель", name)
		fmt.Fprint(w, "deleted")
	})))
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// toU32 — безопасная конверсия конфиг-лимитов (gosec G115): отрицательное -> 0, >MaxUint32 -> MaxUint32.
func toU32(v int) uint32 {
	if v <= 0 {
		return 0
	}
	if uint64(v) > uint64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(v)
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
