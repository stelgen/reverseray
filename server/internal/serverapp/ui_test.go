package serverapp

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// v0.7.4: /status и /ui — данные для веб-морды в LAN.
func TestStatusAndUIEndpoints(t *testing.T) {
	app, cfg, _ := startTestServer(t)
	base := "http://" + cfg.Listen.AdminTCP

	resp, err := http.Get(base + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status code = %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	var s StatusReport
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("bad json: %v\n%s", err, b)
	}
	if !s.OK || s.Version == "" || s.DefaultProto == "" || len(s.Protocols) == 0 {
		t.Fatalf("неполный /status: %+v", s)
	}

	resp2, err := http.Get(base + "/ui")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	ui, _ := io.ReadAll(resp2.Body)
	if resp2.Header.Get("Content-Type") == "" || !strings.Contains(string(ui), "ReverseRay") {
		t.Fatalf("/ui не отдал HTML: %d %q", resp2.StatusCode, ui[:min(80, len(ui))])
	}
	_ = app
}

// v0.9.1: /status несёт «О сервере» и «Константы защиты» — паритет фактов с APK;
// /ui рендерит секцию и не содержит дурацких уточнений.
func TestStatusServerFactsAndUI(t *testing.T) {
	_, cfg, _ := startTestServer(t)

	body, status := httpGet(t, "http://"+cfg.Listen.AdminTCP+"/status")
	if status != 200 {
		t.Fatalf("status: %d", status)
	}
	var rep StatusReport
	if err := json.Unmarshal([]byte(body), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.GoVersion == "" || rep.GOOS == "" || rep.GOARCH == "" {
		t.Fatalf("go facts пусты: %q %q %q", rep.GoVersion, rep.GOOS, rep.GOARCH)
	}
	if rep.UptimeSec < 0 || rep.MemSysMB <= 0 {
		t.Fatalf("uptime/mem: %d %f", rep.UptimeSec, rep.MemSysMB)
	}
	if len(rep.Facts) < 5 {
		t.Fatalf("фактов защиты мало: %d", len(rep.Facts))
	}
	found := false
	for _, f := range rep.Facts {
		if strings.Contains(f, "SPKI CA") {
			found = true
		}
	}
	if !found {
		t.Fatal("факт про пин CA отсутствует")
	}

	html, _ := httpGet(t, "http://"+cfg.Listen.AdminTCP+"/ui")
	if !strings.Contains(html, "Константы защиты") {
		t.Fatal("/ui без секции Константы защиты")
	}
	if strings.Contains(html, "только чтение") {
		t.Fatal("/ui содержит дурацкое уточнение «только чтение»")
	}
}
