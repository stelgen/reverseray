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
	// v0.9.5 канон: «Константы защиты» живут в APK и /status — в дашборде их
	// нет (карточка убрана по решению владельца); дашборд = RT-график + клиенты.
	if strings.Contains(html, "Константы защиты") {
		t.Fatal("/ui не должен рендерить «Константы защиты» (v0.9.5)")
	}
	for _, need := range []string{"Трафик через туннель", ">Устройства<", ">Туннели<", "Журнал событий", "<svg", "relay_in"} {
		if !strings.Contains(html, need) {
			t.Fatal("/ui без элемента дашборда 2026: " + need)
		}
	}
	if strings.Contains(html, "только чтение") {
		t.Fatal("/ui содержит дурацкое уточнение «только чтение»")
	}
}

// v0.9.6: график содержит сетку (≥5 линий), легенду (EMA/пик) и подписи осей
// (скорость в человекочитаемых единицах, время -90с…0).
func TestUIGraphGridLegendAxis(t *testing.T) {
	_, cfg, _ := startTestServer(t)

	html, status := httpGet(t, "http://"+cfg.Listen.AdminTCP+"/ui")
	if status != 200 {
		t.Fatalf("/ui: %d", status)
	}
	// v1.3.0 (Grafana-стиль): сетка рисуется JS-циклом — 5 горизонтальных линий
	if !strings.Contains(html, `id="chart"`) || !strings.Contains(html, "i<=4;i++") {
		t.Fatal("график без сетки (5 линий)")
	}
	// легенда: входящий/исходящий/пик + палитра Grafana
	for _, need := range []string{"входящий", "исходящий", "пик", "#73bf69", "#5794f2"} {
		if !strings.Contains(html, need) {
			t.Fatal("легенда графика без элемента: " + need)
		}
	}
	// подписи: скорости в человекочитаемых единицах + селектор периода/юнита
	for _, need := range []string{"5 мин", "15 мин", "1 ч", "КБ/с", "МБ/с", "Мбит/с"} {
		if !strings.Contains(html, need) {
			t.Fatal("переключатели периода/юнитов без элемента: " + need)
		}
	}
	// журнал событий: ринг с уровнями и видами
	for _, need := range []string{"/ui/logs", "все", "предупреждения"} {
		if !strings.Contains(html, need) {
			t.Fatal("журнал событий без элемента: " + need)
		}
	}
}

// v1.8.8: канон «пустое поле не рендерится» теперь проверяется на JSON
// /status: сессия без UDP/DNS/стримов/RTT не содержит нулевых ключей
// (не «0», а отсутствие ключа — тот же инвариант, но на честных данных).
func TestUIStatusEmptyFieldsNotReported(t *testing.T) {
	app, _, _ := startTestServer(t)

	sess := []map[string]any{
		{
			"session": "abcd1234efgh5678",
			"device":  "TestPhone",
			"proto":   "rrp1",
		},
	}
	app.hub.SetSnapshotForTest(sess)
	out := app.statusJSON()
	var report struct {
		Sessions []map[string]any `json:"sessions"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Sessions) != 1 {
		t.Fatalf("sessions != 1: %q", out)
	}
	for _, bad := range []string{"dns", "udp", "streams", "rtt_ms"} {
		if _, ok := report.Sessions[0][bad]; ok {
			t.Fatalf("нулевой ключ %s присутствует в /status: %q", bad, out)
		}
	}
	if report.Sessions[0]["device"] != "TestPhone" {
		t.Fatalf("device потерян: %q", out)
	}
}
