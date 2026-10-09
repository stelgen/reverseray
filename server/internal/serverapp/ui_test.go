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
	for _, need := range []string{"Трафик в реальном времени", "Клиенты", "<svg", "relay_in"} {
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
	// сетка: контейнер линий + JS рисует 5 горизонтальных линий
	if !strings.Contains(html, `id="gridLines"`) || !strings.Contains(html, `id="gridLabels"`) {
		t.Fatal("график без сетки/подписей")
	}
	if !strings.Contains(html, "k<5") {
		t.Fatal("сетка графика менее 5 линий")
	}
	// легенда: rx/tx/EMA/пик
	for _, need := range []string{"Вход rx", "Выход tx", "среднее (EMA)", "пик", "var(--in)", "var(--out)"} {
		if !strings.Contains(html, need) {
			t.Fatal("легенда графика без элемента: " + need)
		}
	}
	// подписи осей: время назад и скорость с единицами
	for _, need := range []string{"-90с", "КБ/с", "МБ/с"} {
		if !strings.Contains(html, need) {
			t.Fatal("подписи осей графика без элемента: " + need)
		}
	}
	// градиентная заливка и сглаживание (Катмулл-Ром → кривые Безье)
	if !strings.Contains(html, "linearGradient") || !strings.Contains(html, "url(#gIn)") {
		t.Fatal("график без градиентной заливки")
	}
	if !strings.Contains(html, "smoothPath") || !strings.Contains(html, "' C'") {
		t.Fatal("график без сглаживания Катмулла-Рома")
	}
}

// v0.9.6: пустые поля не рендерятся — сессия без UDP/DNS/стримов/RTT не
// содержит строк с этими подписями вовсе (не «0», а отсутствие элемента).
func TestUICardsEmptyFieldsNotRendered(t *testing.T) {
	app, _, _ := startTestServer(t)

	// фикстура: сессия только с обязательными полями — всё остальное ноль/пусто
	sess := []map[string]any{
		{
			"session":  "abcd1234efgh5678",
			"device":   "TestPhone",
			"proto":    "rrp1",
			"relay_in": float64(0), "relay_out": float64(0),
			"bytes_in": float64(0), "bytes_out": float64(0),
		},
	}
	app.hub.SetSnapshotForTest(sess)
	html := app.cardsHTML()

	// пустые поля отсутствуют целиком
	for _, bad := range []string{">UDP<", ">DNS<", ">Стримы<", ">RTT<", ">В полёте<", ">↓ relay<", ">↓ телефон<"} {
		if strings.Contains(html, bad) {
			t.Fatalf("пустое поле рендерится в карточке: %s", bad)
		}
	}
	// устройство и бейдж протокола — есть
	if !strings.Contains(html, "TestPhone") || !strings.Contains(html, "badge") {
		t.Fatalf("карточка без базовых элементов: %q", html)
	}
	// сессия без данных не содержит нулевых заглушек
	if strings.Contains(html, ">0<") {
		t.Fatalf("нулевая заглушка в карточке: %q", html)
	}

	// а карточка с данными рендерит их честно
	sess[0]["dns"] = float64(7)
	sess[0]["relay_in"] = float64(2048)
	sess[0]["relay_out"] = float64(4096)
	sess[0]["udp"] = float64(3)
	sess[0]["streams"] = float64(2)
	sess[0]["rtt_ms"] = float64(42)
	sess[0]["bytes_in"] = float64(1048576)
	app.hub.SetSnapshotForTest(sess)
	html = app.cardsHTML()
	for _, need := range []string{">DNS<", ">UDP<", ">Стримы<", ">RTT<", "2.0 КБ", "4.0 КБ", "1.0 МБ"} {
		if !strings.Contains(html, need) {
			t.Fatalf("заполненное поле не отрендерилось: %s в %q", need, html)
		}
	}
}
