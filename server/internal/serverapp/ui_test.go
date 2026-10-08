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
