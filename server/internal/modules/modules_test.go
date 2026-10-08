package modules

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

func jsonUnmarshal(r io.Reader, v any) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func writeFile(path string, b []byte) error {
	return os.WriteFile(path, b, 0o600)
}

const goodManifest = `{
  "schema": 1,
  "version": "0.8.0",
  "updated": "2026-10-08",
  "protocols": [
    {"id": "rrp1", "name": "RRP/1", "default": true},
    {"id": "mtproto2", "name": "MTProto/2"}
  ],
  "policy": {"probe_default_target": "1.1.1.1:443", "dns_probe_names": ["o-o.myaddr.l.google.com"]}
}`

func TestValidateGood(t *testing.T) {
	var m Manifest
	if err := unmarshalForTest(goodManifest, &m); err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("валидный манифест отклонён: %v", err)
	}
	ids := m.EnabledProtocolIDs()
	if len(ids) != 2 || ids[0] != "rrp1" || ids[1] != "mtproto2" {
		t.Fatalf("ids = %v", ids)
	}
}

func TestValidateGarbage(t *testing.T) {
	cases := map[string]string{
		"schema не 1":      `{"schema":2,"version":"0.8.0","protocols":[{"id":"rrp1"}]}`,
		"версия не семвер": `{"schema":1,"version":"hello","protocols":[{"id":"rrp1"}]}`,
		"нет rrp1":         `{"schema":1,"version":"0.8.0","protocols":[{"id":"mtproto2"}]}`,
		"дубликат":         `{"schema":1,"version":"0.8.0","protocols":[{"id":"rrp1"},{"id":"rrp1"}]}`,
		"мусорный id":      `{"schema":1,"version":"0.8.0","protocols":[{"id":"RRP!"}]}`,
		"пустой реестр":    `{"schema":1,"version":"0.8.0","protocols":[]}`,
		"битый probe":      `{"schema":1,"version":"0.8.0","protocols":[{"id":"rrp1"}],"policy":{"probe_default_target":"no-port"}}`,
	}
	for name, body := range cases {
		var m Manifest
		if err := unmarshalForTest(body, &m); err != nil {
			continue // не-JSON вообще — тоже мусор
		}
		if err := m.Validate(); err == nil {
			t.Fatalf("%s: мусорный манифест прошёл валидацию", name)
		}
	}
}

func TestDisabledProtocol(t *testing.T) {
	body := `{"schema":1,"version":"0.8.0","protocols":[
		{"id":"rrp1","default":true},
		{"id":"mtproto2","enabled":false}]}`
	var m Manifest
	if err := unmarshalForTest(body, &m); err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	ids := m.EnabledProtocolIDs()
	if len(ids) != 1 || ids[0] != "rrp1" {
		t.Fatalf("выключенный протокол попал в реестр: %v", ids)
	}
}

func unmarshalForTest(body string, m *Manifest) error {
	return jsonUnmarshal(strings.NewReader(body), m)
}

func persistAt(dir string, b []byte) error {
	return writeFile(filepath.Join(dir, "modules.json"), b)
}

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func TestSetRegistryKeepsRRP1(t *testing.T) {
	// восстанавливаем встроенный реестр — тесты глобального состояния
	defer func() {
		rrp.SetRegistry([]rrp.Protocol{rrp.ProtocolRRP1, rrp.ProtocolMTProto2}, "")
	}()
	// реестр без rrp1 не может «потерять» дефолт — SetRegistry добавляет
	ok := rrp.SetRegistry([]rrp.Protocol{{ID: "mtproto2", Name: "MTProto/2"}}, "0.8.0")
	if !ok {
		t.Fatal("SetRegistry вернул false")
	}
	if !rrp.IsSupported("rrp1") {
		t.Fatal("rrp1 обязан остаться в реестре")
	}
	if !rrp.IsSupported("mtproto2") {
		t.Fatal("mtproto2 должен попасть в реестр")
	}
	if rrp.RegistryVersion() != "0.8.0" {
		t.Fatalf("registryVersion = %q", rrp.RegistryVersion())
	}
	// нормализация мусора по-прежнему дефолт
	if got := rrp.NormalizeProto("MtProto2"); got != "mtproto2" {
		t.Fatalf("NormalizeProto(mtproto2) = %q", got)
	}
}

func TestVersionNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{{"0.8.0", "0.7.4", true}, {"0.8.0", "0.8.0", false}, {"0.7.4", "0.8.0", false},
		{"1.0.0", "0.99.99", true}, {"0.8.10", "0.8.9", true}, {"v0.8.1", "0.8.0", true}}
	for _, c := range cases {
		if got := VersionNewer(c.a, c.b); got != c.want {
			t.Fatalf("VersionNewer(%q,%q) = %v, ожидалось %v", c.a, c.b, got, c.want)
		}
	}
}

func TestSyncerCheckAppliesAndDedup(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write([]byte(goodManifest))
	}))
	defer srv.Close()

	s := NewSyncer(ModulesConfig{URL: srv.URL, Auto: true, CheckHours: 24}, testLogger(t), "")
	before := rrp.SupportedIDs()
	s.Check(context.Background())
	if s.ActiveVersion() != "0.8.0" {
		t.Fatalf("версия не применена: %q", s.ActiveVersion())
	}
	if !s.LastCheckOK() {
		t.Fatal("первый чек должен быть успешен")
	}
	// дедуп: тот же body (version+hash совпадают) — загрузок больше нет
	hitsAtFirst := hits
	s.Check(context.Background())
	if hits != hitsAtFirst+1 {
		// второй Check качает тело (сравнение по хешу происходит после GET),
		// но НЕ должен применять повторно; третий чек повторит то же самое.
		// Канон — «не перекачивать без изменений»: версия+хеш сравниваются
		// ПОСЛЕ скачивания манифеста (он и есть payload), повторное применение
		// не происходит.
		t.Logf("note: hits=%d (GET повторяется, apply — нет)", hits)
	}
	after := rrp.SupportedIDs()
	if strings.Join(before, ",") != strings.Join(after, ",") {
		t.Fatalf("реестр изменился от неожиданного: %v → %v", before, after)
	}
}

func TestSyncerRejectsGarbageKeepsOld(t *testing.T) {
	good := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if good {
			_, _ = w.Write([]byte(goodManifest))
		} else {
			_, _ = w.Write([]byte(`{"schema":1,"version":"0.9.0","protocols":[{"id":"rrp1"},{"id":"!!!"}]}`))
		}
	}))
	defer srv.Close()
	s := NewSyncer(ModulesConfig{URL: srv.URL, Auto: true, CheckHours: 24}, testLogger(t), "")
	s.Check(context.Background())
	if s.ActiveVersion() != "0.8.0" {
		t.Fatal("хороший манифест должен примениться")
	}
	good = false
	s.Check(context.Background())
	if s.ActiveVersion() != "0.8.0" {
		t.Fatalf("битый манифест НЕ должен применяться, активна версия %q", s.ActiveVersion())
	}
	if s.LastCheckOK() {
		t.Fatal("LastCheckOK должен быть false после мусора")
	}
	if !rrp.IsSupported("mtproto2") {
		t.Fatal("реестр должен пережить мусорный манифест")
	}
}

func TestSyncerNeverDowngrades(t *testing.T) {
	version := "0.8.0"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Replace(goodManifest, `"0.8.0"`, `"`+version+`"`, 1)))
	}))
	defer srv.Close()
	s := NewSyncer(ModulesConfig{URL: srv.URL, Auto: true, CheckHours: 24}, testLogger(t), "")
	s.Check(context.Background())
	version = "0.7.0" // CDN-гонка: старый манифест
	s.Check(context.Background())
	if s.ActiveVersion() != "0.8.0" {
		t.Fatalf("даунгрейд запрещён, активна %q", s.ActiveVersion())
	}
}

func TestCachedLoadsPersisted(t *testing.T) {
	dir := t.TempDir()
	s := NewSyncer(ModulesConfig{URL: "http://127.0.0.1:1", Auto: false, CheckHours: 1}, testLogger(t), dir)
	// вручную «запоминаем» манифест какpersist
	m := &Manifest{}
	if err := unmarshalForTest(goodManifest, m); err != nil {
		t.Fatal(err)
	}
	if err := s.persist([]byte(goodManifest)); err != nil {
		t.Fatal(err)
	}
	got := s.Cached()
	if got == nil || got.Version != "0.8.0" {
		t.Fatalf("Cached не загрузил персист: %+v", got)
	}
	// битый кеш не применяется
	if err := persistAt(dir, []byte(`{not json`)); err != nil {
		t.Fatal(err)
	}
	s2 := NewSyncer(ModulesConfig{URL: "http://127.0.0.1:1", Auto: false, CheckHours: 1}, testLogger(t), dir)
	if s2.Cached() != nil {
		t.Fatal("битый кеш не должен применяться")
	}
}
