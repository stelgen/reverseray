package modules

import (
	"testing"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

// v0.8.1: поле ver в манифесте — публичная версия протокола для всего стека.

func TestManifestVerParsing(t *testing.T) {
	body := `{"schema":1,"version":"0.8.1","protocols":[
		{"id":"rrp1","name":"RRP/1","ver":"1","default":true},
		{"id":"mtproto2","name":"MTProto/2","ver":"2.0"},
		{"id":"future1","name":"Future/1"}]}`
	var m Manifest
	if err := unmarshalForTest(body, &m); err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("валидный манифест с ver отклонён: %v", err)
	}
	reg := m.ProtocolRegistry()
	if len(reg) != 3 {
		t.Fatalf("registry = %v", reg)
	}
	if reg[0].Ver != "1" || reg[1].Ver != "2.0" || reg[2].Ver != "" {
		t.Fatalf("ver потерян/загрязнён: %v", reg)
	}
	// будущий протокол без версии — валиден (канон «пусто»)
	if reg[2].Name != "Future/1" {
		t.Fatalf("name = %q", reg[2].Name)
	}
}

func TestManifestVerGarbageBecomesEmpty(t *testing.T) {
	body := `{"schema":1,"version":"0.8.1","protocols":[
		{"id":"rrp1","name":"RRP/1","ver":"1 \"hax\"","default":true}]}`
	var m Manifest
	if err := unmarshalForTest(body, &m); err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("мусорная ver не должна ломать манифест: %v", err)
	}
	reg := m.ProtocolRegistry()
	if reg[0].Ver != "" {
		t.Fatalf("мусорная ver прошла: %q", reg[0].Ver)
	}
}

func TestRegistryAppliesVer(t *testing.T) {
	defer func() {
		rrp.SetRegistry([]rrp.Protocol{rrp.ProtocolRRP1, rrp.ProtocolMTProto2}, "")
	}()
	body := `{"schema":1,"version":"0.8.1","protocols":[
		{"id":"rrp1","name":"RRP/1","ver":"1","default":true},
		{"id":"mtproto2","name":"MTProto/2","ver":"2.0"}]}`
	var m Manifest
	if err := unmarshalForTest(body, &m); err != nil {
		t.Fatal(err)
	}
	if !rrp.SetRegistry(m.ProtocolRegistry(), m.Version) {
		t.Fatal("SetRegistry вернул false")
	}
	if rrp.Ver("mtproto2") != "2.0" || rrp.Label("mtproto2") != "MTProto/2" {
		t.Fatalf("версия/метка не применились: %q/%q", rrp.Label("mtproto2"), rrp.Ver("mtproto2"))
	}
}
