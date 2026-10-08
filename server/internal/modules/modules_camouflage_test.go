package modules

import (
	"encoding/json"
	"testing"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

// Секция camouflage (v0.8.2) парсится и нормализуется как на сервере,
// так и в APK (один и тот же modules.json).
func TestCamouflageParse(t *testing.T) {
	body := `{
	  "schema": 1, "version": "0.8.2",
	  "protocols": [{"id":"rrp1","name":"RRP/1","ver":"1","default":true}],
	  "camouflage": {"id":"apimask","name":"API Mask","ver":"1","enabled":true,
	                 "min_interval_sec":120,"max_interval_sec":600,"max_bytes_per_day":65536}
	}`
	var m Manifest
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("валидный манифест отвергнут: %v", err)
	}
	c := m.CamouflageConfig()
	if !c.Enabled || c.ID != "apimask" || c.Name != "API Mask" || c.Ver != "1" {
		t.Fatalf("кривой конфиг: %+v", c)
	}
	if c.MinIntervalSec != 120 || c.MaxIntervalSec != 600 || c.MaxBytesPerDay != 65536 {
		t.Fatalf("потеряны параметры: %+v", c)
	}
}

// Секции нет → модуль выключен (решение за манифестом).
func TestCamouflageAbsent(t *testing.T) {
	body := `{"schema":1,"version":"0.8.2","protocols":[{"id":"rrp1","name":"RRP/1"}]}`
	var m Manifest
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	c := m.CamouflageConfig()
	if c.Enabled {
		t.Fatal("без секции камуфляж обязан быть выключен")
	}
}

// Мусорный id = битый манифест (не применяется никогда).
func TestCamouflageGarbageIDRejected(t *testing.T) {
	body := `{"schema":1,"version":"0.8.2","protocols":[{"id":"rrp1"}],
	          "camouflage":{"id":"EVIL ID"}}`
	var m Manifest
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err == nil {
		t.Fatal("мусорный id camouflage не отвергнут")
	}
}

// Мусорные числа сводятся к дефолтам (канон: мусор не ломает стек).
func TestCamouflageClamp(t *testing.T) {
	off := false
	m := Manifest{Camouflage: &CamouflageEntry{
		ID: "apimask", Enabled: &off, MinIntervalSec: -5, MaxIntervalSec: 999999, MaxBytesPerDay: 0,
	}}
	// нормализация происходит в rrp.SetCamouflage — проверяем через rrp
	rrp.SetCamouflage(m.CamouflageConfig())
	got := rrp.CamouflageConfig()
	if got.MinIntervalSec <= 0 || got.MaxIntervalSec < got.MinIntervalSec {
		t.Fatalf("кривой интервал после нормализации: %+v", got)
	}
	if got.MaxBytesPerDay <= 0 || got.MaxBytesPerDay > 1024*1024 {
		t.Fatalf("кривой бюджет после нормализации: %+v", got)
	}
	if rrp.CamouflageFeature() != nil {
		t.Fatal("выключенный камуфляж не должен выдавать feature")
	}
	// включаем: feature появляется и совпадает с апишным маркером
	enabled := true
	m.Camouflage.Enabled = &enabled
	rrp.SetCamouflage(m.CamouflageConfig())
	if got := rrp.CamouflageFeature(); len(got) != 1 || got[0] != "apimask" {
		t.Fatalf("feature не совпадает: %v", got)
	}
	if rrp.CamouflageLabel() == "" {
		t.Fatal("метка с версией не показывается")
	}
}
