package apimasq

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"testing"
	"time"
)

// Тело запроса — валидный JSON-объект в рабочих пределах размеров.
func TestRequestShape(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	seen := map[string]int{}
	for i := 0; i < 200; i++ {
		b := Request(r, time.Now())
		if !Valid(b) {
			t.Fatalf("request %d не валиден: %s", i, b)
		}
		if len(b) > MaxPayloadSize {
			t.Fatalf("request %d длиннее лимита: %d", i, len(b))
		}
		if len(b) < MinRequestSize {
			t.Fatalf("request %d короче ожидаемого: %d", i, len(b))
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("не объект JSON: %v", err)
		}
		if kind, ok := m["kind"]; ok {
			seen[string(kind)]++
		}
	}
	if len(seen) < 2 {
		t.Fatalf("ротация форм сломана: %v", seen)
	}
}

// Тело ответа — валидный JSON-объект в рабочих пределах размеров.
func TestResponseShape(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	for i := 0; i < 200; i++ {
		b := Response(r, time.Now())
		if !Valid(b) {
			t.Fatalf("response %d не валиден: %s", i, b)
		}
		if len(b) > MaxPayloadSize {
			t.Fatalf("response %d длиннее лимита: %d", i, len(b))
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("не объект: %v", err)
		}
		if code, ok := m["code"].(float64); !ok || int(code) != 200 {
			t.Fatalf("ответ без code=200: %s", b)
		}
	}
}

// Валидатор отсекает мусор (массивы/строки/пустоту/битый JSON).
func TestValidRejectsGarbage(t *testing.T) {
	garbage := [][]byte{
		nil,
		{},
		[]byte(`[1,2,3]`),
		[]byte(`"string"`),
		[]byte(`{`),
		[]byte(`{"a":`),
		bytes.Repeat([]byte("x"), MaxPayloadSize+1),
	}
	for i, g := range garbage {
		if Valid(g) {
			t.Fatalf("мусор #%d прошёл валидацию: %q", i, g)
		}
	}
	if !Valid([]byte(`{"a":1}`)) {
		t.Fatal("валидный объект не принят")
	}
}

// Clamp сводит мусорные конфиги к дефолтам (канон «мусор не ломает стек»).
func TestConfigClamp(t *testing.T) {
	d := DefaultConfig()
	cases := []Config{
		{},
		{MinIntervalSec: -5, MaxIntervalSec: 999999, MaxBytesPerDay: -1},
		{MinIntervalSec: 900, MaxIntervalSec: 100, MaxBytesPerDay: 999999999},
	}
	for i, c := range cases {
		got := c.Clamp()
		if got.MinIntervalSec <= 0 || got.MaxIntervalSec < got.MinIntervalSec {
			t.Fatalf("case %d: кривой интервал %+v", i, got)
		}
		if got.MaxBytesPerDay <= 0 || got.MaxBytesPerDay > 1024*1024 {
			t.Fatalf("case %d: кривой бюджет %+v", i, got)
		}
	}
	good := Config{MinIntervalSec: 10, MaxIntervalSec: 20, MaxBytesPerDay: 65536}.Clamp()
	if good.MinIntervalSec != 10 || good.MaxIntervalSec != 20 || good.MaxBytesPerDay != 65536 {
		t.Fatalf("валидный конфиг перекручен: %+v", good)
	}
	if d.Enabled {
		t.Fatal("по умолчанию камуфляж выключен (манифест решает)")
	}
}

// Interval держится в заданном коридоре.
func TestIntervalBounds(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	c := Config{MinIntervalSec: 300, MaxIntervalSec: 900}.Clamp()
	for i := 0; i < 500; i++ {
		d := c.Interval(r)
		if d < 300*time.Second || d > 900*time.Second {
			t.Fatalf("интервал вне коридора: %v", d)
		}
	}
}
