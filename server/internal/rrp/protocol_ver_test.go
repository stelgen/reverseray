package rrp

import "testing"

// v0.8.1: версии протоколов пробрасываются по всему стеку (GUI/логи/статусы).
// Канон: имя известного протокола несёт версию; если публичной версии нет —
// пусто, нигде ничего не показываем.

func TestBuiltinProtocolsHaveVersions(t *testing.T) {
	if Label("rrp1") != "RRP/1" || Ver("rrp1") != "1" {
		t.Fatalf("rrp1: label=%q ver=%q", Label("rrp1"), Ver("rrp1"))
	}
	if Label("mtproto2") != "MTProto/2" || Ver("mtproto2") != "2.0" {
		t.Fatalf("mtproto2: label=%q ver=%q", Label("mtproto2"), Ver("mtproto2"))
	}
}

func TestLabelUnknownIDShowsIDWithoutVersion(t *testing.T) {
	// «новый протокол без версии» — метка = сам id, версия пустая
	if got := Label("будущийнет"); got != "будущийнет" {
		t.Fatalf("Label(unknown) = %q", got)
	}
	if got := Ver("будущийнет"); got != "" {
		t.Fatalf("Ver(unknown) = %q, ожидалась пусто", got)
	}
}

func TestSetRegistryKeepsVerAndSanitizesGarbage(t *testing.T) {
	defer func() {
		SetRegistry([]Protocol{ProtocolRRP1, ProtocolMTProto2}, "")
	}()
	ok := SetRegistry([]Protocol{
		{ID: "rrp1", Name: "RRP/1", Ver: "1"},
		{ID: "mtproto2", Name: "MTProto/2", Ver: "2.0"},
		{ID: "proto9", Name: "Proto/9", Ver: "9 Beta!!"},
	}, "0.8.1")
	if !ok {
		t.Fatal("SetRegistry вернул false")
	}
	if Ver("rrp1") != "1" || Ver("mtproto2") != "2.0" {
		t.Fatalf("версии потеряны: rrp1=%q mtproto2=%q", Ver("rrp1"), Ver("mtproto2"))
	}
	// мусорная версия → пусто (не ошибка): «версии нет» — показываем пусто
	if Ver("proto9") != "" {
		t.Fatalf("мусорная версия прошла: %q", Ver("proto9"))
	}
	if Label("proto9") != "Proto/9" {
		t.Fatalf("имя без версии потеряно: %q", Label("proto9"))
	}
}

func TestSanitizeVer(t *testing.T) {
	cases := map[string]string{
		"1":                 "1",
		"2.0":               "2.0",
		" 2.1 ":             "2.1",
		"1.0-b":             "1.0-b",
		"":                  "",
		"   ":               "",
		"1 2":               "", // пробел внутри → мусор
		"\"1\"":             "", // кавычки → мусор
		"v1.0":              "v1.0",
		"12345678901234567": "", // > 16 символов
	}
	for in, want := range cases {
		if got := SanitizeVer(in); got != want {
			t.Fatalf("SanitizeVer(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}

func TestLabelsAndVersMaps(t *testing.T) {
	defer func() {
		SetRegistry([]Protocol{ProtocolRRP1, ProtocolMTProto2}, "")
	}()
	SetRegistry([]Protocol{{ID: "rrp1", Name: "RRP/1", Ver: "1"}}, "0.8.1")
	l := Labels()
	if l["rrp1"] != "RRP/1" {
		t.Fatalf("Labels: %v", l)
	}
	v := Vers()
	if v["rrp1"] != "1" {
		t.Fatalf("Vers: %v", v)
	}
}
