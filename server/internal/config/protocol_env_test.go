package config

import (
	"os"
	"testing"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

// v0.7.4: RR_PROTOCOL — протокол по умолчанию переменной окружения/compose.
// Мусор или пустое значение НЕ должны ронять сервер — сводим к стабильному
// дефолту (пользователь: «даже мусорное значение или пустое обрабатывались
// без ошибки, просто уходить в дефолт самое стабильное»).
func TestDefaultProtocolEnvGarbage(t *testing.T) {
	cases := map[string]string{
		"":         rrp.DefaultProtocolID,
		"rrp1":     "rrp1",
		"RRP1":     "rrp1",
		"  rrp1  ": "rrp1",
		"junk://x": rrp.DefaultProtocolID,
		"trojan":   rrp.DefaultProtocolID,
		"\"rrp1\"": "rrp1",
	}
	for env, want := range cases {
		t.Setenv("RR_PROTOCOL", env)
		c, err := Load("-")
		if err != nil {
			t.Fatalf("RR_PROTOCOL=%q: Load вернул ошибку: %v", env, err)
		}
		if c.DefaultProtocol != want {
			t.Errorf("RR_PROTOCOL=%q → %q, want %q", env, c.DefaultProtocol, want)
		}
	}
	os.Unsetenv("RR_PROTOCOL")
}

func TestDefaultProtocolLongEnv(t *testing.T) {
	t.Setenv("RR_DEFAULT_PROTOCOL", "RRP1")
	c, err := Load("-")
	if err != nil {
		t.Fatal(err)
	}
	if c.DefaultProtocol != "rrp1" {
		t.Fatalf("RR_DEFAULT_PROTOCOL: %q", c.DefaultProtocol)
	}
	os.Unsetenv("RR_DEFAULT_PROTOCOL")
}
