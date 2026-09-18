package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultsAndValidate(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.TokensFile != c.StateDir+"/tokens.json" {
		t.Fatalf("tokens default: %s", c.TokensFile)
	}
}

func TestLoadFileAndEnv(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	os.WriteFile(p, []byte(`{"listen":{"mixed":":2080"},"auth":{"username":"u","password":"p"},"allowlist":["192.168.1.0/24"]}`), 0o600)
	t.Setenv("RR_LISTEN_TUNNELS", ":9443")
	t.Setenv("RR_LIMITS_MAX_STREAMS", "32")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen.Mixed != ":2080" || c.Listen.Tunnels != ":9443" {
		t.Fatalf("file+env merge failed: %+v", c.Listen)
	}
	if c.Limits.MaxStreams != 32 {
		t.Fatalf("env limit: %d", c.Limits.MaxStreams)
	}
	if c.Auth.Username != "u" || c.Auth.Password != "p" {
		t.Fatal("auth from file lost")
	}
}

func TestValidateErrors(t *testing.T) {
	c := Default()
	c.Listen.Tunnels = ""
	c.Listen.Mixed = ""
	if err := c.Validate(); err == nil {
		t.Fatal("empty listeners must fail")
	}
	c = Default()
	c.Limits.MaxStreams = 0
	if err := c.Validate(); err == nil {
		t.Fatal("max_streams=0 must fail")
	}
}

func TestLoadPasswordFile(t *testing.T) {
	dir := t.TempDir()
	pf := filepath.Join(dir, "pass")
	os.WriteFile(pf, []byte("s3cret\n"), 0o600)
	c := Default()
	c.Auth.PasswordFile = pf
	got, err := c.LoadPassword()
	if err != nil || got != "s3cret" {
		t.Fatalf("password file: %q %v", got, err)
	}
}
