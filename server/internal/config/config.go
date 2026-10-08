// Package config loads server configuration (JSON file + RR_* env overrides).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

// Config is the full server configuration.
type Config struct {
	// PublicHost — доменное имя/хост для конфигурационных строк (DDNS).
	// Пусто — используется автоопределённый внешний IP.
	PublicHost string `json:"public_host"`

	Listen struct {
		Tunnels   string   `json:"tunnels"`   // TLS listener for phones
		Mixed     string   `json:"mixed"`     // SOCKS5+HTTP autodetect
		Socks     string   `json:"socks"`     // optional separate socks5
		HTTP      string   `json:"http"`      // optional separate http proxy
		AdminTCP  string   `json:"admin_tcp"` // healthz/readyz/metrics/admin
		AdminUnix string   `json:"admin_unix"`
		TLSHosts  []string `json:"tls_hosts"` // SANs for the leaf cert
	} `json:"listen"`

	StateDir   string `json:"state_dir"`
	TokensFile string `json:"tokens_file"`

	Auth struct {
		Username     string `json:"username"` // inbound proxy auth (optional)
		Password     string `json:"password"`
		PasswordFile string `json:"password_file"` // overrides password
	} `json:"auth"`

	Allowlist []string `json:"allowlist"` // CIDRs for inbound; empty = any

	Log struct {
		Level  string `json:"level"`  // debug|info|warn|error
		Redact bool   `json:"redact"` // never log destination hosts (default true)
	} `json:"log"`

	// DefaultProtocol — протокол туннеля по умолчанию (RR_PROTOCOL).
	// Любое мусорное/пустое значение сводится к стабильному дефолту без ошибки.
	DefaultProtocol string `json:"default_protocol"`

	// Hardening — WAN-стойкость туннельного порта (v0.8): скрытие сервиса
	// от сканеров (tarpit без ответных байтов), глобальный/per-IP лимиты
	// параллельных соединений. См. internal/hardening и SECURITY.md.
	Hardening struct {
		Enabled    bool `json:"enabled"`
		TarpitSec  int  `json:"tarpit_sec"`
		MaxConns   int  `json:"max_conns"`
		PerIPConns int  `json:"per_ip_conns"`
	} `json:"hardening"`

	// Modules — автообновляемый манифест модулей (v0.8): общий для APK и
	// сервера источник правил (реестр протоколов, политики). См.
	// internal/modules и modules/README.md.
	Modules struct {
		URL        string `json:"url"`
		Auto       bool   `json:"auto"`
		CheckHours int    `json:"check_hours"`
	} `json:"modules"`

	Limits struct {
		MaxStreams          int `json:"max_streams"`
		StreamWindow        int `json:"stream_window"`
		MaxStreamWindow     int `json:"max_stream_window"`
		DeviceBudget        int `json:"device_budget"`
		MaxTunnelsPerDevice int `json:"max_tunnels_per_device"`
		IdleTimeoutSec      int `json:"idle_timeout_sec"`
		PingIntervalSec     int `json:"ping_interval_sec"`
		DialTimeoutSec      int `json:"dial_timeout_sec"`
		HandshakesPerMin    int `json:"handshakes_per_min"`
	} `json:"limits"`
}

// Default returns production-sane defaults.
func Default() *Config {
	var c Config
	c.Listen.Tunnels = ":4433"
	c.PublicHost = ""
	c.Listen.Mixed = ":1080"
	c.Listen.AdminTCP = "127.0.0.1:9090"
	c.Listen.TLSHosts = []string{"localhost"}
	c.StateDir = "/var/lib/reverseray"
	c.TokensFile = "" // default: <state_dir>/tokens.json
	c.Log.Level = "info"
	c.Log.Redact = true
	c.DefaultProtocol = "" // Validate() сводит пустое/мусорное к дефолту протокола
	c.Limits.MaxStreams = 256
	c.Limits.StreamWindow = 512 * 1024
	c.Limits.MaxStreamWindow = 4 * 1024 * 1024
	c.Limits.DeviceBudget = 16 * 1024 * 1024
	c.Limits.MaxTunnelsPerDevice = 8
	c.Limits.IdleTimeoutSec = 180
	c.Limits.PingIntervalSec = 60
	c.Limits.DialTimeoutSec = 10
	// v0.7: смягчённый rate-limit рукопожатий. Лимит 60/min рвал легитимные
	// реконнекты при нестабильной мобильной сети (реконнект ≈ 1/с уже упирался
	// в потолок, у NAT за ним могли сидеть несколько клиентов).
	c.Limits.HandshakesPerMin = 120
	// v0.8 hardening: сканеры получают тишину+tarpit, реальные клиенты — TLS.
	c.Hardening.Enabled = true
	c.Hardening.TarpitSec = 3
	c.Hardening.MaxConns = 4096
	c.Hardening.PerIPConns = 32
	// v0.8 modules: чек манифеста раз в сутки (только при изменении версии/хеша).
	c.Modules.URL = "https://raw.githubusercontent.com/stelgen/reverseray/main/modules/modules.json"
	c.Modules.Auto = true
	c.Modules.CheckHours = 24
	return &c
}

// Load reads config from path (JSON) and applies RR_* env overrides.
func Load(path string) (*Config, error) {
	c := Default()
	if path != "" && path != "-" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
		if err := json.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("config parse: %w", err)
		}
	}
	c.applyEnv()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) applyEnv() {
	setStr := func(dst *string, key string) {
		if v := os.Getenv(key); v != "" {
			*dst = v
		}
	}
	setStr(&c.PublicHost, "RR_PUBLIC_HOST")
	setStr(&c.Listen.Tunnels, "RR_LISTEN_TUNNELS")
	setStr(&c.Listen.Mixed, "RR_LISTEN_MIXED")
	setStr(&c.Listen.Socks, "RR_LISTEN_SOCKS")
	setStr(&c.Listen.HTTP, "RR_LISTEN_HTTP")
	setStr(&c.Listen.AdminTCP, "RR_LISTEN_ADMIN_TCP")
	setStr(&c.Listen.AdminUnix, "RR_LISTEN_ADMIN_UNIX")
	setStr(&c.StateDir, "RR_STATE_DIR")
	setStr(&c.TokensFile, "RR_TOKENS_FILE")
	setStr(&c.Auth.Username, "RR_AUTH_USERNAME")
	setStr(&c.Auth.Password, "RR_AUTH_PASSWORD")
	setStr(&c.Auth.PasswordFile, "RR_AUTH_PASSWORD_FILE")
	setStr(&c.Log.Level, "RR_LOG_LEVEL")
	// Протокол по умолчанию: RR_PROTOCOL (короткая форма) и
	// RR_DEFAULT_PROTOCOL (длинная, для наглядности в compose). Мусор/пустое
	// НЕ приводят к ошибке — Validate() сводит к самому стабильному протоколу.
	setStr(&c.DefaultProtocol, "RR_PROTOCOL")
	setStr(&c.DefaultProtocol, "RR_DEFAULT_PROTOCOL")
	setInt := func(dst *int, key string) {
		if v := os.Getenv(key); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				*dst = n
			}
		}
	}
	setInt(&c.Limits.MaxStreams, "RR_LIMITS_MAX_STREAMS")
	setInt(&c.Limits.MaxTunnelsPerDevice, "RR_LIMITS_MAX_TUNNELS")
	setInt(&c.Limits.IdleTimeoutSec, "RR_LIMITS_IDLE_TIMEOUT")
	setInt(&c.Limits.DialTimeoutSec, "RR_LIMITS_DIAL_TIMEOUT")
	setInt(&c.Limits.HandshakesPerMin, "RR_LIMITS_HANDSHAKES_PER_MIN")
	// v0.8: hardening (RR_HARDENING=false/0 выключает скрытие порта) и модули.
	if v := os.Getenv("RR_HARDENING"); v != "" {
		c.Hardening.Enabled = v != "false" && v != "0"
	}
	setInt(&c.Hardening.TarpitSec, "RR_HARDENING_TARPIT_SEC")
	setInt(&c.Hardening.MaxConns, "RR_HARDENING_MAX_CONNS")
	setInt(&c.Hardening.PerIPConns, "RR_HARDENING_PER_IP_CONNS")
	setStr(&c.Modules.URL, "RR_MODULES_URL")
	if v := os.Getenv("RR_MODULES_AUTO"); v != "" {
		c.Modules.Auto = v != "false" && v != "0"
	}
	setInt(&c.Modules.CheckHours, "RR_MODULES_CHECK_HOURS")
	if v := os.Getenv("RR_LOG_REDACT"); v != "" {
		c.Log.Redact = v != "false" && v != "0"
	}
}

// Validate checks values and normalizes derived fields.
func (c *Config) Validate() error {
	if c.Listen.Tunnels == "" && c.Listen.Mixed == "" {
		return errors.New("config: at least one of listen.tunnels / listen.mixed required")
	}
	c.DefaultProtocol = rrp.NormalizeProto(c.DefaultProtocol) // мусор → дефолт, никогда не ошибка
	if c.TokensFile == "" {
		c.TokensFile = c.StateDir + "/tokens.json"
	}
	if _, _, err := net.SplitHostPort(c.Listen.AdminTCP); err != nil && c.Listen.AdminTCP != "" {
		return fmt.Errorf("config: bad admin_tcp: %w", err)
	}
	if c.Limits.MaxStreams <= 0 || c.Limits.MaxStreams > 1024 {
		return errors.New("config: limits.max_streams out of range (1..1024)")
	}
	if c.Limits.HandshakesPerMin <= 0 {
		c.Limits.HandshakesPerMin = 120
	}
	// hardening: мусорные/нереалистичные значения сводятся к дефолту без ошибки
	if c.Hardening.TarpitSec < 0 || c.Hardening.TarpitSec > 60 {
		c.Hardening.TarpitSec = 3
	}
	if c.Hardening.MaxConns <= 0 {
		c.Hardening.MaxConns = 4096
	}
	if c.Hardening.PerIPConns <= 0 {
		c.Hardening.PerIPConns = 32
	}
	if c.Modules.CheckHours <= 0 {
		c.Modules.CheckHours = 24
	}
	return nil
}

// IdleTimeout returns the session idle timeout.
func (c *Config) IdleTimeout() time.Duration {
	return time.Duration(c.Limits.IdleTimeoutSec) * time.Second
}

// PingInterval returns the server keepalive interval.
func (c *Config) PingInterval() time.Duration {
	return time.Duration(c.Limits.PingIntervalSec) * time.Second
}

// DialTimeout returns the egress dial timeout.
func (c *Config) DialTimeout() time.Duration {
	return time.Duration(c.Limits.DialTimeoutSec) * time.Second
}

// LoadPassword resolves password from file if configured.
func (c *Config) LoadPassword() (string, error) {
	if c.Auth.PasswordFile != "" {
		b, err := os.ReadFile(c.Auth.PasswordFile)
		if err != nil {
			return "", fmt.Errorf("password file: %w", err)
		}
		return trim(string(b)), nil
	}
	return c.Auth.Password, nil
}

func trim(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
