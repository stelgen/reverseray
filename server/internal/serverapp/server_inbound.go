// Package serverapp — зона «Inbound» (сборка протокола входящего списка). Pure move из server.go (v1.8.3).
package serverapp

import (
	"fmt"
	"net"
	"strings"

	"github.com/stelgen/reverseray/server/internal/inbound"
)

// ---- inbound ----

func (a *App) inbound(ln net.Listener) *inbound.Inbound {
	pass, err := a.cfg.LoadPassword()
	if err != nil {
		a.log.Warn("inbound password file unreadable; starting without inbound auth", "err", err)
	}
	return &inbound.Inbound{
		Dialer:      a.hub,
		Parker:      a.hub, // v1.3.0: буфер трафика — паркинг стримов при потере туннеля
		Username:    a.cfg.Auth.Username,
		Password:    pass,
		Allowlist:   parseAllowlist(a.cfg.Allowlist),
		DialTimeout: a.cfg.DialTimeout(),
		UDPBindPort: udpBindPort(a.cfg.Listen.Mixed),
		Logf: func(f string, args ...any) {
			if a.cfg.Log.Redact {
				a.log.Info("inbound event redacted")
				return
			}
			a.log.Info(fmt.Sprintf(f, args...))
		},
	}
}

func parseAllowlist(specs []string) []*net.IPNet {
	var out []*net.IPNet
	for _, s := range specs {
		if !strings.Contains(s, "/") {
			s += "/32"
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}
