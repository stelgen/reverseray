// Package inbound implements the mixed SOCKS5/HTTP entry listener.
package inbound

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stelgen/reverseray/server/internal/park"
	"github.com/stelgen/reverseray/server/internal/rrp"
)

// Dialer abstracts the tunnel hub (implemented by *hub.Hub).
type Dialer interface {
	Dial(ctx context.Context, atyp byte, addr []byte, port uint16, timeout time.Duration) (net.Conn, error)
	// DialUDP открывает UDP-ассоциацию на пуле телефонов (v0.7).
	DialUDP(ctx context.Context, timeout time.Duration) (*rrp.UdpChannel, error)
}

// UdpPacket — алиас пакета туннеля (source: телефон, target: клиент SOCKS).
type UdpPacket = rrp.UdpPacket

// socks request cmd codes (RFC 1928).
const (
	socksCmdConnect = 0x01
	socksCmdUdpAsoc = 0x03
)

// Inbound is a mixed-protocol proxy listener.
type Inbound struct {
	Dialer    Dialer
	Username  string // optional; both empty = no auth
	Password  string
	Allowlist []*net.IPNet
	Logf      func(format string, args ...any)

	// v1.3.0 «буфер трафика»: приемник паркинга стримов (hub). nil = паркинг
	// выключен (старое поведение: смерть туннеля закрывает браузерную сторону).
	Parker park.Sink

	DialTimeout time.Duration

	// UDPBindPort — порт UDP-сокета для SOCKS5 UDP ASSOCIATE (RFC 1928).
	// Один общий сокет на listener (клиент шлёт дейтаграммы на BND.PORT).
	// 0 → порт берётся из listen-адреса mixed (1080).
	UDPBindPort int

	udpMu        sync.Mutex
	udpSock      *net.UDPConn
	udpByIP      map[string][]*udpAssoc
	udpByClient  map[string]*udpAssoc
	UdpDatagrams atomic.Uint64
}

// Serve accepts connections until the listener closes.
func (in *Inbound) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if !in.allowed(c.RemoteAddr()) {
			_ = c.Close()
			continue
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true) // v0.9.6: интерактивные SOCKS-сессии без Nagle
		}
		go in.handle(c)
	}
}

func (in *Inbound) allowed(ra net.Addr) bool {
	if len(in.Allowlist) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(ra.String())
	if err != nil {
		host = ra.String()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range in.Allowlist {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (in *Inbound) logf(f string, a ...any) {
	if in.Logf != nil {
		in.Logf(f, a...)
	}
}

// handle — v0.8: panic-safety (недоверенный ввод не роняет процесс) и
// slowloris-гвард: первый запрос обязан прийти ≤30 с, дальше дедлайн
// снимается (relay ставит свои).
func (in *Inbound) handle(c net.Conn) {
	// v1.3.0 «буфер трафика»: если стрим запаркован (владение c передано
	// буферу) — закрывать c здесь НЕЛЬЗЯ, он переживёт потерю туннеля.
	parked := false
	defer func() {
		if r := recover(); r != nil {
			in.logf("inbound panic recovered: %v", r)
		}
		if !parked {
			_ = c.Close()
		}
	}()
	br := bufio.NewReaderSize(c, 16*1024)
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	switch first[0] {
	case 0x05:
		parked = in.socks5(c, br)
	default:
		parked = in.http(c, br)
	}
}

func (in *Inbound) dial(_ net.Conn, atyp byte, addr []byte, port uint16) (net.Conn, error) {
	return in.Dialer.Dial(context.Background(), atyp, addr, port, in.DialTimeout)
}

func encodeHost(host string) (byte, []byte, error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return 1, v4, nil
		}
		return 4, ip.To16(), nil
	}
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 255 {
		return 0, nil, fmt.Errorf("bad host")
	}
	return 3, []byte(strings.ToLower(host)), nil
}

// proxyBasicAuth parses the Proxy-Authorization header (RFC 7235 proxy variant).
