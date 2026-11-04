// Package hub tracks devices and their tunnels, routing egress dials
// with a least-outstanding strategy.
package hub

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/stelgen/reverseray/server/internal/park"
	"github.com/stelgen/reverseray/server/internal/rrp"
)

var ErrNoTunnel = errors.New("hub: no connected device tunnel")

type Device struct {
	Name       string
	MaxTunnels int

	mu       sync.Mutex
	sessions []*rrp.Session
	// v1.3.0 «буфер трафика»: запаркованные стримы (потеря туннеля), ключ — токен.
	parked map[[16]byte]*park.Parked
}

type Hub struct {
	mu      sync.Mutex
	devices map[string]*Device
	// test-only: подмена снимка сессий в юнит-тестах (/ui, v0.9.6).
	// nil в продакшене — Snapshot работает как раньше.
	testSnapshot []map[string]any

	// v1.3.0 «буфер трафика»: TTL паркинга (сек) и приёмник событий для /ui.
	ParkSec int
	Logf    func(level, kind, msg string)
}

func New() *Hub {
	h := &Hub{devices: make(map[string]*Device), ParkSec: 30}
	go h.parkJanitor()
	return h
}

func (h *Hub) logf(level, kind, msg string) {
	if h.Logf != nil {
		h.Logf(level, kind, msg)
	}
}

// Park сохраняет стрим в буфере устройства (Sink для inbound-релея).
func (h *Hub) Park(p *park.Parked) bool {
	h.mu.Lock()
	d := h.devices[p.Device]
	h.mu.Unlock()
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.parked == nil {
		d.parked = make(map[[16]byte]*park.Parked)
	}
	if _, dup := d.parked[p.Token]; dup {
		return false
	}
	if len(d.parked) >= 256 {
		return false // защита памяти: слишком много запаркованных стримов
	}
	d.parked[p.Token] = p
	return true
}

// parkSnapshot — снимок очереди буфера устройства.
func (d *Device) parkSnapshot() []*park.Parked {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]*park.Parked, 0, len(d.parked))
	for _, p := range d.parked {
		out = append(out, p)
	}
	return out
}

// takeParked изымает стрим из буфера (для резюме или TTL-закрытия).
func (d *Device) takeParked(token [16]byte) *park.Parked {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.parked[token]
	delete(d.parked, token)
	return p
}

// parkJanitor — TTL: стримы, не дожившие до реконнекта, закрываются штатно
// (TCP-стороны уведомлены корректно, телефонный сокет утилизирует свой рипер).
func (h *Hub) parkJanitor() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		h.mu.Lock()
		devs := make([]*Device, 0, len(h.devices))
		for _, d := range h.devices {
			devs = append(devs, d)
		}
		h.mu.Unlock()
		ttl := time.Duration(h.ParkSec) * time.Second
		if ttl <= 0 {
			ttl = 30 * time.Second
		}
		for _, d := range devs {
			for _, p := range d.parkSnapshot() {
				if time.Since(p.ParkedAt) > ttl {
					if taken := d.takeParked(p.Token); taken != nil {
						taken.Close()
					}
				}
			}
		}
	}
}

// ParkedTotal (v1.3.0) — сколько стримов сейчас в буфере (все устройства).
func (h *Hub) ParkedTotal() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, d := range h.devices {
		d.mu.Lock()
		n += len(d.parked)
		d.mu.Unlock()
	}
	return n
}

// resumeParked — реконнект состоялся: просим телефон привязать запаркованные
// сокеты к новым стримам; буфер c→p дозылается, релей продолжается.
func (h *Hub) resumeParked(device string, s *rrp.Session, list []*park.Parked) {
	for _, p := range list {
		select {
		case <-s.Done():
			return
		case <-p.Done:
			continue
		default:
		}
		dctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		st, err := s.OpenResume(dctx, p.Token, p.Dst)
		cancel()
		if err != nil {
			h.logf("warn", "park", "устройство "+device+": резюме не удалось ("+err.Error()+") — соединение закрыто штатно")
			if taken := h.take(device, p.Token); taken != nil {
				taken.Close()
			}
			continue
		}
		if rerr := p.Resume(st); rerr != nil {
			h.logf("warn", "park", "устройство "+device+": склейка буфера не удалась: "+rerr.Error())
			continue
		}
		h.logf("info", "park", "устройство "+device+": поток возобновлён после потери связи — буфер "+fmt.Sprint(p.PendingLen())+" Б дозалиты")
	}
}

func (h *Hub) take(device string, token [16]byte) *park.Parked {
	h.mu.Lock()
	d := h.devices[device]
	h.mu.Unlock()
	if d == nil {
		return nil
	}
	return d.takeParked(token)
}

func (h *Hub) device(name string, maxTunnels int) *Device {
	d := h.devices[name]
	if d == nil {
		d = &Device{Name: name, MaxTunnels: maxTunnels}
		h.devices[name] = d
	}
	return d
}

// Attach registers a session; enforces the per-device tunnel cap.
// v1.3.0: после подключения запускаем резюме запаркованных стримов —
// «буфер трафика» доигрывает очередь после потери связи.
func (h *Hub) Attach(device string, s *rrp.Session, maxTunnels int) error {
	h.mu.Lock()
	d := h.device(device, maxTunnels)
	h.mu.Unlock()
	d.mu.Lock()
	limit := d.MaxTunnels
	if maxTunnels > 0 && maxTunnels < limit {
		limit = maxTunnels
	}
	if len(d.sessions) >= limit {
		d.mu.Unlock()
		return errors.New("hub: device tunnel limit reached")
	}
	d.sessions = append(d.sessions, s)
	// Снимок под УЖЕ удерживаемым d.mu — parkSnapshot() вызывать здесь
	// нельзя (не реентерабельный лок → self-deadlock, найден e2e-тестом).
	parked := make([]*park.Parked, 0, len(d.parked))
	for _, p := range d.parked {
		parked = append(parked, p)
	}
	d.mu.Unlock()
	if len(parked) > 0 {
		go h.resumeParked(device, s, parked)
	}
	return nil
}

// Detach removes a session (idempotent).
func (h *Hub) Detach(device string, s *rrp.Session) {
	h.mu.Lock()
	d := h.devices[device]
	h.mu.Unlock()
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, x := range d.sessions {
		if x == s {
			d.sessions = append(d.sessions[:i], d.sessions[i+1:]...)
			break
		}
	}
}

// pickSession returns the least-outstanding live session (phone pool).
func (h *Hub) pickSession() *rrp.Session {
	h.mu.Lock()
	defer h.mu.Unlock()
	var best *rrp.Session
	for _, d := range h.devices {
		d.mu.Lock()
		for _, s := range d.sessions {
			select {
			case <-s.Done():
				continue
			default:
			}
			if best == nil || s.Outstanding() < best.Outstanding() {
				best = s
			}
		}
		d.mu.Unlock()
	}
	return best
}

// Dial routes an egress connect to the least-outstanding tunnel.
// The phone performs the real dial (and DNS) — the server never egresses.
func (h *Hub) Dial(ctx context.Context, atyp byte, addr []byte, port uint16, timeout time.Duration) (net.Conn, error) {
	best := h.pickSession()
	if best == nil {
		return nil, ErrNoTunnel
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return best.Open(dctx, rrp.DialRequest{ATYP: atyp, Addr: addr, Port: port})
}

// DialUDP opens a UDP association on the least-outstanding tunnel (v0.7).
// Дейтаграммы ходят через туннель до телефона, телефон выполняет реальный
// UDP-обмен (и DNS) — сервер не делает исходящих соединений.
func (h *Hub) DialUDP(ctx context.Context, timeout time.Duration) (*rrp.UdpChannel, error) {
	best := h.pickSession()
	if best == nil {
		return nil, ErrNoTunnel
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return best.UdpOpen(dctx)
}

// SetSnapshotForTest подменяет снимок сессий (только тесты /ui, v0.9.6).
// nil снимает подмену. В продакшене не вызывается.
func (h *Hub) SetSnapshotForTest(sessions []map[string]any) {
	h.mu.Lock()
	h.testSnapshot = sessions
	h.mu.Unlock()
}

// Snapshot lists live sessions for the admin API.
func (h *Hub) Snapshot() []map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.testSnapshot != nil {
		return h.testSnapshot
	}
	var out []map[string]any
	for _, d := range h.devices {
		d.mu.Lock()
		for _, s := range d.sessions {
			// v0.9.5: полный снимок сессии для дашборда /ui — relay-байты,
			// стримы, uptime, крипта протокола, UDP/DNS-счётчики.
			relayIn, relayOut := s.Relayed()
			st := s.LastStats()
			var up int64
			if ct := s.ConnectedAt(); !ct.IsZero() {
				up = int64(time.Since(ct).Seconds())
			}
			out = append(out, map[string]any{
				"session":     s.ID,
				"device":      d.Name,
				"outstanding": s.Outstanding(),
				"rtt_ms":      s.RTT(),
				"proto":       s.Proto,
				"bytes_in":    st.BytesIn, // трафик, отчитанный телефоном
				"bytes_out":   st.BytesOut,
				"relay_in":    relayIn, // байты payload'ов через сервер
				"relay_out":   relayOut,
				"streams":     s.StreamsOpen(),
				// v1.2.0: autotune-окна и отказы диала телефона (наблюдаемость)
				"open_errors":  s.OpenErrors(),
				"window_grant": s.WindowGrantTotal(),
				"window_grow":  s.WindowGrowTotal(),
				"mt_active":    s.MTActive(),
				"udp":          s.UdpDatagrams(),
				"dns":          s.DnsHits(),
				"connected_at": s.ConnectedAt().Unix(),
				"uptime_sec":   up,
			})
		}
		d.mu.Unlock()
	}
	return out
}

// Kick terminates all sessions of a device.
func (h *Hub) Kick(device string) int {
	h.mu.Lock()
	d := h.devices[device]
	h.mu.Unlock()
	if d == nil {
		return 0
	}
	d.mu.Lock()
	n := len(d.sessions)
	for _, s := range d.sessions {
		_ = s.Close()
	}
	d.sessions = nil
	d.mu.Unlock()
	return n
}
