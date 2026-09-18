// Package hub tracks devices and their tunnels, routing egress dials
// with a least-outstanding strategy.
package hub

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

var ErrNoTunnel = errors.New("hub: no connected device tunnel")

type Device struct {
	Name       string
	MaxTunnels int

	mu       sync.Mutex
	sessions []*rrp.Session
}

type Hub struct {
	mu      sync.Mutex
	devices map[string]*Device
}

func New() *Hub {
	return &Hub{devices: make(map[string]*Device)}
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
func (h *Hub) Attach(device string, s *rrp.Session, maxTunnels int) error {
	h.mu.Lock()
	d := h.device(device, maxTunnels)
	h.mu.Unlock()
	d.mu.Lock()
	defer d.mu.Unlock()
	limit := d.MaxTunnels
	if maxTunnels > 0 && maxTunnels < limit {
		limit = maxTunnels
	}
	if len(d.sessions) >= limit {
		return errors.New("hub: device tunnel limit reached")
	}
	d.sessions = append(d.sessions, s)
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

// Dial routes an egress connect to the least-outstanding tunnel.
// The phone performs the real dial (and DNS) — the server never egresses.
func (h *Hub) Dial(ctx context.Context, atyp byte, addr []byte, port uint16, timeout time.Duration) (net.Conn, error) {
	var best *rrp.Session
	h.mu.Lock()
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
	h.mu.Unlock()
	if best == nil {
		return nil, ErrNoTunnel
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return best.Open(dctx, rrp.DialRequest{ATYP: atyp, Addr: addr, Port: port})
}

// Snapshot lists live sessions for the admin API.
func (h *Hub) Snapshot() []map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []map[string]any
	for _, d := range h.devices {
		d.mu.Lock()
		for _, s := range d.sessions {
			out = append(out, map[string]any{
				"session":     s.ID,
				"device":      d.Name,
				"outstanding": s.Outstanding(),
				"rtt_ms":      s.RTT(),
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
