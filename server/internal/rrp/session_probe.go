package rrp

import (
	"context"
	"encoding/json"
	"net"
	"time"
)

// ---- PROBE (v0.7.4): валидация реального egress для смены протокола ----

type probeRequest struct {
	Target    string `json:"target"`
	TimeoutMs int64  `json:"timeout_ms"`
}

type probeResponse struct {
	OK    bool   `json:"ok"`
	Err   string `json:"err"`
	Proto string `json:"proto"`
}

// handleProbe диалит цель с сервера (егресс сервера = егресс туннеля) и
// отвечает результатом. Клиент использует это как доказательство «туннель
// реально возит трафик до реальных хостов» перед коммитом смены протокола.
func (s *Session) handleProbe(f *Frame) {
	resp := probeResponse{OK: false, Err: "probe disabled", Proto: s.cfg.Protocol}
	defer func() {
		b, _ := json.Marshal(resp)
		s.writeAsync(&Frame{Type: TypeProbe, Payload: b})
	}()
	if s.cfg.ProbeDialer == nil {
		return
	}
	var req probeRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		resp.Err = "bad probe json"
		return
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if timeout > 15*time.Second {
		timeout = 15 * time.Second
	}
	_, _, err := net.SplitHostPort(req.Target)
	if err != nil {
		resp.Err = "bad probe target"
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := s.cfg.ProbeDialer(ctx, req.Target, timeout); err != nil {
		resp.Err = err.Error()
		return
	}
	resp.OK = true
	resp.Err = ""
}

// isPayloadFrame — кадры, чьи payload'ы идут через крипто-конверт.
func isPayloadFrame(t uint8) bool { return t == TypeData || t == TypeUdpData }
