package rrp

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// в план обмена ключами (rrp.InitResponder). Вызывается из Run — гонок нет.
func (s *Session) handleWgInit(f *Frame) {
	s.mu.Lock()
	if s.crypto != nil || s.keyPlan == nil {
		s.mu.Unlock()
		return // повторный/неожиданный INIT — игнор (анти-мусор)
	}
	ir, ok := s.keyPlan.(InitResponder)
	if !ok || ir.ClientInitFrameType() != TypeWgInit {
		s.mu.Unlock()
		s.logf("rrp: unexpected WG_INIT for proto %s", s.Proto)
		s.shutdown(fmt.Errorf("unexpected frame 0x27"))
		return
	}
	s.mu.Unlock()
	respType, respPayload, crypto, err := ir.OnClientInit(f.Payload)
	if err != nil {
		s.logf("rrp: key exchange failed: %v", err)
		s.shutdown(fmt.Errorf("key exchange: %w", err))
		return
	}
	s.writeAsync(&Frame{Type: respType, Payload: respPayload})
	s.commitCrypto(crypto)
	s.logf("rrp: payload crypto engaged (session %s, proto %s)", s.ID, s.Proto)
}

// handleBtInit: бинарный кадр BT_INIT (v0.10, bittorrent/MSE) — маршрутизация
// в план обмена ключами (rrp.InitResponder). Вызывается из Run — гонок нет.
func (s *Session) handleBtInit(f *Frame) {
	s.mu.Lock()
	if s.crypto != nil || s.keyPlan == nil {
		s.mu.Unlock()
		return // повторный/неожиданный INIT — игнор (анти-мусор)
	}
	ir, ok := s.keyPlan.(InitResponder)
	if !ok || ir.ClientInitFrameType() != TypeBtInit {
		s.mu.Unlock()
		s.logf("rrp: unexpected BT_INIT for proto %s", s.Proto)
		s.shutdown(fmt.Errorf("unexpected frame 0x29"))
		return
	}
	s.mu.Unlock()
	respType, respPayload, crypto, err := ir.OnClientInit(f.Payload)
	if err != nil {
		s.logf("rrp: key exchange failed: %v", err)
		s.shutdown(fmt.Errorf("key exchange: %w", err))
		return
	}
	// Канонный порядок: RESP уходит в очередь ДО свапа крипты (клиент
	// декодирует старым конвертом всё, что придёт до RESP).
	s.writeAsync(&Frame{Type: respType, Payload: respPayload})
	s.commitCrypto(crypto)
	s.logf("rrp: payload crypto engaged (session %s, proto %s)", s.ID, s.Proto)
}

// ---- бесшовная смена протокола (v0.10, кадр 0x2C) ----

type protoSwitchMsg struct {
	Proto  string `json:"proto"`
	Nonce  string `json:"nonce,omitempty"`
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

func encodeProtoSwitch(proto, nonce string, ok bool, reason string) []byte {
	b, _ := json.Marshal(protoSwitchMsg{Proto: proto, Nonce: nonce, OK: ok, Reason: reason})
	return b
}

// handleProtoSwitch — клиент просит сменить протокол без разрыва связи:
// валидация цели → ответ ok → ПАРКОВКА payload'ов → перехендшейк целевого
// протокола (KEY_REQ → INIT/RESP) → атомарный свап крипто-конверта.
func (s *Session) handleProtoSwitch(f *Frame) {
	var req protoSwitchMsg
	if err := json.Unmarshal(f.Payload, &req); err != nil || strings.TrimSpace(req.Proto) == "" {
		s.logf("rrp: proto-switch garbage ignored")
		return // мусор не рвёт сессию (канон)
	}
	fail := func(reason string) {
		s.writeAsync(&Frame{Type: TypeProtoSwitch, Payload: encodeProtoSwitch("", req.Nonce, false, reason)})
	}
	if !s.cfg.Switchable || s.cfg.SwitchPlanner == nil {
		fail("switch disabled")
		return
	}
	target := NormalizeProto(req.Proto) // мусор → дефолт (никогда не ошибка)
	if !IsExecutable(target) {
		fail("protocol not executable")
		return
	}
	if target == DefaultProtocolID && s.crypto != nil {
		// v0.10: возврат на rrp1 = снятие крипты; в живой сессии безопасной
		// точки дрена нет (старые envelope-кадры клиента в полёте). Честный
		// отказ: клиент делает reconnect-свитч (валидирует и перезапускает).
		fail("rrp1 switch requires reconnect")
		return
	}
	s.mu.Lock()
	if s.pendingProto != "" {
		s.mu.Unlock()
		fail("switch already in progress")
		return
	}
	plan, err := s.cfg.SwitchPlanner(target)
	if err != nil {
		s.mu.Unlock()
		fail("plan unavailable")
		return
	}
	s.parkPayloadLocked()
	s.pendingProto = target
	s.switchStartedAt = time.Now() // v1.8.3: наблюдаемость длительности смены
	s.keyPlan = plan
	s.mu.Unlock()
	s.writeAsync(&Frame{Type: TypeProtoSwitch, Payload: encodeProtoSwitch(target, req.Nonce, true, "")})
	// перехендшейк целевого протокола (тот же поток, что и после READY в Run)
	reqPayload, err := plan.RequestPayload()
	if err != nil {
		s.shutdown(fmt.Errorf("proto switch key request: %w", err))
		return
	}
	errcc := make(chan error, 1)
	s.outq <- outItem{frame: &Frame{Type: TypeKeyReq, Payload: reqPayload}, err: errcc}
	if err := <-errcc; err != nil {
		s.shutdown(fmt.Errorf("proto switch key request write: %w", err))
		return
	}
	s.startSwitchDeadline()
	s.logf("rrp: protocol switch started (session %s, %s → %s)", s.ID, s.Proto, target)
}

// startSwitchDeadline — дедлайн перехендшейка свитча (старая крипта жива,
// поэтому критерий — pendingProto, а не crypto==nil). Единая точка тайминга
// смены (v1.8.3): parkWait паркинга таймера не имеет и ждёт именно этого
// дедлайна через done.
func (s *Session) startSwitchDeadline() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyTimer = time.AfterFunc(SwitchTimeout, func() {
		s.mu.Lock()
		pp := s.pendingProto
		s.mu.Unlock()
		if pp != "" {
			s.logf("rrp: protocol switch timeout (%s) — closing", pp)
			s.shutdown(fmt.Errorf("proto switch timeout"))
		}
	})
}

// handleCamCtl: клиент выключил/включил камуфляж для устройства (0x2A).
// Выбор персистится на сервере (см. serverapp) и переживает офлайн клиента.
func (s *Session) handleCamCtl(f *Frame) {
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.Unmarshal(f.Payload, &req); err != nil || req.Enabled == nil {
		s.logf("rrp: camctl garbage ignored")
		return // мусор не рвёт сессию (канон)
	}
	enabled := *req.Enabled
	if s.cfg.CamCtl != nil {
		s.cfg.CamCtl(enabled)
	}
	s.logf("rrp: camouflage %s by client (persisted)", map[bool]string{true: "enabled", false: "disabled"}[enabled])
}
