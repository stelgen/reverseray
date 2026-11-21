package rrp

import (
	"encoding/json"
	"fmt"
	"time"
)

// session_handshake.go — обмен ключами протокола (WG_INIT/BT_INIT/KEY_RESP)
// и управление камуфляжем (0x2A).
//
// v1.9.3: бесшовная смена протокола (0x2C) удалена. Обмен ключами —
// единственная механика согласования конверта: она живёт ТОЛЬКО при
// первичном подключении (сессия стартует с keyPlan из SessionConfig,
// Run шлёт KEY_REQ → клиент отвечает INIT/KEY_RESP → commitCrypto).
// Повторный/неожиданный INIT при живой крипте — игнор (анти-мусор);
// смена протокола клиентом выполняется обычным реконнектом.

// handleWgInit: бинарный кадр WG_INIT (v0.9.6, wireguard/Noise_IKpsk2) —
// маршрутизация в план обмена ключами (rrp.InitResponder). Вызывается из
// Run — гонок нет.
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

// ---- обмен ключами протокола (v0.9.2, внутри сессии) ----

// handleKeyResp: KEY_RESP от телефона → Complete → крипта включена.
// Вызывается из Run (единственный читатель) — гонок нет.
func (s *Session) handleKeyResp(f *Frame) {
	s.mu.Lock()
	if s.crypto != nil || s.keyPlan == nil {
		s.mu.Unlock()
		return // повторный/неожиданный KEY_RESP — игнор (анти-мусор)
	}
	crypto, err := s.keyPlan.Complete(f.Payload)
	if err != nil {
		s.mu.Unlock()
		s.logf("rrp: key exchange failed: %v", err)
		s.shutdown(fmt.Errorf("key exchange: %w", err))
		return
	}
	s.mu.Unlock()
	s.commitCrypto(crypto)
	s.logf("rrp: payload crypto engaged (session %s, proto %s)", s.ID, s.Proto)
}

// startKeyDeadline: жёсткий дедлайн обмена ключами (битый клиент не висит
// сессией вечно — idle-таймаут слишком долгий для рукопожатия).
func (s *Session) startKeyDeadline() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyTimer = time.AfterFunc(KeyExchangeTimeout, func() {
		s.mu.Lock()
		crypto := s.crypto
		s.mu.Unlock()
		if crypto == nil {
			s.logf("rrp: key exchange timeout (%s) — closing", s.ID)
			s.shutdown(fmt.Errorf("key exchange timeout"))
		}
	})
}
