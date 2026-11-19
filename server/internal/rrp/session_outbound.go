package rrp

import (
	"errors"
	"time"
)

// ---- outbound (server -> phone) ----

func (s *Session) writeAsync(f *Frame) {
	select {
	case <-s.done:
		return
	default:
	}
	// v0.10: во время бесшовной смены протокола payload-кадры ждут коммита
	// нового крипто-конверта (иначе в полёте встречаются конверты двух
	// протоколов). Контрольные кадры хендшейка идут свободно.
	if isPayloadFrame(f.Type) && !s.parkWait() {
		return
	}
	select {
	case s.outq <- outItem{frame: f}:
	case <-time.After(10 * time.Second):
		go s.shutdown(errors.New("writer backlog"))
	case <-s.done:
	}
}

// parkWait блокирует payload-отправителя до снятия паркинга или смерти
// сессии. v1.8.3: собственного таймера НЕТ — дедлайн свитча принадлежит
// startSwitchDeadline (SwitchTimeout): при просрочке shutdown закрывает done,
// и все parkWait корректно выходят. Легитимный pending-свитч живёт ровно
// столько, сколько жив pending-свитч — «ноль потерь» не ограничен таймером
// паркинга (канон v1.3.0: буфер в RAM без дропов).
func (s *Session) parkWait() bool {
	s.mu.Lock()
	if !s.parked {
		s.mu.Unlock()
		return true
	}
	gate := s.parkGate
	s.mu.Unlock()
	if gate == nil {
		return true
	}
	select {
	case <-gate:
		return true
	case <-s.done:
		return false
	}
}

// unparkPayload снимает паркинг (все ожидающие отправители проходят).
func (s *Session) unparkPayload() {
	s.mu.Lock()
	if s.parked {
		s.parked = false
		gate := s.parkGate
		s.parkGate = nil
		if gate != nil {
			close(gate)
		}
	}
	s.mu.Unlock()
}

// parkPayloadLocked — включить паркинг (ВЫЗЫВАТЬ ПОД s.mu).
func (s *Session) parkPayloadLocked() {
	if !s.parked {
		s.parked = true
		s.parkGate = make(chan struct{})
	}
}

// commitCrypto — точка атомарного коммита нового крипто-конверта:
// свап + коммит целевого протокола бесшовной смены + снятие паркинга.
// Вызывается ТОЛЬКО из читающей горутины (Run) — гонок нет.
func (s *Session) commitCrypto(pc PayloadCrypto) {
	s.mu.Lock()
	s.crypto = pc
	hadSwitch := false
	switchDur := time.Duration(0)
	if s.pendingProto != "" {
		s.Proto = s.pendingProto
		s.pendingProto = ""
		hadSwitch = true
		switchDur = time.Since(s.switchStartedAt) // v1.8.3: наблюдаемость
	}
	if s.keyTimer != nil {
		s.keyTimer.Stop()
		s.keyTimer = nil
	}
	s.mu.Unlock()
	s.unparkPayload()
	if hadSwitch {
		s.logf("rrp: protocol switch committed (%s, %v)", s.Proto, switchDur)
	}
}

func (s *Session) writeLoop() {
	for {
		select {
		case it := <-s.outq:
			err := s.emit(it.frame)
			if it.err != nil {
				it.err <- err
			}
			if err != nil {
				s.shutdown(err)
				return
			}
		case <-s.done:
			return
		}
	}
}

// emit — один кадр наружу: payload-кадры (DATA/UDP_DATA) при включённой
// крипте шифруются (конверт добавляет заголовки — открытый DATA режется на
// чанки ≤ MaxPlainData; слишком большой UDP_DATA дропается — семантика UDP).
// Вызывается только из writeLoop (горутин-эксклюзивно).
func (s *Session) emit(f *Frame) error {
	s.mu.Lock()
	crypto := s.crypto
	s.mu.Unlock()
	if crypto == nil || !isPayloadFrame(f.Type) {
		return WriteFrame(s.wc, f.Type, f.Flags, f.StreamID, f.Payload)
	}
	if f.Type == TypeUdpData {
		if len(f.Payload) > crypto.MaxPlainData() {
			return nil // дроп, UDP — без гарантий (как в mtproto wrapper)
		}
		env, err := crypto.EncryptUp(f.Payload)
		if err != nil {
			return err
		}
		return WriteFrame(s.wc, f.Type, f.Flags, f.StreamID, env)
	}
	payload := f.Payload
	max := crypto.MaxPlainData()
	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > max {
			chunk = chunk[:max]
		}
		payload = payload[len(chunk):]
		env, err := crypto.EncryptUp(chunk)
		if err != nil {
			return err
		}
		if err := WriteFrame(s.wc, f.Type, f.Flags, f.StreamID, env); err != nil {
			return err
		}
	}
	return nil
}

// decryptDown расшифровывает входящий payload-кадр (если крипта включена).
// До завершения обмена ключами крипто nil — кадры идут открытыми.
func (s *Session) decryptDown(payload []byte) ([]byte, error) {
	s.mu.Lock()
	crypto := s.crypto
	s.mu.Unlock()
	if crypto == nil || len(payload) == 0 {
		return payload, nil
	}
	return crypto.DecryptDown(payload)
}
