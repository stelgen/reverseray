package rrp

import (
	"errors"
	"time"
)

// ---- outbound (server -> phone) ----

// v1.9.3: бесшовная смена протокола (0x2C) удалена — паркинг payload-кадров
// больше не нужен: смена конверта = обычный реконнект клиента.

func (s *Session) writeAsync(f *Frame) {
	select {
	case <-s.done:
		return
	default:
	}
	select {
	case s.outq <- outItem{frame: f}:
	case <-time.After(10 * time.Second):
		go s.shutdown(errors.New("writer backlog"))
	case <-s.done:
	}
}

// commitCrypto — включение крипто-конверта протокола. Вызывается ТОЛЬКО из
// читающей горутины (Run) — гонок нет.
// v1.9.9: активный конверт (если был — ре-кей) ретирится в prev-окно:
// кадры в полёте, запечатанные телефоном до получения RESP, декодируются
// старым конвертом в течение prevGrace (session_rekey.go).
func (s *Session) commitCrypto(pc PayloadCrypto) {
	s.mu.Lock()
	if s.crypto != nil {
		s.cryptoPrev = s.crypto
		s.prevUntil = time.Now().Add(prevGrace)
	}
	s.crypto = pc
	if s.keyTimer != nil {
		s.keyTimer.Stop()
		s.keyTimer = nil
	}
	// v1.9.9: сброс rekeying безопасен при живом prev-окне — кадры в полёте
	// расшифровываются через cryptoPrev, а спекулятивный Open (bt.openPeek)
	// не потребляет кейстрим при фейле: ни активный, ни prev конверт
	// битым/чужим кадром не отравляются.
	s.rekeying = false
	s.fails = 0
	s.mu.Unlock()
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
// v1.9.9 dual-window: сначала активный конверт; на фейл — prev (кадры,
// запечатанные телефоном до получения RESP в момент ре-кея).
func (s *Session) decryptDown(payload []byte) ([]byte, error) {
	s.mu.Lock()
	crypto := s.crypto
	var prev PayloadCrypto
	if crypto == nil || time.Now().Before(s.prevUntil) {
		prev = s.cryptoPrev
	}
	s.mu.Unlock()
	if crypto == nil || len(payload) == 0 {
		return payload, nil
	}
	plain, err := crypto.DecryptDown(payload)
	if err == nil {
		s.mu.Lock()
	s.fails = 0
		s.mu.Unlock()
		return plain, nil
	}
	if prev != nil {
		if p2, e2 := prev.DecryptDown(payload); e2 == nil {
			s.mu.Lock()
			s.fails = 0
			s.mu.Unlock()
			return p2, nil
		}
	}
	return nil, err
}
