package rrp

import (
	"io"
	"net"
	"time"
)

// ---- C→S OPEN (v1.8.1): телефон инициирует стрим сквозь туннель ----
//
// Зачем: E2E-пробник полезной нагрузки (клиент v1.8.0) проверяет сквозной
// путь OPEN→DATA→ответ — единственный способ поймать сигнатурную блокировку
// (ТСПУ/DPI режет payload-кадры при живых контрольных PING/PROBE). До
// v1.8.1 сервер считал Open от телефона нарушением порядка (ErrProtocolOrder)
// и рвал сессию — клиент с E2E-пробником переподключался каждые ~5 с
// (регрессия v1.8.0, найдена живым e2e против сервера).
//
// Семантика: симметрия S→C. Сервер диалит цель СВОИМ egress, отвечает
// OPEN_OK(err) и релеит байты в обе стороны через канонный flow-control
// (stream.Write / pushIn: окна, outstand, паркинг при смене протокола).
//
// Доверие: телефон владеет токеном сервера — тот же принцип, что и S→C
// (сервер просит телефон диалить что угодно). Лимиты: гейт
// [SessionConfig.PhoneOpenAllowed], MaxStreams, бюджет outstand,
// диал-таймаут 10 с, IdleTimeout сессии, Echo-amplification нет (релей 1:1).
// Стримы телефона — ЧЁТНЫЕ id (сервер занимает нечётные: openStream
// nextID += 2), поэтому nextID не трогается и коллизий пространств нет.

// phoneOpenDialTimeout — диал цели с сервера (как CONNECT_TIMEOUT на телефоне).
const phoneOpenDialTimeout = 10 * time.Second

// handlePhoneOpen обрабатывает OPEN от телефона. Ошибки протокола потока
// (битый payload) НЕ рвут сессию — стриму уходит вежливый отказ.
func (s *Session) handlePhoneOpen(f *Frame) error {
	atyp, addr, port, err := DecodeOpen(f.Payload)
	if err != nil {
		// битый payload — не нарушение синхронизации кадр-потока;
		// вежливый отказ (ERR_BAD_ADDRESS), сессия живёт.
		s.writeAsync(&Frame{Type: TypeOpenOK, StreamID: f.StreamID, Payload: EncodeOpenOK(3)})
		return nil
	}
	d := DialRequest{ATYP: atyp, Addr: addr, Port: port}

	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return ErrClosed
	}
	// гейты ДО диала: конфиг-флаг, лимит стримов, бюджет outstand.
	if !s.cfg.PhoneOpenAllowed {
		s.writeAsync(&Frame{Type: TypeOpenOK, StreamID: f.StreamID, Payload: EncodeOpenOK(1)})
		return nil
	}
	s.mu.Lock()
	tooMany := len(s.streams) >= s.cfg.MaxStreams
	noBudget := s.outstand >= s.cfg.Budget
	s.mu.Unlock()
	if tooMany {
		s.writeAsync(&Frame{Type: TypeOpenOK, StreamID: f.StreamID, Payload: EncodeOpenOK(8)})
		return nil
	}
	if noBudget {
		s.writeAsync(&Frame{Type: TypeOpenOK, StreamID: f.StreamID, Payload: EncodeOpenOK(1)})
		return nil
	}

	conn, err := net.DialTimeout("tcp", d.String(), phoneOpenDialTimeout)
	if err != nil {
		s.writeAsync(&Frame{Type: TypeOpenOK, StreamID: f.StreamID, Payload: EncodeOpenOK(4)})
		return nil
	}

	// регистрация стрима: id ЧЁТНЫЙ от телефона, nextID (нечётный) не трогаем.
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		conn.Close()
		return ErrClosed
	}
	if len(s.streams) >= s.cfg.MaxStreams { // гонка с другими open'ами
		s.mu.Unlock()
		conn.Close()
		s.writeAsync(&Frame{Type: TypeOpenOK, StreamID: f.StreamID, Payload: EncodeOpenOK(8)})
		return nil
	}
	st := newStream(s, f.StreamID, d)
	s.streams[f.StreamID] = st
	s.mu.Unlock()
	s.writeAsync(&Frame{Type: TypeOpenOK, StreamID: f.StreamID, Payload: EncodeOpenOK(0)})

	// релей. цель → телефон: io.Copy(st, conn) — stream.Write канонно ведёт
	// окна/outstand. телефон → цель: pushIn (TypeData) наполняет буфер стрима,
	// io.Copy(conn, st) потребляет его. Оба конца закрываются симметрично:
	// EOF цели → Close телефону; Close телефона → markClosed → conn закрыт.
	go func() {
		defer conn.Close()
		go func() {
			_, _ = io.Copy(st, conn)
			// EOF/ошибка цели — штатное закрытие стрима в сторону телефона
			s.writeAsync(&Frame{Type: TypeClose, StreamID: st.id, Payload: EncodeClose(0)})
			st.markClosed(0)
		}()
		_, _ = io.Copy(conn, st)
		// телефон закрыл стрим (или сессия) — гасим цель
		conn.Close()
	}()
	return nil
}
