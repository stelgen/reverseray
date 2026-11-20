package rrp

import (
	"container/list"
	crand "crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ResumeInfo (v1.3.0 «буфер трафика») — токен/цель/устройство для паркинга.
func (st *stream) ResumeInfo() (token [16]byte, dst DialRequest, device string, ok bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.hasToken {
		return token, dst, "", false
	}
	return st.token, st.dst, st.sess.Device, true
}

type stream struct {
	sess *Session
	id   uint32
	dst  DialRequest

	mu     sync.Mutex
	cond   *sync.Cond
	inQ    [][]byte
	inLen  int
	closed bool
	cerr   uint8

	tokens chan struct{}
	winSz  uint32
	// v1.3.0: текущее разрешённое окно телефона на отправку (download).
	// Стартует с initialGrant (= TunnelWindow, что реально у телефона) и растёт
	// BDP-автотюнингом до MaxStreamWin, пока потребитель осушает буфер.
	grant int64

	// v1.3.0 «буфер трафика»: токен резюме — привязка телефонного сокета.
	token    [16]byte
	hasToken bool
}

type errOpen uint8

func (e errOpen) Error() string { return fmt.Sprintf("phone dial failed: code %d", uint8(e)) }

// StreamError — типизированное закрытие стрима: код 1 = транспорт/сессия умер
// (триггер паркинга «буфера трафика»), 0 = штатное закрытие, остальное — ошибки.
type StreamError struct{ Code uint8 }

func (e *StreamError) Error() string { return fmt.Sprintf("stream closed: code %d", e.Code) }

func openResultErr(code uint8) error {
	if code == 0 {
		return nil
	}
	return errOpen(code)
}

func (f *Frame) closeCode() uint8 {
	if len(f.Payload) == 1 {
		return f.Payload[0]
	}
	return 1
}

func newStream(s *Session, id uint32, d DialRequest) *stream {
	st := &stream{
		sess:   s,
		id:     id,
		dst:    d,
		winSz:  s.cfg.StreamWindow,
		tokens: make(chan struct{}, s.cfg.MaxStreamWin),
		grant:  s.cfg.initialGrant(),
	}
	if s.cfg.ResumeCapable {
		_, _ = crand.Read(st.token[:])
		st.hasToken = true
	}
	st.cond = sync.NewCond(&st.mu)
	for i := uint32(0); i < s.cfg.StreamWindow/1024; i++ {
		st.tokens <- struct{}{}
	}
	return st
}

func (st *stream) pushIn(b []byte) {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return
	}
	// v1.2.0: буфер обязан вместить текущее окно (autotune поднимает его выше
	// стартового), минимум — прежний анти-абьюз 1 МБ; агрегат по устройству
	// ограничен grantedTotal ≤ Budget.
	bufCap := max(int(st.grant), 1<<20)
	if st.inLen+len(b) > bufCap {
		st.mu.Unlock()
		st.sess.writeAsync(&Frame{Type: TypeClose, StreamID: st.id, Payload: EncodeClose(4)})
		st.markClosed(4)
		return
	}
	// v1.2.0: DATA от телефона = in-flight байты. Раньше инкремента не было,
	// а Read декрементил → outstand уезжал в минус (−469 МБ на живой сессии)
	// и бюджет устройства не защищал память.
	// Примечание: грант НЕ спускается при заторе — кредиты WINDOW в протоколе
	// неотзывные, а грант = фактически выданные телефону пермиты; буфер всегда
	// вмещает грант, поэтому честный телефон никогда не ловит kill(4).
	// Память ограничена агрегатно: grantedTotal ≤ Budget.
	st.sess.mu.Lock()
	st.sess.outstand += int64(len(b))
	st.sess.mu.Unlock()
	cp := append([]byte(nil), b...)
	st.inQ = append(st.inQ, cp)
	st.inLen += len(cp)
	st.cond.Broadcast()
	st.mu.Unlock()
}

func (st *stream) markClosed(code uint8) {
	st.mu.Lock()
	if !st.closed {
		st.closed = true
		st.cerr = code
		// v1.2.0: вернуть autotune-прирост окна в общий бюджет устройства.
		if floor := int64(st.sess.cfg.initialGrant()); st.grant > floor {
			ex := st.grant - floor
			st.grant = floor
			st.sess.mu.Lock()
			st.sess.grantedTotal -= ex
			st.sess.mu.Unlock()
		}
	}
	st.cond.Broadcast()
	st.mu.Unlock()
}

// refill returns consumed window to the phone (WINDOW increments).
func (st *stream) refill(n uint32) {
	for i := uint32(0); i < n/1024 && i < st.winSz/1024; i++ {
		select {
		case st.tokens <- struct{}{}:
		default:
			return
		}
	}
}

func (st *stream) Read(p []byte) (int, error) {
	st.mu.Lock()
	for st.inLen == 0 && !st.closed {
		st.cond.Wait()
	}
	if st.inLen == 0 && st.closed {
		st.mu.Unlock()
		if st.cerr != 0 && st.cerr != 1 {
			return 0, &StreamError{Code: st.cerr}
		}
		if st.cerr == 1 {
			return 0, &StreamError{Code: 1}
		}
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && len(st.inQ) > 0 {
		chunk := st.inQ[0]
		c := copy(p[n:], chunk)
		n += c
		if c == len(chunk) {
			st.inQ = st.inQ[1:]
		} else {
			st.inQ[0] = chunk[c:]
		}
		st.inLen -= c
		st.sess.mu.Lock()
		st.sess.outstand -= int64(c)
		st.sess.mu.Unlock()
	}
	// v1.2.0 BDP-автотюнинг: потребитель осушил буфер целиком → выдаём телефону
	// дополнительное окно пропорционально темпу потребления (≤n за раунд).
	// Потолок — MaxStreamWin, агрегат по устройству — Budget (grantedTotal).
	// Это снимает потолок throughput = окно/RTT: при RTT мобильной сети 300–600мс
	// стартовое окно 1МБ давало лишь ~14–27 Мбит/с; рост до 4МБ поднимает
	// потолок до ~57 Мбит/с (и выше при меньшем RTT).
	grow := int64(0)
	if n > 0 && st.inLen == 0 && !st.closed {
		if room := int64(st.sess.cfg.MaxStreamWin) - st.grant; room > 0 {
			grow = min(int64(n), room)
			st.sess.mu.Lock()
			if st.sess.grantedTotal+grow > st.sess.cfg.Budget {
				grow = max(st.sess.cfg.Budget-st.sess.grantedTotal, 0)
			}
			st.sess.grantedTotal += grow
			st.sess.windowGrow += uint64(grow)
			st.grant += grow
			st.sess.mu.Unlock()
		}
	}
	st.mu.Unlock()
	if n > 0 || grow > 0 {
		st.sess.writeAsync(&Frame{Type: TypeWindow, StreamID: st.id, Payload: EncodeWindow(uint32(int64(n) + grow))})
	}
	return n, nil
}

func (st *stream) Write(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		select {
		case <-st.tokens:
		case <-st.sess.Done():
			return total, &StreamError{Code: 1} // v1.3.0: транспорт умер — паркинг
		}
		st.mu.Lock()
		closed, code := st.closed, st.cerr
		st.mu.Unlock()
		if closed {
			// v1.3.0: типизированная ошибка — relay «буфера трафика» различает
			// смерть транспорта (code 1 → паркинг) от прочих закрытий.
			return total, &StreamError{Code: code}
		}
		chunk := p[total:]
		if len(chunk) > MaxDataPayload {
			chunk = chunk[:MaxDataPayload]
		}
		errc := make(chan error, 1)
		st.sess.outq <- outItem{
			frame: &Frame{Type: TypeData, StreamID: st.id, Payload: append([]byte(nil), chunk...)},
			err:   errc,
		}
		if err := <-errc; err != nil {
			return total, err
		}
		st.sess.mu.Lock()
		st.sess.outstand += int64(len(chunk))
		st.sess.bout += uint64(len(chunk))
		st.sess.mu.Unlock()
		total += len(chunk)
	}
	return total, nil
}

func (st *stream) Close() error {
	st.markClosed(0)
	st.sess.writeAsync(&Frame{Type: TypeClose, StreamID: st.id, Payload: EncodeClose(0)})
	st.sess.dropStream(st.id)
	return nil
}

func (st *stream) LocalAddr() net.Addr  { return addrString("rrp-stream") }
func (st *stream) RemoteAddr() net.Addr { return addrString(st.dst.String()) }
func (st *stream) SetDeadline(t time.Time) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	// Best-effort: wake readers on deadline.
	if !t.IsZero() {
		time.AfterFunc(time.Until(t), st.cond.Broadcast)
	}
	return nil
}
func (st *stream) SetReadDeadline(t time.Time) error  { return st.SetDeadline(t) }
func (st *stream) SetWriteDeadline(t time.Time) error { return nil }

type addrString string

func (a addrString) Network() string { return "rrp" }
func (a addrString) String() string  { return string(a) }

func listPush(l *list.List, v Stats) *list.List {
	if l == nil {
		l = list.New()
	}
	l.PushBack(v)
	for l.Len() > 32 {
		l.Remove(l.Front())
	}
	return l
}
