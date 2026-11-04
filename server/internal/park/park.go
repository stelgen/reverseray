// Package park — v1.3.0 «буфер трафика»: паркинг живых стримов при потере
// туннеля. TCP-сокеты обеих сторон НЕ закрываются: браузер держит соединение,
// телефон держит сокет до таргета, поток управления (SITE↔phone) восстановится
// end-to-end средствами TCP (ретрансмиссии с обеих сторон). Данные c→p,
// прочитанные relay'ем в момент смерти туннеля, буферизуются в оперативке
// (bounded, без дропа: при переполнении — TCP backpressure) и досылаются
// после RESUME. Смена протокола на очереди не влияет: конверт меняется
// внутри живой сессии, стримы и паркинг не затрагиваются.
package park

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

// PendingCap — верхняя граница буфера c→p на стрим. При превышении Feed
// блокируется (TCP backpressure к браузеру) — данные не дропаются никогда.
const PendingCap = 256 * 1024

// Parked — запаркованный стрим: браузерная сторона + цель + токен резюме.
type Parked struct {
	Device string
	Token  [16]byte
	Dst    rrp.DialRequest
	Conn   net.Conn

	mu        sync.Mutex
	cond      *sync.Cond
	pending   [][]byte
	pendingN  int
	st        net.Conn // resumed rrp-стрим (после Resume)
	closed    bool
	ParkedAt  time.Time
	Transport string // proto сессии, в которой жил стрим (для телеметрии)

	Done chan struct{} // закрыт при окончательном закрытии паркинга
}

func New(device string, token [16]byte, dst rrp.DialRequest, conn net.Conn, transport string) *Parked {
	p := &Parked{
		Device:    device,
		Token:     token,
		Dst:       dst,
		Conn:      conn,
		Transport: transport,
		ParkedAt:  time.Now(),
		Done:      make(chan struct{}),
	}
	p.cond = sync.NewCond(&p.mu)
	return p
}

// Feed добавляет байты c→p в буфер (bounded). Блокируется при переполнении —
// так TCP-давление доходит до браузера и ни один байт не теряется.
// false — паркинг закрыт (TTL/resume fail), данных больше не принимаем.
func (p *Parked) Feed(b []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for !p.closed && p.pendingN+len(b) > PendingCap && p.st == nil {
		p.cond.Wait()
	}
	if p.closed {
		return false
	}
	if p.st != nil {
		p.mu.Unlock()
		_, err := p.st.Write(b)
		p.mu.Lock()
		return err == nil
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	p.pending = append(p.pending, cp)
	p.pendingN += len(cp)
	return true
}

// Resume подключает новый rrp-стрим: досылает буфер, переключает режим.
func (p *Parked) Resume(st net.Conn) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return errors.New("park: closed")
	}
	for _, b := range p.pending {
		if _, err := st.Write(b); err != nil {
			p.pending = nil
			p.pendingN = 0
			p.mu.Unlock()
			_ = st.Close()
			p.closeLocked()
			return err
		}
	}
	p.pending = nil
	p.pendingN = 0
	p.st = st
	p.cond.Broadcast()
	p.mu.Unlock()
	// downstream: новый стрим → браузер. Upstream продолжает вести pump-горутина
	// релея (Feed при resume пишет напрямую в st) — второй читатель Conn здесь
	// недопустим (иначе данные расщепляются между двумя читателями).
	go func() {
		_, _ = io.Copy(p.Conn, st)
		p.Close()
	}()
	return nil
}

// PendingLen — байтов в буфере c→p (диагностика/телеметрия).
func (p *Parked) PendingLen() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pendingN
}

func (p *Parked) Resumed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.st != nil
}

func (p *Parked) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeLocked()
}

func (p *Parked) closeLocked() {
	if p.closed {
		return
	}
	p.closed = true
	p.cond.Broadcast()
	if p.Conn != nil {
		_ = p.Conn.Close()
	}
	if p.st != nil {
		_ = p.st.Close()
	}
	close(p.Done)
}

// Sink — приёмник паркинга (реализует hub.Hub): только приём; изъятие
// (резюме/TTL) выполняет hub внутри своего устройства.
type Sink interface {
	Park(p *Parked) bool
}
