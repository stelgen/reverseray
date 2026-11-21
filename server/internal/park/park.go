// Package park — v1.3.0 «буфер трафика»: паркинг живых стримов при потере
// туннеля. TCP-сокеты обеих сторон НЕ закрываются: браузер держит соединение,
// телефон держит сокет до таргета, поток управления (SITE↔phone) восстановится
// end-to-end средствами TCP (ретрансмиссии с обеих сторон). Данные c→p,
// прочитанные relay'ем в момент смерти туннеля, буферизуются в оперативке
// (bounded, без дропа: при переполнении — TCP backpressure) и досылаются
// после RESUME. Смена протокола на очереди не влияет: конверт меняется
// внутри живой сессии, стримы и паркинг не затрагиваются.
//
// v1.9.6: ядро буфера вынесено в internal/buf (канон Buffer/1,
// docs/spec/buffer.md) — единая семантика с клиентским зеркалом
// core/RrpStreamBuffer.kt; park остаётся точкой интеграции.
package park

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/stelgen/reverseray/server/internal/buf"
	"github.com/stelgen/reverseray/server/internal/rrp"
)

// Parked — запаркованный стрим: браузерная сторона + цель + токен резюме.
type Parked struct {
	Device string
	Token  [16]byte
	Dst    rrp.DialRequest
	Conn   net.Conn

	buf       *buf.Buffer // канон Buffer/1: bounded FIFO c→p (MODE_BLOCK)
	once      sync.Once   // идемпотентность Close
	stMu      sync.Mutex
	st        net.Conn // возобновлённый rrp-стрим (после Resume)
	ParkedAt  time.Time
	Transport string // proto сессии, в которой жил стрим (для телеметрии)

	Done chan struct{} // закрыт при окончательном закрытии паркинга
}

func New(device string, token [16]byte, dst rrp.DialRequest, conn net.Conn, transport string) *Parked {
	return &Parked{
		Device:    device,
		Token:     token,
		Dst:       dst,
		Conn:      conn,
		buf:       buf.New(),
		Transport: transport,
		ParkedAt:  time.Now(),
		Done:      make(chan struct{}),
	}
}

// Feed добавляет байты c→p в буфер (bounded, MODE_BLOCK). Блокируется при
// переполнении — так TCP-давление доходит до браузера и ни один байт не
// теряется. false — паркинг закрыт (TTL/resume fail) или запись в живой
// стрим не удалась.
func (p *Parked) Feed(b []byte) bool {
	return p.buf.Push(b)
}

// Resume подключает новый rrp-стрим: досылает буфер (FIFO), переключает
// режим на живой путь; downstream: io.Copy стрим → браузер. Upstream
// продолжает вести pump-горутина релея (Feed при resume пишет напрямую в
// стрим) — второй читатель Conn здесь недопустим (иначе данные расщепляются
// между двумя читателями).
func (p *Parked) Resume(st net.Conn) error {
	if p.buf.Closed() {
		return errors.New("park: closed")
	}
	if err := p.buf.Attach(st); err != nil {
		_ = st.Close()
		p.Close()
		return err
	}
	p.stMu.Lock()
	p.st = st
	p.stMu.Unlock()
	go func() {
		_, _ = io.Copy(p.Conn, st)
		p.Close()
	}()
	return nil
}

// PendingLen — байтов в буфере c→p (диагностика/телеметрия).
func (p *Parked) PendingLen() int {
	return p.buf.Len()
}

func (p *Parked) Resumed() bool {
	return p.buf.Live()
}

func (p *Parked) Close() {
	p.once.Do(func() {
		p.buf.Close()
		p.stMu.Lock()
		st := p.st
		p.st = nil
		p.stMu.Unlock()
		if p.Conn != nil {
			_ = p.Conn.Close()
		}
		if st != nil {
			_ = st.Close()
		}
		close(p.Done)
	})
}

// Sink — приёмник паркинга (реализует hub.Hub): только приём; изъятие
// (резюме/TTL) выполняет hub внутри своего устройства.
type Sink interface {
	Park(p *Parked) bool
}
