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

	// v1.9.8 Buffer/2 (docs/spec/ack.md): LEDGER-снимок старого стрима.
	// replay — неподтверждённый c→p хвост (оффсеты от replayBase); при RESUME
	// телефон присылает K (потреблено), лишняя голова срезается, остаток
	// дозылается в НОВЫЙ стрим через stream.Write (LEDGER продолжается).
	// delivered — кумулятивно доставлено браузеру p→c: база стартового
	// TypeAck resumed-стрима (телефон досылает p→c ровно с неё).
	replayBase uint64
	replay     [][]byte
	delivered  uint64

	Done chan struct{} // закрыт при окончательном закрытии паркинга
}

// New паркует стрим. v1.9.8 Buffer/2: snap — LEDGER-снимок старого стрима
// (rrp.ResumeSnapshot; нулевой — старое поведение без ack-режима).
func New(device string, token [16]byte, dst rrp.DialRequest, conn net.Conn, transport string, snap rrp.ResumeSnapshot) *Parked {
	return &Parked{
		Device:     device,
		Token:      token,
		Dst:        dst,
		Conn:       conn,
		buf:        buf.New(),
		Transport:  transport,
		ParkedAt:   time.Now(),
		Done:       make(chan struct{}),
		replayBase: snap.Base,
		replay:     snap.Chunks,
		delivered:  snap.Delivered,
	}
}

// Delivered — кумулятивно доставлено браузеру p→c до смерти (база стартового ACK).
func (p *Parked) Delivered() uint64 { return p.delivered }

// Feed добавляет байты c→p в буфер (bounded, MODE_BLOCK). Блокируется при
// переполнении — так TCP-давление доходит до браузера и ни один байт не
// теряется. false — паркинг закрыт (TTL/resume fail) или запись в живой
// стрим не удалась.
func (p *Parked) Feed(b []byte) bool {
	return p.buf.Push(b)
}

// Resume подключает новый rrp-стрим: досылает LEDGER-хвост (Buffer/2), затем
// буфер (FIFO Buffer/1), переключает режим на живой путь; downstream:
// io.Copy стрим → браузер. Upstream продолжает вести pump-горутина релея
// (Feed при resume пишет напрямую в стрим) — второй читатель Conn здесь
// недопустим (иначе данные расщепляются между двумя читателями).
func (p *Parked) Resume(st net.Conn) error {
	if p.buf.Closed() {
		return errors.New("park: closed")
	}
	// v1.9.8 Buffer/2: досыл LEDGER старого стрима ДО буфера (порядок!).
	// K — телефонное потребление c→p (расширенный OPEN_OK); подтверждённая
	// голова replay срезается, остаток уходит через stream.Write — LEDGER
	// нового стрима продолжает нумерацию с K, телефонное окно и ACK работают
	// дальше как для живого трафика.
	if len(p.replay) > 0 {
		k := uint64(0)
		if rk, ok := st.(interface{ ResumeK() (uint64, bool) }); ok {
			if kk, ok2 := rk.ResumeK(); ok2 {
				k = kk
			}
		}
		for _, c := range buf.ReplayFilter(p.replayBase, k, p.replay) {
			if _, err := st.Write(c); err != nil {
				_ = st.Close()
				p.Close()
				return errors.New("park: ledger replay: " + err.Error())
			}
		}
	}
	// FIFO+live идут через streamLedgerWriter: stream.Write назначает оффсеты
	// LEDGER (продолжение нумерации) — досыл и новый трафик одинаково
	// подтверждаемы. Ошибка записи (снова смерть транспорта) закрывает буфер.
	if err := p.buf.Attach(streamLedgerWriter{st: st}); err != nil {
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

// streamLedgerWriter — маршрутизирует FIFO/live c→p через stream.Write:
// LEDGER-нумерация продолжается, байты подтверждаемы WINDOW'ами телефона.
type streamLedgerWriter struct{ st net.Conn }

func (w streamLedgerWriter) Write(b []byte) (int, error) { return w.st.Write(b) }

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
