// v1.9.0: зона релея вынесена из mixed.go (транш-2): half-close relay,
// stream-relay с resume-паркингом (v1.3.0 «буфер трафика»).

package inbound

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/stelgen/reverseray/server/internal/park"
	"github.com/stelgen/reverseray/server/internal/rrp"
)

func relayHalf(a, b net.Conn) error {
	done := make(chan error, 2)
	go func() { _, err := io.Copy(b, a); done <- err }()
	go func() { _, err := io.Copy(a, b); done <- err }()
	err1 := <-done
	_ = b.SetDeadline(time.Now())
	_ = a.SetDeadline(time.Now())
	err2 := <-done
	if err1 != nil && err1 != io.EOF {
		return err1
	}
	if err2 != nil && err2 != io.EOF {
		return err2
	}
	return nil
}

// resumeInfoer — доступ к токену резюме rrp-стрима (v1.3.0).
type resumeInfoer interface {
	ResumeInfo() (token [16]byte, dst rrp.DialRequest, device string, ok bool)
}

// relayStream — релей CONNECT-пути с «буфером трафика» (v1.3.0):
// при смерти туннеля (StreamError code 1) браузерная сторона НЕ закрывается —
// стрим паркуется в hub-буфере; телефон при реконнекте привязывает свой сокет
// заново (OPEN_RESUME), буфер c→p дозылается. Обе TCP-стороны переживают
// блып туннеля end-to-end, ни один байт не дропается (при переполнении
// буфера — TCP backpressure). Без паркинга — прежнее поведение relayHalf.
func (in *Inbound) relayStream(c, dst net.Conn) bool {
	var ps atomic.Pointer[park.Parked]
	done := make(chan error, 2)

	// downstream: rrp-стрим → браузер.
	go func() {
		_, err := io.Copy(c, dst)
		if err != nil {
			var se *rrp.StreamError
			if errors.As(err, &se) && se.Code == 1 && in.Parker != nil {
				if ri, ok := dst.(resumeInfoer); ok {
					if token, d, device, ok2 := ri.ResumeInfo(); ok2 {
						p := park.New(device, token, d, c, "")
						if in.Parker.Park(p) {
							ps.Store(p)
							done <- nil // владение c передано буферу — не закрываем
							return
						}
					}
				}
			}
		}
		done <- err
	}()

	// upstream: браузер → rrp-стрим; после паркинга — дозапись в буфер (pump).
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := c.Read(buf)
			if err != nil {
				if ps.Load() == nil {
					done <- err // паркинга нет — штатное завершение
				}
				return // c принадлежит буферу — не закрываем
			}
			p := ps.Load()
			wn := 0
			if p == nil {
				var werr error
				wn, werr = dst.Write(buf[:n])
				if werr == nil {
					continue
				}
				var se *rrp.StreamError
				if !(errors.As(werr, &se) && se.Code == 1) || in.Parker == nil {
					done <- werr
					return
				}
				if ri, ok := dst.(resumeInfoer); ok {
					if token, d, device, ok2 := ri.ResumeInfo(); ok2 {
						np := park.New(device, token, d, c, "")
						if in.Parker.Park(np) {
							ps.Store(np)
							p = np
						}
					}
				}
				if p == nil {
					// Паркинг мог выиграть downstream (дубликат токена) — он
					// уже сохранил ps: продолжаем как pump буфера, а не выходим.
					p = ps.Load()
				}
				if p == nil {
					done <- werr
					return // паркинг не удался — релей завершается
				}
			}
			// Буфер: досылаем непроханные байты. Feed блокируется при
			// переполнении (TCP backpressure) и НЕ дропает данные.
			if !p.Feed(buf[wn:n]) {
				return // буфер закрыт (TTL/резюме не удалось) — c закрыт им же
			}
		}
	}()

	if err := <-done; err != nil {
		in.logf("pump exit: %v", err)
	}
	if ps.Load() != nil {
		// Паркинг состоялся: вторая горутина живёт как pump буфера, владение
		// c у него — не ждём и не закрываем.
		return true
	}
	_ = dst.Close()
	_ = c.Close()
	if err := <-done; err != nil {
		in.logf("second pump exit: %v", err)
	}
	return false
}
