// wire_wrapper.go — зона «Wrapper: framed-транспорт с MTProto-конвертом» — pure move из wire.go (v1.8.3, дробление по зонам; поведение не меняется).
package mtproto

import (
	"bytes"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

type wrapper struct {
	inner  io.ReadWriteCloser
	sc     *SessionCrypto
	server bool // true — серверная сторона (шифруем x=8, расшифровываем x=0)

	wmu  sync.Mutex
	wbuf []byte

	rmu  sync.Mutex
	rbuf []byte
}

func newWrapper(inner io.ReadWriteCloser, sc *SessionCrypto, server bool) io.ReadWriteCloser {
	return &wrapper{inner: inner, sc: sc, server: server}
}

func isPayloadFrame(t uint8) bool { return t == rrp.TypeData || t == rrp.TypeUdpData }

// Write принимает сериализованные кадры (WriteFrame пишет заголовок и
// payload отдельными вызовами) — буферизуем и перепаковываем целиком.
func (w *wrapper) Write(p []byte) (int, error) {
	w.wmu.Lock()
	w.wbuf = append(w.wbuf, p...)
	written := len(p)
	var ferr error
	for {
		f, rest, ok := parseBufferedFrame(w.wbuf)
		if !ok {
			break
		}
		w.wbuf = rest
		if err := w.emit(f); err != nil {
			ferr = err
			break
		}
	}
	w.wmu.Unlock()
	if ferr != nil {
		return 0, ferr
	}
	return written, nil
}

// parseBufferedFrame — аккуратный парсер кадров из буфера записи.
func parseBufferedFrame(buf []byte) (*rrp.Frame, []byte, bool) {
	if len(buf) < rrp.HeaderLen {
		return nil, nil, false
	}
	if buf[0] != rrp.Version1 {
		// протокол испорчен — такого не бывает от WriteFrame; сигнализируем
		// нулевой длиной кадра (emit вернёт ошибку через MaxPayloadFor)
		return nil, nil, false
	}
	t := buf[1]
	n := int(binary.BigEndian.Uint32(buf[8:12]))
	if n < 0 || n > rrp.MaxPayloadFor(t) {
		return nil, nil, false
	}
	total := rrp.HeaderLen + n
	if len(buf) < total {
		return nil, nil, false
	}
	f := &rrp.Frame{
		Type:     t,
		Flags:    binary.BigEndian.Uint16(buf[2:4]),
		StreamID: binary.BigEndian.Uint32(buf[4:8]),
		Payload:  append([]byte(nil), buf[rrp.HeaderLen:total]...),
	}
	return f, buf[total:], true
}

// emit — один кадр наружу: DATA/UDP_DATA в конверт, остальные — как есть.
// Большой DATA режется на чанки ≤ maxPlainData (поток DATA это позволяет);
// слишком большой UDP_DATA дропается (семантика UDP).
func (w *wrapper) emit(f *rrp.Frame) error {
	if w.sc == nil || !isPayloadFrame(f.Type) {
		return rrp.WriteFrame(w.inner, f.Type, f.Flags, f.StreamID, f.Payload)
	}
	if f.Type == rrp.TypeUdpData {
		if len(f.Payload) > maxPlainData {
			return nil // дроп, UDP — без гарантий
		}
		env, err := w.encryptPayload(f.Payload)
		if err != nil {
			return err
		}
		return rrp.WriteFrame(w.inner, f.Type, f.Flags, f.StreamID, env)
	}
	// DATA: разрезаем на чанки
	payload := f.Payload
	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > maxPlainData {
			chunk = chunk[:maxPlainData]
		}
		payload = payload[len(chunk):]
		env, err := w.encryptPayload(chunk)
		if err != nil {
			return err
		}
		if err := rrp.WriteFrame(w.inner, f.Type, f.Flags, f.StreamID, env); err != nil {
			return err
		}
	}
	return nil
}

func (w *wrapper) encryptPayload(payload []byte) ([]byte, error) {
	if w.server {
		return w.sc.EncryptUp(payload)
	}
	return w.sc.EncryptDown(payload)
}

func (w *wrapper) Read(p []byte) (int, error) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	for len(w.rbuf) == 0 {
		f, err := rrp.ReadFrame(w.inner)
		if err != nil {
			return 0, err
		}
		if w.sc != nil && isPayloadFrame(f.Type) {
			var plain []byte
			if w.server {
				plain, err = w.sc.DecryptDown(f.Payload)
			} else {
				plain, err = w.sc.DecryptUp(f.Payload)
			}
			if err != nil {
				return 0, err
			}
			f.Payload = plain
		}
		var buf bytes.Buffer
		if err := rrp.WriteFrame(&buf, f.Type, f.Flags, f.StreamID, f.Payload); err != nil {
			return 0, err
		}
		w.rbuf = append(w.rbuf, buf.Bytes()...)
	}
	n := copy(p, w.rbuf)
	w.rbuf = w.rbuf[n:]
	return n, nil
}

func (w *wrapper) Close() error { return w.inner.Close() }

// SetReadDeadline/SetWriteDeadline делегируются (сессия ставит idle-таймаут).
func (w *wrapper) SetReadDeadline(t time.Time) error {
	type d interface{ SetReadDeadline(time.Time) error }
	if ds, ok := w.inner.(d); ok {
		return ds.SetReadDeadline(t)
	}
	return nil
}

func (w *wrapper) SetWriteDeadline(t time.Time) error {
	type d interface{ SetWriteDeadline(time.Time) error }
	if ds, ok := w.inner.(d); ok {
		return ds.SetWriteDeadline(t)
	}
	return nil
}
