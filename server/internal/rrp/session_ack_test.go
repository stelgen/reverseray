package rrp

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// v1.9.8 Buffer/2: интеграционные тесты ACK-режима (кумулятивный ACK,
// LEDGER, фильтр дублей, replay при RESUME). Телефон — фейковый, поверх net.Pipe.

func newAckSession(t *testing.T, c1 net.Conn, c2 net.Conn) *Session {
	t.Helper()
	cfg := DefaultSessionConfig()
	cfg.AckCapable = true
	sess := NewSession("s1", "dev", pipeConn{c1}, cfg)
	go sess.Run()
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

func sendAckData(t *testing.T, c2 net.Conn, id uint32, off uint64, chunk []byte) {
	t.Helper()
	if err := WriteFrame(c2, TypeData, 0, id, EncodeDataOffset(off, chunk)); err != nil {
		t.Fatalf("send data off=%d: %v", off, err)
	}
}

// TestAckDupFilterStraddle: телефон (реплей после «обрыва») шлёт чанки с
// оффсетами, включая дубль начала и straddle-чанк, перекрывающий границу.
// Сервер обязан доставить ровно AAABBCCCC — без дублей и дыр.
func TestAckDupFilterStraddle(t *testing.T) {
	c1, c2 := net.Pipe()
	sess := newAckSession(t, c1, c2)

	go func() {
		for {
			f, err := ReadFrame(c2)
			if err != nil {
				return
			}
			switch f.Type {
			case TypeOpen:
				_ = WriteFrame(c2, TypeOpenOK, 0, f.StreamID, []byte{0})
			case TypePing:
				_ = WriteFrame(c2, TypePong, 0, 0, f.Payload)
			}
		}
	}()

	st, err := sess.Open(context.Background(), DialRequest{ATYP: ATYPDomain, Addr: []byte("example.com"), Port: 443})
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	sendAckData(t, c2, st.(*stream).id, 0, []byte("AAA"))
	sendAckData(t, c2, st.(*stream).id, 0, []byte("AAA")) // дубль — скип
	sendAckData(t, c2, st.(*stream).id, 3, []byte("BB"))
	sendAckData(t, c2, st.(*stream).id, 4, []byte("XCCCC")) // straddle: X дропается, CCC+1 доставляется

	want := "AAABBCCCC"
	buf := make([]byte, len(want))
	_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != want {
		t.Fatalf("dup filter: want %q, got %q", want, buf)
	}
}

// TestAckEmissionAfterBatch: после 16КиБ доставленных байт сервер шлёт
// кумулятивный TypeAck с границей доставленного.
func TestAckEmissionAfterBatch(t *testing.T) {
	c1, c2 := net.Pipe()
	sess := newAckSession(t, c1, c2)

	acks := make(chan uint64, 4)
	go func() {
		for {
			f, err := ReadFrame(c2)
			if err != nil {
				return
			}
			switch f.Type {
			case TypeOpen:
				_ = WriteFrame(c2, TypeOpenOK, 0, f.StreamID, []byte{0})
			case TypeAck:
				off, _, err := SplitDataOffset(f.Payload)
				if err == nil {
					acks <- off
				}
			case TypePing:
				_ = WriteFrame(c2, TypePong, 0, 0, f.Payload)
			}
		}
	}()

	st, err := sess.Open(context.Background(), DialRequest{ATYP: ATYPDomain, Addr: []byte("example.com"), Port: 443})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	sid := st.(*stream).id

	big := bytes.Repeat([]byte("x"), ackBatchMin)
	sendAckData(t, c2, sid, 0, big)
	sendAckData(t, c2, sid, uint64(len(big)), []byte("yyyy"))

	buf := make([]byte, len(big)+4)
	_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	sel := time.NewTimer(5 * time.Second)
	defer sel.Stop()
	for last := uint64(0); ; {
		select {
		case off := <-acks:
			last = off
			if off == uint64(len(big)+4) {
				return // полная кумулятивная граница пришла — ок
			}
		case <-sel.C:
			t.Fatalf("ack boundary %d: want %d (последний off=%d)", len(big)+4, len(big)+4, last)
		}
	}
}

// TestAckResumeReplay: телефон ресюмит стрим (OPEN_OK с K=3) и реплеит
// уже подтверждённые/недоставленные чанки; сервер фильтрует по baseIn и
// доставляет только новые байты.
func TestAckResumeReplay(t *testing.T) {
	c1, c2 := net.Pipe()
	sess := newAckSession(t, c1, c2)

	go func() {
		for {
			f, err := ReadFrame(c2)
			if err != nil {
				return
			}
			switch f.Type {
			case TypeOpenResume:
				// K=3: до «смерти» браузер получил 3 байта (AAA).
				_ = WriteFrame(c2, TypeOpenOK, 0, f.StreamID, EncodeResumedOpenOK(0, 3))
			case TypePing:
				_ = WriteFrame(c2, TypePong, 0, 0, f.Payload)
			}
		}
	}()

	token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	st, err := sess.OpenResume(context.Background(), token, DialRequest{ATYP: ATYPDomain, Addr: []byte("example.com"), Port: 443}, 3)
	if err != nil {
		t.Fatalf("openresume: %v", err)
	}

	// Реплей: off=0..2 (уже доставлено) — скип; off=3 "BBB" — доставляется.
	sendAckData(t, c2, st.(*stream).id, 0, []byte("AAA")) // end<=baseIn → дроп
	sendAckData(t, c2, st.(*stream).id, 3, []byte("BBB"))

	want := "BBB"
	buf := make([]byte, len(want))
	_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != want {
		t.Fatalf("replay: want %q, got %q", want, buf)
	}
	if k, hasK := st.(*stream).ResumeK(); !hasK || k != 3 {
		t.Fatalf("resume K: want 3/true, got %d/%v", k, hasK)
	}
}

// TestAckResumeFirstACK: после OPEN_OK(resume) сервер сразу шлёт стартовый
// TypeAck(baseIn) — телефон знает границу для eviction своего LEDGER'а.
func TestAckResumeFirstACK(t *testing.T) {
	c1, c2 := net.Pipe()
	sess := newAckSession(t, c1, c2)

	acks := make(chan uint64, 4)
	go func() {
		for {
			f, err := ReadFrame(c2)
			if err != nil {
				return
			}
			switch f.Type {
			case TypeOpenResume:
				_ = WriteFrame(c2, TypeOpenOK, 0, f.StreamID, EncodeResumedOpenOK(0, 7))
			case TypeAck:
				off, _, err := SplitDataOffset(f.Payload)
				if err == nil {
					acks <- off
				}
			case TypePing:
				_ = WriteFrame(c2, TypePong, 0, 0, f.Payload)
			}
		}
	}()

	token := [16]byte{9}
	st, err := sess.OpenResume(context.Background(), token, DialRequest{ATYP: ATYPDomain, Addr: []byte("example.com"), Port: 443}, 7)
	if err != nil {
		t.Fatalf("openresume: %v", err)
	}
	_ = st

	select {
	case off := <-acks:
		if off != 7 {
			t.Fatalf("first ack: want 7, got %d", off)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no starting TypeAck on resume")
	}
}
