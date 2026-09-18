package rrp

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

// pipeConn adapts net.Pipe ends into ReadWriteCloser for session tests.
type pipeConn struct{ net.Conn }

func (p pipeConn) Close() error { return p.Conn.Close() }

func TestSessionOpenDataClose(t *testing.T) {
	c1, c2 := net.Pipe()
	sess := NewSession("s1", "dev", pipeConn{c1}, DefaultSessionConfig())
	go sess.Run()

	// Fake phone on the other end.
	go func() {
		for {
			f, err := ReadFrame(c2)
			if err != nil {
				return
			}
			switch f.Type {
			case TypeOpen:
				// accept every dial
				WriteFrame(c2, TypeOpenOK, 0, f.StreamID, []byte{0})
			case TypeData:
				// echo back
				WriteFrame(c2, TypeData, 0, f.StreamID, f.Payload)
			case TypePing:
				WriteFrame(c2, TypePong, 0, 0, f.Payload)
			}
		}
	}()

	st, err := sess.Open(context.Background(), DialRequest{ATYP: ATYPDomain, Addr: []byte("example.com"), Port: 443})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	msg := []byte("hello through the tunnel")
	if _, err := st.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch %q", buf)
	}
	_ = st.Close()
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSessionOpenRejected(t *testing.T) {
	c1, c2 := net.Pipe()
	sess := NewSession("s1", "dev", pipeConn{c1}, DefaultSessionConfig())
	go sess.Run()
	go func() {
		for {
			f, err := ReadFrame(c2)
			if err != nil {
				return
			}
			if f.Type == TypeOpen {
				WriteFrame(c2, TypeOpenOK, 0, f.StreamID, []byte{1}) // dial failed
			}
		}
	}()
	_, err := sess.Open(context.Background(), DialRequest{ATYP: ATYPDomain, Addr: []byte("blocked.example"), Port: 80})
	if err == nil {
		t.Fatal("expected dial failure")
	}
}

func TestSessionPeerErrorCloses(t *testing.T) {
	c1, c2 := net.Pipe()
	sess := NewSession("s1", "dev", pipeConn{c1}, DefaultSessionConfig())
	go sess.Run()
	WriteFrame(c2, TypeError, 0, 0, EncodeError(9, "bye"))
	select {
	case <-sess.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("session must close on peer ERROR")
	}
}

func TestSessionProtocolOrder(t *testing.T) {
	c1, c2 := net.Pipe()
	sess := NewSession("s1", "dev", pipeConn{c1}, DefaultSessionConfig())
	go sess.Run()
	hb, _ := json.Marshal(&Hello{Agent: "x", Device: "d"})
	WriteFrame(c2, TypeHello, 0, 0, hb)
	select {
	case <-sess.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("HELLO after ready must terminate session")
	}
}
