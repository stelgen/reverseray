package rrp

import (
	"net"
	"testing"
	"time"
)

// DATA на неизвестный поток обязан получить защитный CLOSE (err != 0;
// сервер отвечает EncodeClose(2) = «unknown stream, stop»).
func TestSessionDataUnknownStreamClose(t *testing.T) {
	c1, c2 := net.Pipe()
	sess := NewSession("s1", "dev", pipeConn{c1}, DefaultSessionConfig())
	go sess.Run()
	defer sess.Close()

	// Со стороны «приложения» (c1) прилетает DATA на stream, которого нет.
	// Сессия обязана ответить CLOSE c err_code = 7 в сторону телефона (c2).
	hdr := make([]byte, 12)
	hdr[0] = 1
	hdr[1] = TypeData
	hdr[4] = 0
	hdr[5] = 0
	hdr[6] = 3
	hdr[7] = 9 // streamID = 999
	hdr[8] = 0
	hdr[9] = 0
	hdr[10] = 0
	hdr[11] = 1
	if _, err := c2.Write(hdr); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := c2.Write([]byte("x")); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	_ = c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	f, err := ReadFrame(c2)
	if err != nil {
		t.Fatalf("read CLOSE: %v", err)
	}
	if f.Type != TypeClose {
		t.Fatalf("expected CLOSE, got type %d", f.Type)
	}
	if len(f.Payload) < 1 || f.Payload[0] == 0 {
		t.Fatalf("expected protective CLOSE (err != 0), got %v", f.Payload)
	}
}
