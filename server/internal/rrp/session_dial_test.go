package rrp

import (
	"net"
	"testing"
	"time"
)

// tcpEcho — локальная цель для диала с сервера (эхо 1:1).
func tcpEcho(t *testing.T) (host string, port uint16) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, rerr := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if rerr != nil {
						return
					}
				}
			}(c)
		}
	}()
	ha := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", uint16(ha.Port)
}

// phoneOpen — телефон шлёт OPEN (чётный id) и ждёт OPEN_OK.
func phoneOpen(t *testing.T, c2 net.Conn, id uint32, host string, port uint16, timeout time.Duration) uint8 {
	t.Helper()
	_ = c2.SetWriteDeadline(time.Now().Add(timeout))
	if err := WriteFrame(c2, TypeOpen, 0, id, EncodeOpen(ATYPIPv4, net.ParseIP(host).To4(), port)); err != nil {
		t.Fatalf("send open: %v", err)
	}
	_ = c2.SetReadDeadline(time.Now().Add(timeout))
	f, err := ReadFrame(c2)
	if err != nil {
		t.Fatalf("read openok: %v", err)
	}
	if f.Type != TypeOpenOK || f.StreamID != id {
		t.Fatalf("want OPEN_OK id=%d, got type=%d id=%d", id, f.Type, f.StreamID)
	}
	if len(f.Payload) != 1 {
		t.Fatalf("openok payload: %v", f.Payload)
	}
	return f.Payload[0]
}

// TestPhoneOpenDataRoundTrip — канон E2E-пробника: OPEN от телефона →
// сервер диалит цель своим egress → OPEN_OK(0) → DATA телефон→цель→телефон
// (эхо через серверный релей) → Close. Пинг телефона отвечаем штатно.
func TestPhoneOpenDataRoundTrip(t *testing.T) {
	host, port := tcpEcho(t)
	c1, c2 := net.Pipe()
	sess := NewSession("s1", "dev", pipeConn{c1}, DefaultSessionConfig())
	go sess.Run()
	defer sess.Close()

	const id = uint32(2) // чётный — стрим телефона (серверные — нечётные)
	if code := phoneOpen(t, c2, id, host, port, 5*time.Second); code != 0 {
		t.Fatalf("dial echo: err=%d", code)
	}
	msg := []byte("ping-through-server-egress")
	_ = c2.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := WriteFrame(c2, TypeData, 0, id, msg); err != nil {
		t.Fatal(err)
	}
	_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		f, err := ReadFrame(c2)
		if err != nil {
			t.Fatalf("read echo: %v", err)
		}
		switch {
		case f.Type == TypePing:
			_ = c2.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_ = WriteFrame(c2, TypePong, 0, 0, f.Payload)
		case f.Type == TypeData && f.StreamID == id:
			if string(f.Payload) != string(msg) {
				t.Fatalf("echo mismatch: %q", f.Payload)
			}
			return
		}
	}
}

// TestPhoneOpenDialFail — цель недоступна → вежливый OpenOk(ERR_CONNECT_FAILED),
// сессия живёт (это НЕ признак мёртвого пути).
func TestPhoneOpenDialFail(t *testing.T) {
	c1, c2 := net.Pipe()
	sess := NewSession("s1", "dev", pipeConn{c1}, DefaultSessionConfig())
	go sess.Run()
	defer sess.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	if code := phoneOpen(t, c2, 4, "127.0.0.1", closedPort, 10*time.Second); code != 4 {
		t.Fatalf("want ERR_CONNECT_FAILED(4), got %d", code)
	}
}

// TestPhoneOpenRejectedWhenDisabled — гейт PhoneOpenAllowed=false → OpenOk(1),
// сессия живёт (старое поведение серверов v1.8.0 для старого клиента — мягкое).
func TestPhoneOpenRejectedWhenDisabled(t *testing.T) {
	c1, c2 := net.Pipe()
	cfg := DefaultSessionConfig()
	cfg.PhoneOpenAllowed = false
	sess := NewSession("s1", "dev", pipeConn{c1}, cfg)
	go sess.Run()
	defer sess.Close()
	if code := phoneOpen(t, c2, 6, "127.0.0.1", 1, 5*time.Second); code != 1 {
		t.Fatalf("want ERR_GENERAL(1) when gated off, got %d", code)
	}
}
