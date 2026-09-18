package inbound

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// stubDialer records dial targets and can fail on demand.
type stubDialer struct {
	lastATYP byte
	lastAddr []byte
	lastPort uint16
	fail     bool
}

func (s *stubDialer) Dial(_ context.Context, atyp byte, addr []byte, port uint16, _ time.Duration) (net.Conn, error) {
	s.lastATYP, s.lastAddr, s.lastPort = atyp, addr, port
	if s.fail {
		return nil, errors.New("dial failed")
	}
	sc, cc := net.Pipe()
	go func() { _, _ = io.Copy(sc, sc); sc.Close() }()
	return cc, nil
}

func socksHandshake(t *testing.T, c net.Conn, auth bool) {
	t.Helper()
	br := bufio.NewReader(c)
	greet := []byte{5, 1, 0}
	if auth {
		greet = []byte{5, 1, 2}
	}
	if _, err := c.Write(greet); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(br, resp); err != nil {
		t.Fatal(err)
	}
	if auth {
		if resp[1] != 2 {
			t.Fatalf("expected userpass, got %v", resp)
		}
		c.Write([]byte{1, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'})
		vr := make([]byte, 2)
		if _, err := io.ReadFull(br, vr); err != nil || vr[1] != 0 {
			t.Fatalf("auth failed: %v %v", vr, err)
		}
	} else if resp[1] != 0 {
		t.Fatalf("expected noauth, got %v", resp)
	}
}

func TestSocks5NoAuthEcho(t *testing.T) {
	h := &stubDialer{}
	sc, cc := net.Pipe()
	in := &Inbound{Dialer: h}
	go in.handle(cc)

	socksHandshake(t, sc, false)
	host := "example.com"
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, 0x01, 0xBB)
	if _, err := sc.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(bufio.NewReader(sc), rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0 {
		t.Fatalf("connect failed: %d", rep[1])
	}
	if h.lastATYP != 3 || string(h.lastAddr) != "example.com" || h.lastPort != 443 {
		t.Fatalf("bad dial target %v %q %d", h.lastATYP, h.lastAddr, h.lastPort)
	}
	sc.Write([]byte("ping"))
	buf := make([]byte, 4)
	_ = sc.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(sc, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo failed: %q %v", buf, err)
	}
}

func TestSocks5IPv4Target(t *testing.T) {
	h := &stubDialer{}
	sc, cc := net.Pipe()
	in := &Inbound{Dialer: h}
	go in.handle(cc)
	socksHandshake(t, sc, false)
	sc.Write([]byte{5, 1, 0, 1, 8, 8, 8, 8, 0, 53})
	rep := make([]byte, 10)
	if _, err := io.ReadFull(bufio.NewReader(sc), rep); err != nil || rep[1] != 0 {
		t.Fatalf("ipv4 connect failed: %v", err)
	}
	if h.lastATYP != 1 || net.IP(h.lastAddr).String() != "8.8.8.8" || h.lastPort != 53 {
		t.Fatalf("bad target: %v %v %d", h.lastATYP, h.lastAddr, h.lastPort)
	}
}

func TestSocks5WithAuth(t *testing.T) {
	h := &stubDialer{}
	sc, cc := net.Pipe()
	in := &Inbound{Dialer: h, Username: "user", Password: "pass"}
	go in.handle(cc)
	socksHandshake(t, sc, true)
	sc.Write([]byte{5, 1, 0, 1, 1, 2, 3, 4, 0, 80})
	rep := make([]byte, 10)
	if _, err := io.ReadFull(bufio.NewReader(sc), rep); err != nil || rep[1] != 0 {
		t.Fatalf("authed connect failed: %v", err)
	}
}

func TestSocks5BadAuthRejected(t *testing.T) {
	sc, cc := net.Pipe()
	in := &Inbound{Dialer: &stubDialer{}, Username: "user", Password: "pass"}
	go in.handle(cc)
	sc.Write([]byte{5, 1, 2})
	resp := make([]byte, 2)
	io.ReadFull(bufio.NewReader(sc), resp)
	sc.Write([]byte{1, 4, 'u', 's', 'e', 'r', 1, 'x'})
	vr := make([]byte, 2)
	if _, err := io.ReadFull(bufio.NewReader(sc), vr); err != nil || vr[1] != 1 {
		t.Fatalf("bad creds must be rejected: %v %v", vr, err)
	}
}

func TestSocks5DialFailure(t *testing.T) {
	sc, cc := net.Pipe()
	in := &Inbound{Dialer: &stubDialer{fail: true}}
	go in.handle(cc)
	socksHandshake(t, sc, false)
	sc.Write([]byte{5, 1, 0, 1, 1, 2, 3, 4, 0, 80})
	rep := make([]byte, 10)
	if _, err := io.ReadFull(bufio.NewReader(sc), rep); err != nil || rep[1] != 4 {
		t.Fatalf("dial failure should map to 0x04: %v", err)
	}
}

func TestSocks5BindUnsupported(t *testing.T) {
	sc, cc := net.Pipe()
	in := &Inbound{Dialer: &stubDialer{}}
	go in.handle(cc)
	socksHandshake(t, sc, false)
	sc.Write([]byte{5, 2, 0, 1, 1, 2, 3, 4, 0, 80})
	rep := make([]byte, 10)
	if _, err := io.ReadFull(bufio.NewReader(sc), rep); err != nil || rep[1] != 0x07 {
		t.Fatalf("BIND must be rejected with 0x07: %v", err)
	}
}

func TestHTTPConnect(t *testing.T) {
	h := &stubDialer{}
	sc, cc := net.Pipe()
	in := &Inbound{Dialer: h}
	go in.handle(cc)
	fmt.Fprintf(sc, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	status, err := bufio.NewReader(sc).ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("CONNECT failed: %q %v", status, err)
	}
	if h.lastATYP != 3 || string(h.lastAddr) != "example.com" || h.lastPort != 443 {
		t.Fatalf("bad CONNECT target")
	}
}

func TestHTTPConnectWithAuth(t *testing.T) {
	sc, cc := net.Pipe()
	in := &Inbound{Dialer: &stubDialer{}, Username: "u", Password: "p"}
	go in.handle(cc)
	// Proxy-Authorization: Basic dTpw ("u":"p")
	fmt.Fprintf(sc, "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic dTpw\r\n\r\n")
	status, _ := bufio.NewReader(sc).ReadString('\n')
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT with good auth failed: %q", status)
	}
}

func TestAllowlist(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("127.0.0.0/8")
	in := &Inbound{Dialer: &stubDialer{}, Allowlist: []*net.IPNet{ipnet}}
	if !in.allowed(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}) {
		t.Fatal("loopback must be allowed")
	}
	if in.allowed(&net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 1}) {
		t.Fatal("10.0.0.5 must be denied")
	}
}

func TestEncodeHost(t *testing.T) {
	atyp, addr, err := encodeHost("8.8.8.8")
	if err != nil || atyp != 1 || net.IP(addr).String() != "8.8.8.8" {
		t.Fatalf("ipv4: %v", err)
	}
	atyp, addr, err = encodeHost("Example.COM.")
	if err != nil || atyp != 3 || string(addr) != "example.com" {
		t.Fatalf("domain: %v %q", err, addr)
	}
	if _, _, err := encodeHost(""); err == nil {
		t.Fatal("empty host must fail")
	}
}
