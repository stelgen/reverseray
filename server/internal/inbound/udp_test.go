package inbound

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

// fakeUdpPhone — телефон для UDP-тестов: подтверждает UDP_ASSOC и
// эхо-отвечает на UDP_DATA (имитация UDP echo-сервера на устройстве).
func fakeUdpPhone(conn io.ReadWriteCloser) {
	go func() {
		defer conn.Close()
		for {
			f, err := rrp.ReadFrame(conn)
			if err != nil {
				return
			}
			switch f.Type {
			case rrp.TypeUdpAssoc:
				_ = rrp.WriteFrame(conn, rrp.TypeOpenOK, 0, f.StreamID, rrp.EncodeOpenOK(0))
			case rrp.TypeUdpData:
				atyp, addr, port, data, derr := rrp.DecodeUdpData(f.Payload)
				if derr != nil {
					continue
				}
				// эхо: источник = адрес назначения
				echo := rrp.EncodeUdpData(atyp, addr, port, data)
				_ = rrp.WriteFrame(conn, rrp.TypeUdpData, 0, f.StreamID, echo)
			case rrp.TypeClose:
				return
			}
		}
	}()
}

// wireUdpSession поднимает rrp.Session (серверная сторона) поверх net.Pipe
// и подключает к ней фейковый телефон.
func wireUdpSession(t *testing.T) *rrp.Session {
	t.Helper()
	s1, s2 := net.Pipe()
	fakeUdpPhone(s2)
	sess := rrp.NewSession("test-session", "phone-1", s1, rrp.DefaultSessionConfig())
	go sess.Run()
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

func freeUdpPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	_ = conn.Close()
	return port
}

func TestSocks5UdpAssociateEcho(t *testing.T) {
	h := &stubDialer{udpSess: wireUdpSession(t)}
	in := &Inbound{Dialer: h, DialTimeout: 5 * time.Second, UDPBindPort: freeUdpPort(t)}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go in.Serve(ln)
	sc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	socksHandshake(t, sc, false)
	// UDP ASSOCIATE: cmd=3, DST=0.0.0.0:0
	req := []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}
	if _, err := sc.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(bufio.NewReader(sc), rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0 {
		t.Fatalf("udp associate rejected: %d", rep[1])
	}
	bndPort := int(rep[8])<<8 | int(rep[9])
	if bndPort != in.UDPBindPort {
		t.Fatalf("BND.PORT = %d, want %d", bndPort, in.UDPBindPort)
	}

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_ = udp.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Дейтаграмма SOCKS5: [RSV 2][FRAG 0][atyp 1][192.0.2.10][port 5353][data]
	payload := []byte("hello-udp")
	dg := []byte{0, 0, 0, 1, 192, 0, 2, 10, 0x14, 0xE9}
	dg = append(dg, payload...)
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: bndPort}
	if _, err := udp.WriteToUDP(dg, target); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 65535)
	n, _, err := udp.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no udp reply: %v", err)
	}
	// Ответ: [RSV 2][FRAG 0][atyp 1][192.0.2.10][port 5353][echo data]
	if n < 10 {
		t.Fatalf("short reply: %d bytes", n)
	}
	if string(buf[10:n]) != string(payload) {
		t.Fatalf("echo mismatch: %q", buf[10:n])
	}
	if buf[3] != 1 {
		t.Fatalf("reply atyp = %d, want 1 (IPv4)", buf[3])
	}
}

func TestUdpAssociateNoTunnel(t *testing.T) {
	h := &stubDialer{udpFail: true}
	sc, cc := net.Pipe()
	in := &Inbound{Dialer: h, UDPBindPort: freeUdpPort(t)}
	go in.handle(cc)

	socksHandshake(t, sc, false)
	req := []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}
	if _, err := sc.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(bufio.NewReader(sc), rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0x01 {
		t.Fatalf("expected general failure, got %d", rep[1])
	}
}

func TestSocks5BindCmdRejected(t *testing.T) {
	h := &stubDialer{}
	sc, cc := net.Pipe()
	in := &Inbound{Dialer: h}
	go in.handle(cc)

	socksHandshake(t, sc, false)
	if _, err := sc.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(bufio.NewReader(sc), rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0x07 {
		t.Fatalf("expected cmd not supported (0x07), got %d", rep[1])
	}
}
