package serverapp

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// wsTestClient — минимальный RFC 6455 клиент для тестов (binary-only,
// клиентские кадры маскируются, как требует спецификация).
type wsTestClient struct {
	br  *bufio.Reader
	w   io.Writer
	c   io.Closer
	rmu sync.Mutex
	buf []byte
}

func wsUpgradeRequest(key string) []byte {
	return []byte("GET /rrp HTTP/1.1\r\n" +
		"Host: reverseray.test\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n")
}

// dialWsTls: TLS + WS-апгрейд; возвращает клиентский ws-транспорт.
func dialWsTls(t *testing.T, serverAddr, caPinB64 string) *wsTestClient {
	t.Helper()
	cfg, err := makePhoneTLSConfig(caPinB64)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, cfg)
	if err := conn.Handshake(); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	kb := make([]byte, 16)
	_, _ = rand.Read(kb)
	key := base64.StdEncoding.EncodeToString(kb)
	if _, err := conn.Write(wsUpgradeRequest(key)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := readHttpResponse(br)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp, "HTTP/1.1 101") {
		raw.Close()
		t.Fatalf("ws upgrade rejected: %q", firstLine(resp))
	}
	// Проверка Sec-WebSocket-Accept (RFC 6455).
	want := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) // #nosec G401: RFC 6455
	if !strings.Contains(resp, base64.StdEncoding.EncodeToString(want[:])) {
		raw.Close()
		t.Fatal("bad Sec-WebSocket-Accept")
	}
	return &wsTestClient{br: br, w: conn, c: conn}
}

func readHttpResponse(br *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return sb.String(), err
		}
		sb.WriteString(line)
		if line == "\r\n" {
			return sb.String(), nil
		}
		if sb.Len() > 16*1024 {
			return sb.String(), io.ErrShortBuffer
		}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func (c *wsTestClient) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.buf) == 0 {
		fin, opcode, payload, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		switch opcode {
		case 0x2, 0x0:
			c.buf = append(c.buf, payload...)
			_ = fin
		case 0x9: // ping → pong (маскированный)
			_ = c.writeFrame(0xA, payload)
		case 0xA:
		case 0x8:
			return 0, io.EOF
		default:
			return 0, io.ErrUnexpectedEOF
		}
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *wsTestClient) readFrame() (bool, byte, []byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return false, 0, nil, err
	}
	fin := hdr[0]&0x80 != 0
	opcode := hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0
	ln := uint64(hdr[1] & 0x7F)
	switch ln {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		ln = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		ln = binary.BigEndian.Uint64(ext[:])
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(c.br, mask[:]); err != nil {
			return false, 0, nil, err
		}
	}
	payload := make([]byte, ln)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return false, 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return fin, opcode, payload, nil
}

func (c *wsTestClient) Write(p []byte) (int, error) {
	return len(p), c.writeFrame(0x2, p)
}

func (c *wsTestClient) writeFrame(opcode byte, payload []byte) error {
	var hdr [14]byte
	hdr[0] = 0x80 | opcode
	mask := [4]byte{0x11, 0x22, 0x33, 0x44}
	n := len(payload)
	i := 1
	switch {
	case n < 126:
		hdr[1] = 0x80 | byte(n)
		i = 2
	case n <= 0xFFFF:
		hdr[1] = 0x80 | 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		i = 4
	default:
		hdr[1] = 0x80 | 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(n))
		i = 10
	}
	copy(hdr[i:i+4], mask[:])
	i += 4
	if _, err := c.w.Write(hdr[:i]); err != nil {
		return err
	}
	if n > 0 {
		masked := make([]byte, n)
		for j := range payload {
			masked[j] = payload[j] ^ mask[j%4]
		}
		_, err := c.w.Write(masked)
		return err
	}
	return nil
}

func (c *wsTestClient) Close() error                       { return c.c.Close() }
func (c *wsTestClient) LocalAddr() net.Addr                { return addrString("ws-test") }
func (c *wsTestClient) RemoteAddr() net.Addr               { return addrString("ws-test") }
func (c *wsTestClient) SetDeadline(t time.Time) error      { return nil }
func (c *wsTestClient) SetReadDeadline(t time.Time) error  { return nil }
func (c *wsTestClient) SetWriteDeadline(t time.Time) error { return nil }

type addrString string

func (a addrString) Network() string { return "ws-test" }
func (a addrString) String() string  { return string(a) }

// Транспортная цепочка через WS: fake-phone ходит по /rrp upgrade,
// затем SOCKS5-клиент получает эхо через туннель.
func TestWsTransportEchoThroughTunnel(t *testing.T) {
	app, cfg, token := startTestServer(t)

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); c.Close() }(c)
		}
	}()

	ws := dialWsTls(t, cfg.Listen.Tunnels, app.CAPin())
	echoPort := echoLn.Addr().(*net.TCPAddr).Port
	_, _, err = DialPhoneOn(t, ws, token, "phone-ws", func(host string, p uint16) (net.Conn, error) {
		if host != "127.0.0.1" || int(p) != echoPort {
			return nil, errors.New("unexpected dial target")
		}
		return net.Dial("tcp", echoLn.Addr().String())
	})
	if err != nil {
		t.Fatalf("handshake over ws: %v", err)
	}

	c, err := net.Dial("tcp", cfg.Listen.Mixed)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// SOCKS5: no-auth, CONNECT 127.0.0.1:echoPort
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil || resp[1] != 0 {
		t.Fatalf("bad method reply %v", resp)
	}
	req := []byte{5, 1, 0, 3, 9, '1', '2', '7', '.', '0', '.', '0', '.', '1', byte(echoPort >> 8), byte(echoPort)}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0 {
		t.Fatalf("socks connect failed: %d", rep[1])
	}
	msg := []byte("ping-ws")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("echo through ws tunnel: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: %q", got)
	}
}

// Плохой путь WS: неверный ключ/путь → сервер обязан ответить не-101.
func TestWsTransportBadUpgrade(t *testing.T) {
	_, cfg, _ := startTestServer(t)

	raw, err := net.Dial("tcp", cfg.Listen.Tunnels)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tlsConn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) // #nosec G402: тестовый плохой путь
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := tlsConn.Write([]byte("GET /wrong HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\nSec-WebSocket-Version: 13\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(tlsConn)
	resp, err := readHttpResponse(br)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp, "HTTP/1.1 404") {
		t.Fatalf("expected 404 for wrong path, got %q", firstLine(resp))
	}
}
