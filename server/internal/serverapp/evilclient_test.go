package serverapp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

// rawDialEvil открывает TLS-соединение и проходит валидное рукопожатие,
// возвращая сырой conn: evil-клиент управляет протоколом вручную.
func rawDialEvil(t *testing.T, addr, caPinB64, token string) net.Conn {
	t.Helper()
	cfg, err := makePhoneTLSConfig(caPinB64)
	if err != nil {
		t.Fatalf("tls config: %v", err)
	}
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn := tls.Client(raw, cfg)
	if err := conn.Handshake(); err != nil {
		raw.Close()
		t.Fatalf("tls handshake: %v", err)
	}
	if _, err := clientHandshake(conn, token, "phone-evil"); err != nil {
		conn.Close()
		t.Fatalf("rrp handshake: %v", err)
	}
	return conn
}

func sendRawHeader(conn net.Conn, ver, typ uint8, streamID uint32, payloadLen uint32) error {
	hdr := make([]byte, 12)
	hdr[0] = ver
	hdr[1] = typ
	binary.BigEndian.PutUint32(hdr[4:8], streamID)
	binary.BigEndian.PutUint32(hdr[8:12], payloadLen)
	_, err := conn.Write(hdr)
	return err
}

// serverSurvives: после «злого» сценария сервер обязан принимать новых клиентов.
func serverSurvives(t *testing.T, app *App, addr, token string) {
	t.Helper()
	p, _, err := DialPhone(t, addr, app.CAPin(), token, "phone-ok",
		func(host string, port uint16) (net.Conn, error) {
			return nil, fmt.Errorf("no dial")
		})
	if err != nil {
		t.Fatalf("server did not survive: %v", err)
	}
	p.Close()
}

func TestEvilOversizedFrameClosed(t *testing.T) {
	app, cfg, token := startTestServer(t)

	conn := rawDialEvil(t, cfg.Listen.Tunnels, app.CAPin(), token)
	defer conn.Close()

	// payload_len = 0xFFFFFFFF — попытка OOM
	if err := sendRawHeader(conn, 1, rrp.TypeData, 1, 0xFFFFFFFF); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	if _, err := conn.Read(buf); err == nil {
		// сервер мог прислать ERROR-кадр; тогда второе чтение обязано дать EOF
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Read(buf); err == nil {
			t.Fatal("server must close oversized-frame connection")
		}
	}
	serverSurvives(t, app, cfg.Listen.Tunnels, token)
}

func TestEvilBadVersionClosed(t *testing.T) {
	app, cfg, token := startTestServer(t)
	conn := rawDialEvil(t, cfg.Listen.Tunnels, app.CAPin(), token)
	defer conn.Close()

	if err := sendRawHeader(conn, 9, rrp.TypePing, 0, 0); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 64)); err == nil {
		t.Fatal("server must close connection with unsupported version")
	}
	serverSurvives(t, app, cfg.Listen.Tunnels, token)
}

func TestEvilUnknownFrameTypeNoPanic(t *testing.T) {
	app, cfg, token := startTestServer(t)
	conn := rawDialEvil(t, cfg.Listen.Tunnels, app.CAPin(), token)
	defer conn.Close()

	for i := 0; i < 5; i++ {
		if err := sendRawHeader(conn, 1, 0x55, uint32(i), 0); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	time.Sleep(200 * time.Millisecond)
	serverSurvives(t, app, cfg.Listen.Tunnels, token)
}

func TestEvilTruncatedPayloadClosed(t *testing.T) {
	app, cfg, token := startTestServer(t)
	conn := rawDialEvil(t, cfg.Listen.Tunnels, app.CAPin(), token)

	// заявляем 100 байт payload, отправляем 10 и рвём соединение
	if err := sendRawHeader(conn, 1, rrp.TypeData, 1, 100); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _ = conn.Write(make([]byte, 10))
	conn.Close()
	time.Sleep(200 * time.Millisecond)
	serverSurvives(t, app, cfg.Listen.Tunnels, token)
}

func TestEvilGarbageOnTunnelsPort(t *testing.T) {
	app, cfg, token := startTestServer(t)
	for _, payload := range [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		{0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5}, // обрывок TLS ClientHello
		bytes.Repeat([]byte{0xDE, 0xAD}, 512),
		{},
	} {
		c, err := net.Dial("tcp", cfg.Listen.Tunnels)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		_, _ = c.Write(payload)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = c.Read(make([]byte, 16))
		c.Close()
	}
	serverSurvives(t, app, cfg.Listen.Tunnels, token)
}

func TestMixedGarbageRequestsNoPanic(t *testing.T) {
	app, cfg, token := startTestServer(t)

	garbage := []string{
		"GET /admin HTTP/1.1\r\nHost: x\r\n\r\n",
		"CONNECT  HTTP/1.1\r\n\r\n",
		"POST / HTTP/1.1\r\nContent-Length: 999999\r\n\r\nshort",
		"\x00\x01\x02\x03\x04\x05",
		"GET /../../etc/passwd HTTP/1.1\r\n\r\n",
	}
	for _, g := range garbage {
		c, err := net.Dial("tcp", cfg.Listen.Mixed)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		_, _ = c.Write([]byte(g))
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = io.ReadAll(bufio.NewReader(c))
		c.Close()
	}
	serverSurvives(t, app, cfg.Listen.Tunnels, token)
}

func TestMetricsAndAdminLeakNothing(t *testing.T) {
	_, cfg, token := startTestServer(t)

	resp, err := http.Get("http://" + cfg.Listen.AdminTCP + "/metrics")
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	lower := strings.ToLower(string(body))

	for _, secret := range []string{strings.ToLower(token), "tokens.json", "/tmp/"} {
		if strings.Contains(lower, secret) {
			t.Fatalf("leak in /metrics: %q present", secret)
		}
	}

	// admin root не отдаёт стектрейсы/внутренние пути
	resp2, err := http.Get("http://" + cfg.Listen.AdminTCP + "/no-such-page")
	if err == nil {
		defer resp2.Body.Close()
		b2, _ := io.ReadAll(resp2.Body)
		for _, leak := range []string{"/home/", "/tmp/", "goroutine", "tokens.json", ".go:"} {
			if strings.Contains(strings.ToLower(string(b2)), strings.ToLower(leak)) {
				t.Fatalf("admin leak: %q present", leak)
			}
		}
	}
}

func TestPingFloodSurvives(t *testing.T) {
	app, cfg, token := startTestServer(t)
	p, _, err := DialPhone(t, cfg.Listen.Tunnels, app.CAPin(), token, "phone-1",
		func(host string, port uint16) (net.Conn, error) {
			return nil, fmt.Errorf("no dial")
		})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	for i := 0; i < 200; i++ {
		if err := p.WritePing([]byte{byte(i)}); err != nil {
			t.Fatalf("ping %d: %v", i, err)
		}
	}
	time.Sleep(300 * time.Millisecond)
	serverSurvives(t, app, cfg.Listen.Tunnels, token)
}

func TestAuthBruteForceTriggersLockout(t *testing.T) {
	app, cfg, token := startTestServer(t)

	// 5 неверных HMAC -> lockout на IP: даже валидный токен с того же IP
	// обязан быть отклонён (брутфорс токена бессмыслен)
	for i := 0; i < 5; i++ {
		if _, _, err := DialPhone(t, cfg.Listen.Tunnels, app.CAPin(), token+"x", "phone-bf",
			func(host string, port uint16) (net.Conn, error) { return nil, fmt.Errorf("no dial") }); err == nil {
			t.Fatalf("attempt %d with bad HMAC must fail", i)
		}
	}
	if _, _, err := DialPhone(t, cfg.Listen.Tunnels, app.CAPin(), token, "phone-1",
		func(host string, port uint16) (net.Conn, error) { return nil, fmt.Errorf("no dial") }); err == nil {
		t.Fatal("lockout must reject even a valid token from the same IP")
	}
}

func TestConcurrentGarbageThenLegitClient(t *testing.T) {
	app, cfg, token := startTestServer(t)

	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := net.Dial("tcp", cfg.Listen.Tunnels)
			if err != nil {
				return
			}
			_, _ = c.Write(bytes.Repeat([]byte{byte(i)}, 64))
			_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			_, _ = c.Read(make([]byte, 16))
			c.Close()
		}(i)
	}
	wg.Wait()
	serverSurvives(t, app, cfg.Listen.Tunnels, token)
}
