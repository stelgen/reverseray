package serverapp

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestWANScanSilent — интеграционный: HTTP-пробник (сигнатура nmap -sV
// и масс-сканеров) на туннельном порту получает НОЛЬ байтов ответа.
func TestWANScanSilent(t *testing.T) {
	_, cfg, _ := startTestServer(t)

	probe := func(payload []byte) {
		t.Helper()
		c, err := net.Dial("tcp", cfg.Listen.Tunnels)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = c.Write(payload)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 512)
		if n, err := c.Read(buf); err == nil && n > 0 {
			t.Fatalf("пробник получил %d байт: %q — утечка!", n, buf[:n])
		}
	}
	probe([]byte("GET / HTTP/1.1\r\nHost: scanner\r\nUser-Agent: nmap\r\n\r\n"))
	probe([]byte{0x00, 0x00, 0x00, 0x00, 0xFF, 0xEE})
	probe([]byte("PING\r\n"))
}

// TestHardeningMetrics — события анти-скана видны в /metrics (без IP и payload).
func TestHardeningMetrics(t *testing.T) {
	_, cfg, _ := startTestServer(t)
	c, err := net.Dial("tcp", cfg.Listen.Tunnels)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("PING\r\n"))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Read(make([]byte, 64))
	c.Close()

	body, status := httpGet(t, "http://"+cfg.Listen.AdminTCP+"/metrics")
	if status != 200 {
		t.Fatalf("metrics: %d", status)
	}
	if !strings.Contains(body, "reverseray_hardening_scans_total") {
		t.Fatal("метрика hardening отсутствует в /metrics")
	}
}

// TestTLSStillWorksAfterHardening — TLS-клиент не пострадал от гейта.
func TestTLSStillWorksAfterHardening(t *testing.T) {
	app, cfg, token := startTestServer(t)
	_, _, err := DialPhone(t, cfg.Listen.Tunnels, app.CAPin(), token, "phone-1",
		func(host string, port uint16) (net.Conn, error) { return net.Dial("tcp", "127.0.0.1:1") })
	if err != nil {
		t.Fatalf("TLS+RRP handshake после hardening не работает: %v", err)
	}
}

// TestMTPProto2E2E — протокол mtproto2 сквозь весь сервер: согласование,
// DH-апгрейд, шифрованные DATA в обе стороны через SOCKS5-инбокс.
func TestMTProto2E2E(t *testing.T) {
	app, cfg, token := startTestServer(t)
	app.cfg.DefaultProtocol = "mtproto2"

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
			go func(c net.Conn) {
				_, _ = io.Copy(c, c)
				c.Close()
			}(c)
		}
	}()
	echoAddr := echoLn.Addr().String()
	echoHost, echoPortS, _ := net.SplitHostPort(echoAddr)
	var echoPort uint16
	_, _ = fmt.Sscanf(echoPortS, "%d", &echoPort)

	_, _, err = DialPhoneProto(t, cfg.Listen.Tunnels, app.CAPin(), token, "phone-1", "mtproto2",
		func(host string, port uint16) (net.Conn, error) {
			if host != echoHost || port != echoPort {
				t.Fatalf("неожиданная цель диала: %s:%d", host, port)
			}
			return net.Dial("tcp", echoAddr)
		})
	if err != nil {
		t.Fatalf("mtproto2 phone connect: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// SOCKS5-эхо сквозь шифрованный туннель: данные идут в MTProto-конверте.
	c, err := net.Dial("tcp", cfg.Listen.Mixed)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	mresp := make([]byte, 2)
	if _, err := io.ReadFull(br, mresp); err != nil {
		t.Fatal(err)
	}
	req := []byte{5, 1, 0, 3, byte(len(echoHost))}
	req = append(req, echoHost...)
	req = append(req, byte(echoPort>>8), byte(echoPort))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(br, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0 {
		t.Fatalf("socks connect через mtproto2: код %d", rep[1])
	}
	msg := []byte("mtproto2-secret-echo")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("эхо исказилось: %q", got)
	}
}

func httpGet(t *testing.T, url string) (string, int) {
	t.Helper()
	resp, err := http.Get(url) // #nosec G107: URL локальный в тестах
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.StatusCode
}
