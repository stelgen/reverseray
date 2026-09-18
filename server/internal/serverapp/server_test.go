package serverapp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stelgen/reverseray/server/internal/config"
)

// startTestServer boots a full server on ephemeral ports with one device token.
func startTestServer(t *testing.T) (*App, *config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	token := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	sum := sha256.Sum256([]byte(token))
	tokensPath := filepath.Join(dir, "tokens.json")
	_ = os.WriteFile(tokensPath, []byte(fmt.Sprintf(`{"devices":{"phone-1":%q}}`,
		base64.RawURLEncoding.EncodeToString(sum[:]))), 0o600)

	cfg := config.Default()
	cfg.Listen.Tunnels = "127.0.0.1:0"
	cfg.Listen.Mixed = "127.0.0.1:0"
	cfg.Listen.AdminTCP = "127.0.0.1:0"
	cfg.StateDir = dir
	cfg.TokensFile = tokensPath
	cfg.Log.Level = "error"

	// We need real ports; listen first, then patch config is complex —
	// instead bind manually by choosing free ports.
	cfg.Listen.Tunnels = freePort(t)
	cfg.Listen.Mixed = freePort(t)
	cfg.Listen.AdminTCP = freePort(t)

	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	app, err := New(cfg, log)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go func() { _ = app.Run(context.Background()) }()
	waitTCP(t, cfg.Listen.Tunnels)
	waitTCP(t, cfg.Listen.Mixed)
	waitTCP(t, cfg.Listen.AdminTCP)
	t.Cleanup(func() { app.hub.Kick("phone-1") })
	return app, cfg, token
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func waitTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
			// Admin port dials succeed even before Serve; tunnels/inbounds accept.
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server not listening on %s", addr)
}

func TestE2ESocksThroughPhoneTunnel(t *testing.T) {
	app, cfg, token := startTestServer(t)

	// Echo target: the "internet" our fake phone dials into.
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
	fmt.Sscanf(echoPortS, "%d", &echoPort)

	phoneDials := 0
	_, _, err = DialPhone(t, cfg.Listen.Tunnels, app.CAPin(), token, "phone-1",
		func(host string, port uint16) (net.Conn, error) {
			phoneDials++
			if host != echoHost || port != echoPort {
				return nil, fmt.Errorf("unexpected dial target %s:%d", host, port)
			}
			return net.Dial("tcp", echoAddr)
		})
	if err != nil {
		t.Fatalf("phone connect: %v", err)
	}
	// Give hub a moment to register.
	time.Sleep(200 * time.Millisecond)

	// SOCKS5 client through the mixed inbound.
	c, err := net.Dial("tcp", cfg.Listen.Mixed)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	// greeting: offer no-auth
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(br, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 5 || resp[1] != 0 {
		t.Fatalf("bad method reply %v", resp)
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
		t.Fatalf("socks connect failed: code=%d", rep[1])
	}
	msg := []byte("ping-through-phone-tunnel")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: %q", got)
	}
	if phoneDials != 1 {
		t.Fatalf("phone should dial exactly once, got %d", phoneDials)
	}

	// HTTP CONNECT path.
	hc, err := net.Dial("tcp", cfg.Listen.Mixed)
	if err != nil {
		t.Fatal(err)
	}
	defer hc.Close()
	fmt.Fprintf(hc, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr, echoAddr)
	hr := bufio.NewReader(hc)
	hresp, err := http.ReadResponse(hr, nil)
	if err != nil || hresp.StatusCode != 200 {
		t.Fatalf("CONNECT failed: %v %+v", err, hresp)
	}
	if _, err := hc.Write([]byte("second-ping")); err != nil {
		t.Fatal(err)
	}
	_ = hc.SetReadDeadline(time.Now().Add(5 * time.Second))
	got2 := make([]byte, 11)
	if _, err := io.ReadFull(hr, got2); err != nil {
		t.Fatal(err)
	}
	if string(got2) != "second-ping" {
		t.Fatalf("CONNECT echo mismatch: %q", got2)
	}
}

func TestAuthRejectedWithoutToken(t *testing.T) {
	_, cfg, _ := startTestServer(t)
	// No phone ever connects; a socks attempt must fail with general failure.
	c, err := net.Dial("tcp", cfg.Listen.Mixed)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	c.Write([]byte{5, 1, 0})
	resp := make([]byte, 2)
	io.ReadFull(br, resp)
	target := []byte{5, 1, 0, 1, 8, 8, 8, 8, 0, 53}
	c.Write(target)
	rep := make([]byte, 10)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(br, rep); err != nil {
		t.Fatalf("expected reply, got err %v", err)
	}
	if rep[1] == 0 {
		t.Fatal("dial must fail with no tunnels online")
	}
}

func TestBadAuthIsRejected(t *testing.T) {
	app, cfg, goodToken := startTestServer(t)
	badToken := goodToken + "x"
	_, _, err := DialPhone(t, cfg.Listen.Tunnels, app.CAPin(), badToken, "phone-evil",
		func(host string, port uint16) (net.Conn, error) { return net.Dial("tcp", "127.0.0.1:1") })
	if err == nil {
		t.Fatal("bad token must be rejected")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBadPinIsRejected(t *testing.T) {
	_, cfg, token := startTestServer(t)
	badPin := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	_, _, err := DialPhone(t, cfg.Listen.Tunnels, badPin, token, "phone-1",
		func(host string, port uint16) (net.Conn, error) { return net.Dial("tcp", "127.0.0.1:1") })
	if err == nil {
		t.Fatal("wrong CA pin must be rejected")
	}
}

func TestAdminAPI(t *testing.T) {
	app, cfg, _ := startTestServer(t)
	resp, err := http.Get("http://" + cfg.Listen.AdminTCP + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("healthz: %d", resp.StatusCode)
	}
	resp2, err := http.Get("http://" + cfg.Listen.AdminTCP + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("readyz should be ready with tokens loaded: %d", resp2.StatusCode)
	}
	_ = app
}
