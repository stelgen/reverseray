package serverapp

// proto_matrix_test.go — верхнеуровневый e2e-валидатор зоопарка протоколов:
// КАЖДЫЙ протокол payload-конвертов × КАЖДЫЙ транспорт, каждый — с РЕАЛЬНЫМ
// трафиком: SOCKS5-клиент гонит эхо через туннель в активном конверте
// (не «переменные в коде», а честный roundtrip в запечатанном канале).
//
// v1.9.3: бесшовная смена протокола (0x2C) удалена — смена = обычный
// реконнект. Пары «старый → новый» покрываются свежим dial с целевым
// протоколом: каждая строка матрицы — независимый коннект с полным
// хендшейком и реальным крипто-обменом (WG_INIT/BT_INIT/KEY_RESP).

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// echoTarget — «интернет», куда звонит fake-phone: локальный эхо-сервер.
func echoTarget(t *testing.T) (net.Listener, string, uint16) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}(c)
		}
	}()
	addr := ln.Addr().String()
	host, portS, _ := net.SplitHostPort(addr)
	var port uint16
	_, _ = fmt.Sscanf(portS, "%d", &port)
	return ln, host, port
}

// socksEcho — SOCKS5 CONNECT до host:port через mixed-inbound и эхо
// roundtrip payload'а (гейт «туннель реально пропускает трафик»).
func socksEcho(mixed, host string, port uint16, payload []byte) error {
	c, err := net.Dial("tcp", mixed)
	if err != nil {
		return fmt.Errorf("socks dial: %w", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil || resp[0] != 5 || resp[1] != 0 {
		return fmt.Errorf("socks greeting: %v %v", resp, err)
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return err
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		return fmt.Errorf("socks connect: %w", err)
	}
	if rep[1] != 0 {
		return fmt.Errorf("socks connect failed: code=%d", rep[1])
	}
	if _, err := c.Write(payload); err != nil {
		return err
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		return fmt.Errorf("echo read: %w", err)
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("echo mismatch: got %q", got)
	}
	return nil
}

// TestProtoTransportMatrix — стартовые связки: {tcp, ws} × {rrp1, mtproto2,
// wireguard, bittorrent} → эхо-трафик в активном конверте каждого протокола
// (для wg/bt конверт включается серверным KEY_REQ → INIT/RESP при коннекте).
func TestProtoTransportMatrix(t *testing.T) {
	protos := []string{"rrp1", "mtproto2", "wireguard", "bittorrent"}
	transports := []string{"tcp", "ws"}

	for _, transport := range transports {
		for _, proto := range protos {
			name := transport + "/" + proto
			t.Run(name, func(t *testing.T) {
				app, cfg, token := startTestServer(t)
				_ = app
				_, echoHost, echoPort := echoTarget(t)

				dial := func(host string, port uint16) (net.Conn, error) {
					if host != echoHost || port != echoPort {
						return nil, fmt.Errorf("unexpected dial target %s:%d", host, port)
					}
					return net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
				}

				var p *fakePhone
				var err error
				switch transport {
				case "tcp":
					p, _, err = DialPhoneProto(t, cfg.Listen.Tunnels, app.CAPin(), token, "phone-matrix", proto, dial)
				case "ws":
					ws := dialWsTls(t, cfg.Listen.Tunnels, app.CAPin())
					p, _, err = DialPhoneOnProto(t, ws, token, "phone-matrix-ws", proto, dial)
				default:
					t.Fatalf("unknown transport %q", transport)
				}
				if err != nil {
					t.Fatalf("phone connect (%s): %v", name, err)
				}
				defer p.Close()
				time.Sleep(200 * time.Millisecond) // регистрация в hub

				if err := socksEcho(cfg.Listen.Mixed, echoHost, echoPort, []byte("matrix-ping-"+proto)); err != nil {
					if le := p.loopErr.Load(); le != nil {
						t.Fatalf("echo (%s): %v; fake-phone loop died: %v", name, err, le)
					}
					t.Fatalf("echo (%s): %v", name, err)
				}
			})
		}
	}
}
