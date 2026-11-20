package serverapp

// proto_matrix_test.go — верхнеуровневый e2e-валидатор зоопарка протоколов
// (v1.8.6): КАЖДЫЙ протокол payload-конвертов × КАЖДЫЙ транспорт, затем
// бесшовная смена протокола (0x2C) в каждый другой протокол — все
// направленные пары. Проверка — РЕАЛЬНЫЙ трафик: SOCKS5-клиент гонит эхо
// через туннель до и после каждого свитча (не «переменные в коде», а
// честный roundtrip в запечатанном конверте). Новые протоколы добавляются
// в один список — матрица расширяется автоматически.

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
		return err
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

// TestProtoTransportMatrix — стартовая связка: {tcp, ws} × {rrp1, mtproto2,
// wireguard, bittorrent} → эхо-трафик; затем mid-session свитч в каждый
// другой протокол-конверт (rrp1 недостижим бесшовно — требует реконнекта,
// сервер это и отрицает) → снова эхо на новом конверте.
func TestProtoTransportMatrix(t *testing.T) {
	protos := []string{"rrp1", "mtproto2", "wireguard", "bittorrent"}
	transports := []string{"tcp", "ws"}

	for _, transport := range transports {
		for _, initial := range protos {
			name := transport + "/" + initial
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
					p, _, err = DialPhoneProto(t, cfg.Listen.Tunnels, app.CAPin(), token, "phone-matrix", initial, dial)
				case "ws":
					ws := dialWsTls(t, cfg.Listen.Tunnels, app.CAPin())
					p, _, err = DialPhoneOnProto(t, ws, token, "phone-matrix-ws", initial, dial)
				default:
					t.Fatalf("unknown transport %q", transport)
				}
				if err != nil {
					t.Fatalf("phone connect (%s): %v", name, err)
				}
				time.Sleep(200 * time.Millisecond) // регистрация в hub

				check := func(tag string, payload []byte) {
					t.Helper()
					if err := socksEcho(cfg.Listen.Mixed, echoHost, echoPort, payload); err != nil {
						if le := p.loopErr.Load(); le != nil {
							t.Fatalf("%s: %v; fake-phone loop died: %v", tag, err, le)
						}
						t.Fatalf("%s: %v", tag, err)
					}
					if le := p.loopErr.Load(); le != nil {
						t.Fatalf("%s: fake-phone loop died: %v; last frame: %v", tag, le, p.lastSeen.Load())
					}
					if ls := p.lastSeen.Load(); ls != nil {
						t.Logf("%s: phone last seen frame: %v", tag, ls)
					}
				}
				check("initial "+initial, []byte("matrix-ping-"+initial))

				// Свитч в каждый другой протокол; rrp1 бесшовно недостижим —
				// сервер обязан ОТКАЗАТЬ (канон v1.8.3), это тоже проверяем.
				n := 0
				for _, target := range protos {
					if target == initial {
						continue
					}
					n++
					nonce := fmt.Sprintf("matrix-n%d", n)
					err := p.SwitchTo(target, nonce)
					if target == "rrp1" {
						if err == nil {
							t.Fatalf("switch to rrp1 must be denied (seamless switch requires reconnect)")
						}
						continue
					}
					if err != nil {
						t.Fatalf("switch %s→%s: %v", initial, target, err)
					}
					// Трафик в НОВОМ конверте: эхо обязан пройти.
					check("after "+initial+"→"+target, []byte("matrix-ping-"+target))
				}
			})
		}
	}
}
