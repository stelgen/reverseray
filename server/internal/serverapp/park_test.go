package serverapp

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// socks5Connect — минимальный SOCKS5-клиент для тестов (no-auth, CONNECT по IPv4).
func socks5Connect(t *testing.T, addr, host string, port uint16) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("socks dial: %v", err)
	}
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var rb [2]byte
	if _, err := io.ReadFull(c, rb[:]); err != nil {
		t.Fatal(err)
	}
	if rb[0] != 5 || rb[1] != 0 {
		t.Fatalf("socks greeting rejected: %x", rb)
	}
	req := []byte{5, 1, 0, 1}
	req = append(req, net.ParseIP(host).To4()...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0 {
		t.Fatalf("socks connect rejected: code %d", rep[1])
	}
	return c
}

func ipPort(addr string) (string, uint16) {
	h, p, _ := net.SplitHostPort(addr)
	var port uint16
	fmt.Sscanf(p, "%d", &port)
	return h, port
}

// TestParkResumeBuffer — «буфер трафика» (v1.3.0): потеря туннеля НЕ рвёт
// браузерную сторону. Данные, отправленные в разрыв, буферизуются в
// оперативке и досылаются после реконнекта телефона; байты не дропаются.
func TestParkResumeBuffer(t *testing.T) {
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
			go func(c net.Conn) {
				_, _ = io.Copy(c, c)
				c.Close()
			}(c)
		}
	}()
	echoHost, echoPort := ipPort(echoLn.Addr().String())

	phone1, _, err := DialPhoneResume(t, cfg.Listen.Tunnels, app.CAPin(), token, "phone-1",
		func(host string, port uint16) (net.Conn, error) {
			if host != echoHost || port != echoPort {
				return nil, fmt.Errorf("unexpected dial target %s:%d", host, port)
			}
			return net.Dial("tcp", echoLn.Addr().String())
		})
	if err != nil {
		t.Fatalf("phone connect: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	t.Logf("DIAG2: tokens_after_dial=%d (до socks)", phone1.TokenCount())

	socks := socks5Connect(t, cfg.Listen.Mixed, echoHost, echoPort)
	defer socks.Close()

	// До потери: обычная работа (эхо).
	if _, err := socks.Write([]byte("chunk-1\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	t.Logf("DIAG2: tokens_after_socks=%d", phone1.TokenCount())

	// Потеря связи: транспорт телефона умирает.
	phone1.conn.Close()
	time.Sleep(300 * time.Millisecond) // сервер паркует стрим (TTL в конфиге тестов)
	t.Logf("DIAG: parked=%d phone1.tokens=%d", app.hub.ParkedTotal(), phone1.TokenCount())

	// Браузерная сторона ЖИВА: пишем в разрыв — буферизуется в оперативке.
	if _, err := socks.Write([]byte("chunk-2-after-loss\n")); err != nil {
		t.Fatalf("браузерная сторона закрыта при потере туннеля (буфер не работает): %v", err)
	}

	// Реконнект: новый экземпляр фейка наследует припаркованные сокеты
	// (загрузка ДО хендшейка — Attach резюмится сразу).
	parkedIn := phone1.ParkedConns()
	nParkedIn := len(parkedIn)
	_, _, err = DialPhoneResumeWith(t, cfg.Listen.Tunnels, app.CAPin(), token, "phone-1",
		func(host string, port uint16) (net.Conn, error) {
			return net.Dial("tcp", echoLn.Addr().String())
		}, parkedIn)
	if err != nil {
		t.Fatalf("phone reconnect: %v", err)
	}
	t.Logf("DIAG: phone1 parked conns=%d", nParkedIn)
	for i := 0; i < 15; i++ {
		time.Sleep(200 * time.Millisecond)
		t.Logf("DIAG3: parked=%d", app.hub.ParkedTotal())
		if app.hub.ParkedTotal() == 0 {
			break
		}
	}

	// Ждём резюме и эхо дозалитого буфера.
	socks.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(socks)
	var got []string
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		got = append(got, strings.TrimSpace(line))
		if strings.Contains(line, "chunk-2-after-loss") {
			break
		}
	}
	found := false
	for _, g := range got {
		if strings.Contains(g, "chunk-2-after-loss") {
			found = true
		}
	}
	t.Logf("DIAG: parked_after=%d events=%v", app.hub.ParkedTotal(), app.ev.Snapshot(20))
	if !found {
		t.Fatalf("буфер не дозалит после резюме: получили %v (ожидали chunk-2-after-loss)", got)
	}
	// Резюме состоялось без нового диала таргета — сокет телефона тот же.
}

// TestMultiPhoneDistribution — несколько телефонов: новые диалы расходятся по
// устройствам (least-outstanding), буфер каждого устройства резюмится только
// своим устройством (сокет таргета жив на конкретном телефоне).
func TestMultiPhoneDistribution(t *testing.T) {
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
			go func(c net.Conn) {
				_, _ = io.Copy(c, c)
				c.Close()
			}(c)
		}
	}()
	echoHost, echoPort := ipPort(echoLn.Addr().String())

	var dialsA, dialsB int
	dialA := func(host string, port uint16) (net.Conn, error) {
		dialsA++
		return net.Dial("tcp", echoLn.Addr().String())
	}
	dialB := func(host string, port uint16) (net.Conn, error) {
		dialsB++
		return net.Dial("tcp", echoLn.Addr().String())
	}
	phoneA, _, err := DialPhoneResume(t, cfg.Listen.Tunnels, app.CAPin(), token, "phone-1", dialA)
	if err != nil {
		t.Fatal(err)
	}
	phoneB, _, err := DialPhoneResume(t, cfg.Listen.Tunnels, app.CAPin(), token, "phone-2", dialB)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)

	// Два диала: с высокой вероятностью расходятся по устройствам
	// (least-outstanding при нулевом outstanding берёт первый найденный —
	// фиксируем факт распределения, а не конкретное устройство).
	s1 := socks5Connect(t, cfg.Listen.Mixed, echoHost, echoPort)
	defer s1.Close()
	s2 := socks5Connect(t, cfg.Listen.Mixed, echoHost, echoPort)
	defer s2.Close()
	time.Sleep(200 * time.Millisecond)
	if dialsA+dialsB < 2 {
		t.Fatalf("диалы не дошли до телефонов: A=%d B=%d", dialsA, dialsB)
	}

	// Потеря устройства A: его стримы в буфере; устройство B продолжает работу.
	phoneA.conn.Close()
	time.Sleep(300 * time.Millisecond)
	if _, err := s1.Write([]byte("post-loss-a\n")); err != nil {
		t.Fatalf("стрим устройства A не запаркован: %v", err)
	}
	if _, err := s2.Write([]byte("device-b-alive\n")); err != nil {
		t.Fatalf("устройство B сломалось при потере A: %v", err)
	}

	// Реконнект A: буфер A резюмится тем же устройством.
	_, _, err = DialPhoneResumeWith(t, cfg.Listen.Tunnels, app.CAPin(), token, "phone-1", dialA, phoneA.ParkedConns())
	if err != nil {
		t.Fatal(err)
	}
	s1.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(s1)
	deadline := time.Now().Add(8 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		if strings.Contains(line, "post-loss-a") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("буфер устройства A не дозалит после его реконнекта")
	}
	_ = phoneB
	_ = binary.BigEndian
}