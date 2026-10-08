package hardening

import (
	"net"
	"testing"
	"time"
)

// TestClassifyTLSFirstByte: настоящий TLS-клиент проходит, peek-нутый байт
// воспроизводится целиком (TLS-хендшейк увидит полный ClientHello).
func TestClassifyTLSFirstByte(t *testing.T) {
	g := NewGate(true, 0, 100, 10, nil)
	a, b := net.Pipe()
	defer b.Close()
	// net.Pipe синхронный: пишем ДО Classify (Classify Peek(1) ждёт байт)
	msg := append([]byte{0x16, 0x03, 0x01}, []byte("hello-record-body")...)
	go func() { _, _ = b.Write(msg) }()
	time.Sleep(50 * time.Millisecond)
	wrapped, ok := g.Classify(a)
	if !ok {
		t.Fatal("TLS-первый-байт должен пропускаться")
	}
	buf := make([]byte, len(msg))
	if _, err := readFull(wrapped, buf); err != nil {
		t.Fatalf("peek-нутый байт потерян: %v", err)
	}
	for i := range msg {
		if buf[i] != msg[i] {
			t.Fatalf("байт %d искажён: %02x != %02x", i, buf[i], msg[i])
		}
	}
}

// TestClassifyGarbageSilent: HTTP-сканер (nmap -sV / пробники бинаря)
// получает ТИШИНУ: ни одного байта наружу, соединение закрыто.
func TestClassifyGarbageSilent(t *testing.T) {
	g := NewGate(true, 0, 100, 10, nil)
	a, b := net.Pipe()
	defer b.Close()
	go func() {
		_, _ = b.Write([]byte("GET / HTTP/1.1\r\nHost: scanner\r\nUser-Agent: nmap\r\n\r\n"))
	}()
	wrapped, ok := g.Classify(a)
	if ok {
		t.Fatal("не-TLS мусор должен отсекаться")
	}
	if wrapped != nil {
		t.Fatal("wrapped должен быть nil для мусора")
	}
	// соединение закрыто: попытка чтения с другой стороны даёт ошибку
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	if n, err := b.Read(buf); err == nil && n > 0 {
		t.Fatalf("сканер получил %d байт ответа — утечка!", n)
	}
	if g.Stats().Scans.Load() != 1 {
		t.Fatalf("Scans = %d, ожидалась 1", g.Stats().Scans.Load())
	}
}

func TestAdmitLimits(t *testing.T) {
	g := NewGate(true, 0, 2, 1, nil)
	if !g.Admit("1.2.3.4") {
		t.Fatal("первое соединение должно проходить")
	}
	if g.Admit("1.2.3.4") {
		t.Fatal("второе с того же IP при per_ip=1 должно отклоняться")
	}
	if !g.Admit("5.6.7.8") {
		t.Fatal("другой IP должен проходить")
	}
	if g.Admit("9.9.9.9") {
		t.Fatal("третье при max=2 должно отклоняться (глобал)")
	}
	g.Release("1.2.3.4")
	if !g.Admit("9.9.9.9") {
		t.Fatal("после Release должен проходить")
	}
	// Limited: per-IP reject (1.2.3.4 x2) + global reject (9.9.9.9) = 2
	if g.Stats().Limited.Load() != 2 {
		t.Fatalf("Limited = %d, ожидалось 2", g.Stats().Limited.Load())
	}
}

func TestDisabledGatePassesEverything(t *testing.T) {
	g := NewGate(false, 0, 0, 0, nil)
	if !g.Admit("x") {
		t.Fatal("выключенный гейт должен пропускать")
	}
	g.Release("x")
	a, b := net.Pipe()
	defer b.Close()
	if _, ok := g.Classify(a); !ok {
		t.Fatal("выключенный гейт не классифицирует")
	}
}

func TestParseTarpitSec(t *testing.T) {
	cases := map[string]int{"": 3, "5": 5, "0": 0, "-1": 3, "999": 3, "abc": 3}
	for in, want := range cases {
		if got := ParseTarpitSec(in); got != want {
			t.Fatalf("ParseTarpitSec(%q) = %d, ожидалось %d", in, got, want)
		}
	}
}

func TestConnLimit(t *testing.T) {
	l := &ConnLimit{Max: 2}
	if !l.Admit() || !l.Admit() {
		t.Fatal("первые два должны проходить")
	}
	if l.Admit() {
		t.Fatal("третье должно отклоняться")
	}
	l.Release()
	if !l.Admit() {
		t.Fatal("после Release должен проходить")
	}
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}
