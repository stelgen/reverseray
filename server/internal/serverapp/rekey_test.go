package serverapp

// rekey_test.go — e2e самовосстановления конверта (v1.9.9 «коннектор»):
// битый payload-кадр НЕ должен убивать сессию — сервер дропает кадр,
// пересогласовывает конверт (KEY_REQ → INIT/RESP) и трафик продолжается.
// Боевой сценарий 2026-11-21 (bt: bad envelope → смерть сессии → паркинг-цикл).

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

// sendRawData — инъекция DATA-кадра с битым payload (мимо конверта fake-phone):
// сервер обязан увидеть garbage в decryptDown и запустить self-heal.
func sendRawData(t *testing.T, p *fakePhone, streamID uint32, payload []byte) {
	t.Helper()
	// wm сериализует записи fake-phone; прямая запись из теста — только в паузе.
	p.wm.Lock()
	defer p.wm.Unlock()
	if err := rrp.WriteFrame(p.conn, rrp.TypeData, 0, streamID, payload); err != nil {
		t.Fatalf("raw frame write: %v", err)
	}
}

func waitEchoOK(t *testing.T, mixed, host string, port uint16, payload []byte, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		// Короткий per-attempt дедлайн: кадр, отправленный в окне ре-кея
		// (до коммита нового конверта), дропается сервером молча (prev
		// отравлен битым кадром, позиционный RC4) — ретрай проходит, когда
		// телефон уже на новом конверте. 10s-дедлайн socksEcho сжигал бы
		// весь бюджет одной попыткой.
		if err := socksEchoT(mixed, host, port, payload, 700*time.Millisecond); err == nil {
			return nil
		} else {
			last = err
		}
		time.Sleep(300 * time.Millisecond)
	}
	return last
}

// socksEchoT — socksEcho с настраиваемым дедлайном чтения эха (ретраи
// поверх окна ре-кея; см. waitEchoOK).
func socksEchoT(mixed, host string, port uint16, payload []byte, timeout time.Duration) error {
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
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		return fmt.Errorf("echo read: %w", err)
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("echo mismatch: got %q", got)
	}
	return nil
}

// TestRekeySelfHealBT — битый DATA в bt-сессии: ре-кей → эхо снова ходит.
func TestRekeySelfHealBT(t *testing.T) {
	app, cfg, token := startTestServer(t)
	_ = app
	_, echoHost, echoPort := echoTarget(t)

	dial := func(host string, port uint16) (net.Conn, error) {
		if host != echoHost || port != echoPort {
			t.Logf("DEBUG dial mismatch: got %s:%d want %s:%d", host, port, echoHost, echoPort)
			return nil, fmt.Errorf("unexpected dial target %s:%d", host, port)
		}
		return net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	}
	p, _, err := DialPhoneProto(t, cfg.Listen.Tunnels, app.CAPin(), token, "phone-rekey", "bittorrent", dial)
	if err != nil {
		t.Fatalf("phone connect: %v", err)
	}
	defer p.Close()
	time.Sleep(200 * time.Millisecond)

	payload := []byte("rekey-selfheal-ping")
	if err := socksEcho(cfg.Listen.Mixed, echoHost, echoPort, payload); err != nil {
		t.Fatalf("echo before corrupt: %v (loop: %v, lastSeen: %v, env: %v, pend: %v)",
			err, p.loopErr.Load(), p.lastSeen.Load(), p.currentEnv() != nil, p.pend != nil)
	}

	// Битый кадр: garbage вместо bt-конверта.
	sendRawData(t, p, 0x5E17A001, bytes.Repeat([]byte{0xAB}, 100))
	// Self-heal: ре-кей (~RTT) → эхо снова проходит.
	if err := waitEchoOK(t, cfg.Listen.Mixed, echoHost, echoPort, payload, 5*time.Second); err != nil {
		t.Fatalf("echo after corrupt (self-heal failed): %v (loop: %v)", err, p.loopErr.Load())
	}

	// Второй ре-кей после cooldown: resilience, не одноразовый костыль.
	time.Sleep(2 * time.Second)
	sendRawData(t, p, 0x5E17A002, bytes.Repeat([]byte{0xCD}, 100))
	if err := waitEchoOK(t, cfg.Listen.Mixed, echoHost, echoPort, payload, 5*time.Second); err != nil {
		t.Fatalf("echo after second corrupt: %v (loop: %v)", err, p.loopErr.Load())
	}
}

// TestRekeyNoiseLimitShutdown — пачка битых кадров при живой крипте:
// после исчерпания rekeyMax/noise-лимита сессия честно закрывается
// (битый клиент не висит вечно), SOCKS-диал умирает по таймауту.
func TestRekeyNoiseLimitShutdown(t *testing.T) {
	app, cfg, token := startTestServer(t)
	_ = app
	_, echoHost, echoPort := echoTarget(t)

	dial := func(host string, port uint16) (net.Conn, error) {
		if host != echoHost || port != echoPort {
			t.Logf("DEBUG dial mismatch: got %s:%d want %s:%d", host, port, echoHost, echoPort)
			return nil, fmt.Errorf("unexpected dial target %s:%d", host, port)
		}
		return net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	}
	p, _, err := DialPhoneProto(t, cfg.Listen.Tunnels, app.CAPin(), token, "phone-rekey2", "bittorrent", dial)
	if err != nil {
		t.Fatalf("phone connect: %v", err)
	}
	defer p.Close()
	time.Sleep(200 * time.Millisecond)

	// rekeyMax+1 ре-кеев с cooldown-паузами: 4-й битый кадр обязан закрыть сессию.
	for i := 0; i <= rrp.RekeyMax; i++ {
		if i > 0 {
			time.Sleep(2200 * time.Millisecond) // cooldown
		}
		sendRawData(t, p, uint32(0x5E200000+i), bytes.Repeat([]byte{0x11}, 100))
	}
	// Дать последнему ре-кею дойти до отказа (лимит исчерпан → shutdown).
	time.Sleep(1 * time.Second)
	// Сессия мертва: SOCKS-коннект не обслуживается (нет живого устройства).
	c, derr := net.DialTimeout("tcp", cfg.Listen.Mixed, 2*time.Second)
	if derr == nil {
		_ = c.SetReadDeadline(time.Now().Add(8 * time.Second))
		if _, rerr := io.ReadFull(c, make([]byte, 2)); rerr == nil {
			// greeting отвечает — значит слушатель жив; сессия телефона мертва,
			// реальный CONNECT повиснет. Достаточно факта, что greeting есть:
			// keycheck ниже не нужен, а вот эхо обязан фейлиться.
			_ = c.Close()
		}
	}
	if err := waitEchoOK(t, cfg.Listen.Mixed, echoHost, echoPort, []byte("must-die"), 6*time.Second); err == nil {
		t.Fatalf("session must be dead after rekey limit, but echo passed")
	}
}
