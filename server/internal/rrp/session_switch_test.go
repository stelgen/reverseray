package rrp

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"net"
	"sync"
	"testing"
	"time"
)

// ---- фейковый план свитча: KEY_REQ → KEY_RESP → тестовая крипта (passthrough) ----

type fakeSwitchPlan struct{ n int }

func (p *fakeSwitchPlan) RequestPayload() ([]byte, error) {
	return []byte(fmt.Sprintf(`{"n":%d}`, p.n)), nil
}

func (p *fakeSwitchPlan) Complete([]byte) (PayloadCrypto, error) {
	return fakeSwitchCrypto{}, nil
}

type fakeSwitchCrypto struct{}

func (fakeSwitchCrypto) MaxPlainData() int { return MaxDataPayload - 1 }

func (fakeSwitchCrypto) DecryptDown(b []byte) ([]byte, error) { return b, nil }

func (fakeSwitchCrypto) EncryptUp(b []byte) ([]byte, error) { return b, nil }

// switchConfig — сессия со включённой сменой протокола (фейковый план).
func switchConfig() SessionConfig {
	cfg := DefaultSessionConfig()
	cfg.Switchable = true
	cfg.SwitchPlanner = func(string) (KeyPlan, error) { return &fakeSwitchPlan{}, nil }
	return cfg
}

// switchPayload — тестовый payload: [index u32][crc32 u32][data].
func switchPayload(i int, data []byte) []byte {
	p := make([]byte, 8+len(data))
	binary.BigEndian.PutUint32(p[0:4], uint32(i)) // #nosec G115: i < 2^31
	binary.BigEndian.PutUint32(p[4:8], crc32.ChecksumIEEE(data))
	copy(p[8:], data)
	return p
}

// parseSwitchPayload — валидация payload'а (crc и индекс).
func parseSwitchPayload(p []byte) (int, bool) {
	if len(p) < 8 {
		return -1, false
	}
	i := int(binary.BigEndian.Uint32(p[0:4]))
	want := binary.BigEndian.Uint32(p[4:8])
	data := p[8:]
	return i, crc32.ChecksumIEEE(data) == want
}

// shaOrdered — SHA-256 упорядоченного набора payload'ов (по индексу).
func shaOrdered(payloads [][]byte) []byte {
	// простая сортировка по индексу (первые 8 байт)
	for a := 1; a < len(payloads); a++ {
		for b := a; b > 0; b-- {
			if binary.BigEndian.Uint32(payloads[b][0:4]) >= binary.BigEndian.Uint32(payloads[b-1][0:4]) {
				break
			}
			payloads[b], payloads[b-1] = payloads[b-1], payloads[b]
		}
	}
	h := sha256.New()
	for _, p := range payloads {
		h.Write(p)
	}
	return h.Sum(nil)
}

// expectedOrdered — SHA-256 ожидаемого набора (та же конструкция).
func expectedOrdered(n int) []byte {
	payloads := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		payloads = append(payloads, switchPayload(i, []byte(fmt.Sprintf("chunk-%d", i))))
	}
	return shaOrdered(payloads)
}

// fakePhone — фейковый телефон: единственный читатель conn, кадры раскладывает
// в каналы (DATA/OPEN_OK/ProtoSwitch-ack), отвечает на KEY_REQ с задержкой.
type fakePhone struct {
	data       chan []byte
	ack        chan protoSwitchMsg
	openOK     chan Frame
	hangKeyReq bool // не отвечать на KEY_REQ (тест дедлайна)
}

func runSwitchSession(t *testing.T, cfg SessionConfig, phoneDelayMs int) (*Session, net.Conn, *fakePhone) {
	t.Helper()
	c1, c2 := net.Pipe()
	sess := NewSession("s1", "dev", pipeConn{c1}, cfg)
	go sess.Run()

	p := &fakePhone{
		data:   make(chan []byte, 4096),
		ack:    make(chan protoSwitchMsg, 8),
		openOK: make(chan Frame, 8),
	}
	go func() {
		defer close(p.data)
		for {
			f, err := ReadFrame(c2)
			if err != nil {
				return
			}
			switch f.Type {
			case TypeProtoSwitch:
				var m protoSwitchMsg
				if json.Unmarshal(f.Payload, &m) == nil {
					p.ack <- m
				}
			case TypeKeyReq:
				if p.hangKeyReq {
					continue // поглощаем молча — свитч зависает (тест дедлайна)
				}
				time.Sleep(time.Duration(phoneDelayMs) * time.Millisecond)
				_ = WriteFrame(c2, TypeKeyResp, 0, 0, f.Payload) // echo — fake plan примет
			case TypeData:
				p.data <- f.Payload
			case TypeOpenOK:
				p.openOK <- *f
			case TypePong:
				_ = WriteFrame(c2, TypePong, 0, 0, f.Payload)
			}
		}
	}()
	return sess, c2, p
}

// startSwitchFromPhone — телефон инициирует смену (0x2C).
func startSwitchFromPhone(t *testing.T, c2 net.Conn) {
	t.Helper()
	b, _ := json.Marshal(&protoSwitchMsg{Proto: "mtproto2", Nonce: "test-nonce"})
	if err := WriteFrame(c2, TypeProtoSwitch, 0, 0, b); err != nil {
		t.Fatalf("write switch request: %v", err)
	}
}

// waitAck — ждём ack свитча (ok или нет).
func waitAck(t *testing.T, p *fakePhone, timeout time.Duration) protoSwitchMsg {
	t.Helper()
	select {
	case m := <-p.ack:
		return m
	case <-time.After(timeout):
		t.Fatalf("no switch ack in %v", timeout)
		return protoSwitchMsg{}
	}
}

// assertAlive — сессия жива (нет Done).
func assertAlive(t *testing.T, sess *Session) {
	t.Helper()
	select {
	case <-sess.Done():
		t.Fatalf("session must survive")
	default:
	}
}

// drainData — собирает n уникальных по индексу payload'ов, проверяет crc.
func drainData(t *testing.T, p *fakePhone, n int, timeout time.Duration) [][]byte {
	t.Helper()
	var got [][]byte
	seen := make(map[int]bool)
	deadline := time.Now().Add(timeout)
	for len(got) < n {
		if time.Now().After(deadline) {
			t.Fatalf("payload loss: got %d of %d", len(got), n)
		}
		select {
		case pl := <-p.data:
			i, ok := parseSwitchPayload(pl)
			if !ok {
				t.Fatalf("payload #%d: bad crc", len(got))
			}
			if seen[i] {
				t.Fatalf("payload #%d: duplicate index %d", len(got), i)
			}
			seen[i] = true
			got = append(got, pl)
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	return got
}

// TestSessionSwitchNoLoss: 8 потоков × 100 payload-кадров через реальную
// принудительную смену 0x2C — SHA-целостность всего трафика, ноль потерь.
func TestSessionSwitchNoLoss(t *testing.T) {
	sess, c2, p := runSwitchSession(t, switchConfig(), 150)
	startSwitchFromPhone(t, c2)
	m := waitAck(t, p, 3*time.Second)
	if !m.OK {
		t.Fatalf("switch denied: %s", m.Reason)
	}

	// 8 потоков пишут по 100 кадров (часть до паркинга, часть — в паркинге)
	const workers = 8
	const per = 100
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				idx := w*per + i
				sess.writeAsync(&Frame{Type: TypeData, StreamID: 7, Payload: switchPayload(idx, []byte(fmt.Sprintf("chunk-%d", idx)))})
			}
		}(w)
	}
	wg.Wait()

	got := drainData(t, p, workers*per, 10*time.Second)
	if got := shaOrdered(got); fmt.Sprintf("%x", got) != fmt.Sprintf("%x", expectedOrdered(workers*per)) {
		t.Fatalf("sha integrity mismatch")
	}
	assertAlive(t, sess)
}

// TestSessionSwitchDeniedNotKill: отказ planner'а — сессия жива, трафик идёт,
// паркинг не включался (fail() до parkPayloadLocked), ротация продолжает расписание.
func TestSessionSwitchDeniedNotKill(t *testing.T) {
	cfg := switchConfig()
	cfg.SwitchPlanner = func(string) (KeyPlan, error) { return nil, fmt.Errorf("plan unavailable") }
	sess, c2, p := runSwitchSession(t, cfg, 0)

	b, _ := json.Marshal(&protoSwitchMsg{Proto: "mtproto2", Nonce: "n2"})
	if err := WriteFrame(c2, TypeProtoSwitch, 0, 0, b); err != nil {
		t.Fatalf("write switch request: %v", err)
	}
	m := waitAck(t, p, 3*time.Second)
	if m.OK {
		t.Fatalf("denied switch must answer ok=false")
	}

	// сессия жива: payload-кадры проходят свободно
	sess.writeAsync(&Frame{Type: TypeData, StreamID: 7, Payload: switchPayload(1, []byte("after-denied"))})
	drainData(t, p, 1, 3*time.Second)
	assertAlive(t, sess)
}

// TestSessionSwitchParkSurvivesSlowClient: parkWait переживает медленный
// клиент без shutdown — дедлайн единый (SwitchTimeout), все кадры доходят.
func TestSessionSwitchParkSurvivesSlowClient(t *testing.T) {
	old := switchDeadlineFor
	switchDeadlineFor = func() time.Duration { return 3 * time.Second }
	defer func() { switchDeadlineFor = old }()

	sess, c2, p := runSwitchSession(t, switchConfig(), 600) // медленный клиент: 600мс RTT
	startSwitchFromPhone(t, c2)
	if m := waitAck(t, p, 3*time.Second); !m.OK {
		t.Fatalf("switch denied: %s", m.Reason)
	}

	// пишем кадры во время паркинга (в т.ч. за 600мс до коммита)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				idx := w*25 + i
				sess.writeAsync(&Frame{Type: TypeData, StreamID: 7, Payload: switchPayload(idx, []byte(fmt.Sprintf("chunk-%d", idx)))})
			}
		}(w)
	}
	wg.Wait()

	drainData(t, p, 100, 8*time.Second)
	assertAlive(t, sess)
}

// TestSessionSwitchDeadlineKills: свитч реально умер (клиент не ответил
// на KEY_REQ) — дедлайн закрывает сессию.
func TestSessionSwitchDeadlineKills(t *testing.T) {
	old := switchDeadlineFor
	switchDeadlineFor = func() time.Duration { return 300 * time.Millisecond }
	defer func() { switchDeadlineFor = old }()

	sess, c2, p := runSwitchSession(t, switchConfig(), 0)
	p.hangKeyReq = true // телефон поглощает KEY_REQ молча — свитч зависает
	startSwitchFromPhone(t, c2)
	if m := waitAck(t, p, 3*time.Second); !m.OK {
		t.Fatalf("switch denied: %s", m.Reason)
	}

	select {
	case <-sess.Done():
		return // дедлайн закрыл сессию — верно
	case <-time.After(3 * time.Second):
		t.Fatalf("deadline must close the session with a hung switch")
	}
}

// TestSessionSwitchOpenDataInFlight: C→S OPEN (v1.8.1 session_dial) и DATA
// в полёте при паркинге не теряются: OPEN — контрольный (свободно), DATA
// телефона проходит сразу (вход), ответ цели паркуется и приходит после коммита.
func TestSessionSwitchOpenDataInFlight(t *testing.T) {
	// локальный echo-цель: диалится сервером своим egress
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				if n > 0 {
					_, _ = c.Write([]byte("ECHO:" + string(buf[:n]))) // ответ цели — паркуется на сервере
				}
				time.Sleep(300 * time.Millisecond)
			}(nc)
		}
	}()

	sess, c2, p := runSwitchSession(t, switchConfig(), 300)
	startSwitchFromPhone(t, c2)
	if m := waitAck(t, p, 3*time.Second); !m.OK {
		t.Fatalf("switch denied: %s", m.Reason)
	}

	// C→S OPEN в полёте: телефон просит сервер диалить echo-цель
	port := uint16(ln.Addr().(*net.TCPAddr).Port) // #nosec G115: порт < 2^16
	if err := WriteFrame(c2, TypeOpen, 0, 42, EncodeOpen(ATYPIPv4, []byte{127, 0, 0, 1}, port)); err != nil {
		t.Fatalf("write open: %v", err)
	}

	// OpenOk (err=0) — контрольный кадр, не паркуется
	select {
	case f := <-p.openOK:
		if f.StreamID != 42 || len(f.Payload) != 1 || f.Payload[0] != 0 {
			t.Fatalf("open rejected: %+v", f)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("OPEN in flight during parking must pass (control frame)")
	}

	// C→S DATA в полёте: телефон шлёт данные в стрим 42 — сервер pushIn → цель
	if err := WriteFrame(c2, TypeData, 0, 42, []byte("ping-via-dial")); err != nil {
		t.Fatalf("write data: %v", err)
	}

	// ответ цели ("ECHO:ping-via-dial") — сервер → телефон: паркуется до коммита
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case pl := <-p.data:
			if string(pl) == "ECHO:ping-via-dial" {
				assertAlive(t, sess)
				return // ответ цели дошёл после снятия паркинга
			}
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	t.Fatalf("echoed target response must arrive after commit (parked → flush)")
}

// TestSessionSwitchFromCryptoSession: бесшовная смена протокола ПРИ живой
// крипте (свитч mtproto2→mtproto2 «на вращение»). Регресс-тест v1.8.4:
// guard-ы KEY_RESP/INIT требовали crypto==nil, из-за чего целевой обмен
// из-под крипты молча игнорировался и сессия умирала по дедлайну смены.
func TestSessionSwitchFromCryptoSession(t *testing.T) {
	cfg := switchConfig()
	cfg.KeyPlan = &fakeSwitchPlan{n: 1} // стартовый обмен ключами при Run
	sess, c2, p := runSwitchSession(t, cfg, 100)

	// 1) начальный KEY_REQ → echo → крипта включена (pendingProto пуст)
	waitCryptoEngaged(t, sess)

	// 2) смена протокола из-под крипты: целевой KEY_REQ → echo → коммит
	startSwitchFromPhone(t, c2)
	m := waitAck(t, p, 3*time.Second)
	if !m.OK {
		t.Fatalf("switch denied: %s", m.Reason)
	}
	waitSwitchCommitted(t, sess)

	sess.mu.Lock()
	proto := sess.Proto
	crypto := sess.crypto
	sess.mu.Unlock()
	if proto != "mtproto2" {
		t.Fatalf("proto = %q, want mtproto2", proto)
	}
	if crypto == nil {
		t.Fatal("crypto lost after switch")
	}

	// 3) паркинг снят, трафик идёт сквозь новую крипту (fake = passthrough)
	sess.writeAsync(&Frame{Type: TypeData, StreamID: 9, Payload: switchPayload(1, []byte("after-switch"))})
	got := drainData(t, p, 1, 5*time.Second)
	if _, ok := parseSwitchPayload(got[0]); !ok {
		t.Fatal("bad payload after switch")
	}
	assertAlive(t, sess)
}

// waitSwitchCommitted — ждёт атомарного коммита смены (pendingProto снят).
// Дедлайн смены уже остановлен; если коммита нет — тест падает по таймауту.
func waitSwitchCommitted(t *testing.T, s *Session) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s.mu.Lock()
		pp := s.pendingProto
		s.mu.Unlock()
		if pp == "" {
			return
		}
		select {
		case <-s.Done():
			t.Fatalf("session died mid-switch (pendingProto=%q)", pp)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("switch not committed in 3s (pendingProto=%q)", pp)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitCryptoEngaged — ждёт включения крипто-контекста сессии.
func waitCryptoEngaged(t *testing.T, s *Session) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s.mu.Lock()
		c := s.crypto
		s.mu.Unlock()
		if c != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("crypto not engaged in 3s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
