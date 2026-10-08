package rrp

import (
	"io"
	"sync"
	"testing"
	"time"
)

// noiseDuplex — минимальный in-memory транспорт для тестов NOISE-логики.
type noiseDuplex struct {
	r io.Reader
	w io.Writer
	c io.Closer
}

func (d *noiseDuplex) Read(p []byte) (int, error)  { return d.r.Read(p) }
func (d *noiseDuplex) Write(p []byte) (int, error) { return d.w.Write(p) }
func (d *noiseDuplex) Close() error                { return d.c.Close() }

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func newNoisePair() (io.ReadWriteCloser, io.ReadWriteCloser) {
	c1r, c1w := io.Pipe()
	c2r, c2w := io.Pipe()
	return &noiseDuplex{r: c1r, w: c2w, c: nopCloser{}},
		&noiseDuplex{r: c2r, w: c1w, c: nopCloser{}}
}

// Сервер отвечает на валидный NOISE валидным JSON-ответом и учитывает хук.
func TestSessionNoiseRoundTrip(t *testing.T) {
	server, phone := newNoisePair()
	defer phone.Close()
	hooked := 0
	hookMu := sync.Mutex{}
	cfg := DefaultSessionConfig()
	cfg.NoiseHook = func(req, resp int) {
		hookMu.Lock()
		hooked++
		hookMu.Unlock()
	}
	s := NewSession("sid-noise", "phone-1", server, cfg)
	go s.Run()

	// телефон шлёт NOISE (как это делает модуль apimask APK)
	req := []byte(`{"app":"com.acme.workspace","kind":"telemetry.batch","ts":1718000000}`)
	if err := WriteFrame(phone, TypeNoise, 0, 0, req); err != nil {
		t.Fatal(err)
	}
	f, err := ReadFrame(phone)
	if err != nil {
		t.Fatalf("ответ не получен: %v", err)
	}
	if f.Type != TypeNoise {
		t.Fatalf("ожидали NOISE, получили type=0x%02x", f.Type)
	}
	if len(f.Payload) == 0 || f.Payload[0] != '{' {
		t.Fatalf("ответ не JSON-объект: %s", f.Payload)
	}
	// Детерминированное ожидание хука: планировщик может исполнить горутину
	// handleNoise после того, как ответ уже прочитан тестом (CI-флейк).
	waitForHook(t, &hookMu, &hooked, 1)
	_ = s.Close()
}

// waitForHook ждёт, пока счётчик хука дойдёт до want (≤2 с; иначе фейл).
func waitForHook(t *testing.T, mu *sync.Mutex, counter *int, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := *counter
		mu.Unlock()
		if n >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("хук вызван %d раз, ожидалось >= %d", n, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Мусорный NOISE не рвёт сессию (шум декоративный; рвать по нему = вектор DoS).
func TestSessionNoiseGarbageKeepsSession(t *testing.T) {
	server, phone := newNoisePair()
	defer phone.Close()
	s := NewSession("sid-noise2", "phone-1", server, DefaultSessionConfig())
	go s.Run()

	for _, bad := range [][]byte{[]byte(`not json`), []byte(`[1,2]`), []byte(`{`)} {
		if err := WriteFrame(phone, TypeNoise, 0, 0, bad); err != nil {
			t.Fatal(err)
		}
	}
	// сессия жива: PING/PONG продолжает работать
	if err := WriteFrame(phone, TypePing, 0, 0, []byte("12345678")); err != nil {
		t.Fatal(err)
	}
	f, err := ReadFrame(phone)
	if err != nil {
		t.Fatalf("сессия умерла на мусорном NOISE: %v", err)
	}
	if f.Type != TypePong {
		t.Fatalf("ожидали PONG, получили 0x%02x", f.Type)
	}
	_ = s.Close()
}

// Rate-limit: детерминированный тест чистой логики окна (анти-амплификация):
// ровно noiseRate ответов в минуту, дальше тишина; окно сбрасывается.
func TestSessionNoiseRateLimit(t *testing.T) {
	s := NewSession("sid-noise3", "phone-1", nopReadWrite{}, DefaultSessionConfig())
	base := time.Unix(1700000000, 0)
	s.mu.Lock()
	defer s.mu.Unlock()
	allowed := 0
	for i := 0; i < noiseRate+25; i++ {
		if s.noiseAllows(base.Add(time.Duration(i) * 10 * time.Millisecond)) {
			allowed++
		}
	}
	if allowed != noiseRate {
		t.Fatalf("пропущено %d, ожидалось ровно %d (rate-limit протёк)", allowed, noiseRate)
	}
	// следующее минутное окно: счётчик сбрасывается
	if !s.noiseAllows(base.Add(2 * time.Minute)) {
		t.Fatal("окно не сбросилось через минуту")
	}
}

// nopReadWrite — транспорт-заглушка (rate-limit тестируется без IO).
type nopReadWrite struct{}

func (nopReadWrite) Read(p []byte) (int, error)  { return 0, io.EOF }
func (nopReadWrite) Write(p []byte) (int, error) { return len(p), nil }
func (nopReadWrite) Close() error                { return nil }
